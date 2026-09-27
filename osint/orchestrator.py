"""
osint.orchestrator — run many sources for one target concurrently, then merge
their results into a single intelligence object.

This is the async pipeline backbone: it owns one shared AsyncHTTPClient (so rate
limiting and connection reuse are global), fans out to every source whose
``kind`` matches the target, bounds concurrency with a semaphore, applies an
overall per-source timeout, and folds the per-source records into a
de-duplicated set with provenance and a simple corroboration score.

It does NOT decide authorization. The caller (the /osint command layer) is
responsible for checking scope_policy on the target first, exactly as /bbscan
does. The orchestrator only runs the sources it is handed against the target it
is handed.
"""

import time
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .sources.base import Source, SourceResult, SourceStatus
from .utils.async_http import AsyncHTTPClient

logger = logging.getLogger("modbot.osint.orchestrator")

DEFAULT_PER_SOURCE_TIMEOUT = 30.0
DEFAULT_CONCURRENCY = 8


@dataclass
class MergedRecord:
    """One de-duplicated finding, with the set of sources that reported it.
    ``confidence`` is the count of corroborating sources — a deliberately
    simple, explainable score (this repo separates fact from inference, so we
    report "how many sources agree", never a black-box certainty)."""
    type: str
    value: str
    sources: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def confidence(self) -> int:
        return len(set(self.sources))

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "value": self.value,
                "sources": sorted(set(self.sources)),
                "confidence": self.confidence, "extra": self.extra}


@dataclass
class Intelligence:
    """The merged output for one target across all sources that ran."""
    target: str
    kind: str
    results: List[SourceResult] = field(default_factory=list)
    merged: List[MergedRecord] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def elapsed_ms(self) -> int:
        return int((self.finished_at - self.started_at) * 1000)

    def stats(self) -> Dict[str, Any]:
        by_status: Dict[str, int] = {}
        for r in self.results:
            by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
        return {
            "target": self.target,
            "kind": self.kind,
            "sources_run": len(self.results),
            "sources_ok": sum(1 for r in self.results if r.ok),
            "records_total": sum(r.count for r in self.results),
            "records_merged": len(self.merged),
            "by_status": by_status,
            "elapsed_ms": self.elapsed_ms,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stats": self.stats(),
            "merged": [m.to_dict() for m in self.merged],
            "sources": [r.to_dict() for r in self.results],
        }


class Orchestrator:
    def __init__(self, sources: List[Source], *,
                 concurrency: int = DEFAULT_CONCURRENCY,
                 per_source_timeout: float = DEFAULT_PER_SOURCE_TIMEOUT,
                 rate: float = 5.0):
        self.sources = list(sources)
        self.concurrency = max(1, int(concurrency))
        self.per_source_timeout = per_source_timeout
        self.rate = rate

    def sources_for(self, kind: str) -> List[Source]:
        return [s for s in self.sources if s.kind == kind]

    async def run(self, target: str, kind: str, *,
                  client: Optional[AsyncHTTPClient] = None) -> Intelligence:
        """Run every source matching ``kind`` against ``target`` concurrently.

        If ``client`` is provided it is reused (and not closed here); otherwise a
        client is created and closed for this run. A source that exceeds the
        per-source timeout becomes an ERROR result rather than stalling the run.
        """
        intel = Intelligence(target=target, kind=kind, started_at=time.monotonic())
        selected = self.sources_for(kind)
        if not selected:
            intel.finished_at = time.monotonic()
            return intel

        owns_client = client is None
        if owns_client:
            client = AsyncHTTPClient(rate=self.rate)
            await client.__aenter__()
        sem = asyncio.Semaphore(self.concurrency)

        async def _run_one(source: Source) -> SourceResult:
            async with sem:
                try:
                    return await asyncio.wait_for(
                        source.run(client, target), timeout=self.per_source_timeout)
                except asyncio.TimeoutError:
                    return SourceResult(source.name, target, SourceStatus.ERROR,
                                        reason=f"timed out after {self.per_source_timeout}s")

        try:
            intel.results = await asyncio.gather(*(_run_one(s) for s in selected))
        finally:
            if owns_client:
                await client.__aexit__(None, None, None)

        intel.merged = self._merge(intel.results)
        intel.finished_at = time.monotonic()
        return intel

    @staticmethod
    def _merge(results: List[SourceResult]) -> List[MergedRecord]:
        """Fold per-source records into de-duplicated MergedRecords keyed by
        (type, value), accumulating which sources reported each one."""
        merged: Dict[tuple, MergedRecord] = {}
        for result in results:
            for rec in result.records:
                rtype = str(rec.get("type", "")).strip()
                value = str(rec.get("value", "")).strip()
                if not value:
                    continue
                key = (rtype, value.lower())
                if key not in merged:
                    merged[key] = MergedRecord(type=rtype, value=value)
                entry = merged[key]
                entry.sources.append(result.source)
                # Carry any non-standard fields as extra context (first wins).
                for k, v in rec.items():
                    if k not in ("type", "value", "source") and k not in entry.extra:
                        entry.extra[k] = v
        # Sort: highest corroboration first, then type, then value.
        return sorted(merged.values(),
                      key=lambda m: (-m.confidence, m.type, m.value.lower()))
