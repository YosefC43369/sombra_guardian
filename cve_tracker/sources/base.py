"""
cve_tracker.sources.base — the source abstraction every adapter implements.

A source is anything that can hand us newly-published or newly-modified
vulnerability records. The contract is deliberately small:

    class MySource(CVESource):
        name = "..."; kind = SourceKind....
        async def fetch(self, ctx) -> SourceFetchResult: ...

``fetch`` does the network work (through the shared :class:`HttpFetcher`), reads
and advances its incremental cursor via the passed :class:`SourceState`, and
returns the records it parsed plus health/metrics. It must NOT raise on ordinary
source failures — it returns ``SourceFetchResult(ok=False, ...)`` so one source
failing never stops the others (rule §46). Programming errors may still raise;
the coordinator isolates them per-source.

Records returned are single-source normalized :class:`CVERecord`s (one
``SourceRecord`` embedded). Merging across sources happens later in the
deduplicator — a source never has to know another exists.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from typing import List, Optional

from ..config import SourceConfig
from ..enums import SourceKind, SourceHealthState
from ..models import CVERecord, SourceState
from ..ingestion.fetcher import HttpFetcher
from ..utils import now_epoch


@dataclass
class FetchContext:
    """Everything a source needs for one fetch pass, without reaching into the
    engine. Keeps sources decoupled and unit-testable with a fake fetcher."""

    fetcher: HttpFetcher
    config: SourceConfig
    state: SourceState
    #: Cap on records to parse per pass (bounds memory on a huge first sync).
    max_records: int = 2000
    #: True on the very first sync for this source (backfill window applies).
    first_run: bool = False


@dataclass
class SourceFetchResult:
    """What a source returns from one fetch pass."""

    source: str
    ok: bool = True
    records: List[CVERecord] = field(default_factory=list)
    #: Updated incremental state to persist (cursor/etag/last-modified).
    new_cursor: str = ""
    new_etag: str = ""
    new_http_last_modified: str = ""
    new_last_modified_seen: Optional[int] = None
    not_modified: bool = False
    error: str = ""
    health: str = SourceHealthState.UNKNOWN.value
    latency_ms: int = 0
    pages_fetched: int = 0

    @property
    def record_count(self) -> int:
        return len(self.records)


class CVESource(abc.ABC):
    """Base class for a CVE information source."""

    name: str = ""
    kind: str = SourceKind.OTHER.value

    def __init__(self, config: SourceConfig):
        self.config = config
        self.logger = logging.getLogger(f"modbot.cve.source.{self.name or 'base'}")

    # ---------------- contract ----------------

    @abc.abstractmethod
    async def fetch(self, ctx: FetchContext) -> SourceFetchResult:  # pragma: no cover
        """Perform one incremental fetch pass. Must not raise on ordinary
        source failure — return ``SourceFetchResult(ok=False, error=...)``."""
        raise NotImplementedError

    # ---------------- shared helpers ----------------

    def _empty(self, *, not_modified: bool = False, latency_ms: int = 0,
               cursor: str = "", etag: str = "", http_last_modified: str = "") -> SourceFetchResult:
        return SourceFetchResult(
            source=self.name, ok=True, records=[], not_modified=not_modified,
            health=SourceHealthState.HEALTHY.value, latency_ms=latency_ms,
            new_cursor=cursor, new_etag=etag, new_http_last_modified=http_last_modified,
        )

    def _failure(self, error: str, *, degraded: bool = False) -> SourceFetchResult:
        return SourceFetchResult(
            source=self.name, ok=False, error=error,
            health=(SourceHealthState.DEGRADED.value if degraded
                    else SourceHealthState.FAILING.value),
        )

    def _success(self, records: List[CVERecord], **kw) -> SourceFetchResult:
        return SourceFetchResult(
            source=self.name, ok=True, records=records,
            health=SourceHealthState.HEALTHY.value, **kw)

    def describe(self) -> str:
        return f"{self.name} ({self.kind})"
