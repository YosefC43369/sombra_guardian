"""
cve_tracker.coordinator — concurrent, fault-isolated ingestion orchestration.

One :meth:`run_round` does a full polling pass:

    build sources → fetch ALL concurrently (bounded, timeout-isolated) →
    update per-source state/health → pipeline (normalize/validate/dedupe/enrich)
    → reconcile against storage (new vs updated via change detection) →
    prioritize + persist → return the records to alert on

The concurrency contract (rules §6, §27, §46): sources run under a global
semaphore with a per-source timeout; one source failing, timing out or raising
never stops the others — its failure is recorded against its own health and the
round continues. Nothing here sends Telegram messages; the engine hands the
:class:`RoundResult` to the dispatcher.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .config import CVETrackerConfig
from .models import CVERecord, ChangeSet, SourceState
from .sources.base import CVESource, FetchContext, SourceFetchResult
from .sources.registry import SourceRegistry, default_registry
from .ingestion.fetcher import HttpFetcher
from .ingestion.ratelimit import RateLimiterRegistry
from .ingestion.pipeline import IngestionPipeline
from .ingestion.deduplicator import merge_two
from .enrichment import enrich
from .intelligence.prioritization import prioritize
from .intelligence.change_detection import diff, events_for, should_notify_update
from .monitoring.metrics import (
    MetricsRegistry, M_RECORDS_SEEN, M_RECORDS_NEW, M_RECORDS_UPDATED,
    M_RECORDS_FAILED, M_ROUND, M_SOURCE_LATENCY, M_SOURCE_FAIL, M_DUPLICATE_RATE,
)
from .monitoring.health import evaluate_source
from .utils import now_epoch

logger = logging.getLogger("modbot.cve.coordinator")


@dataclass
class RoundResult:
    started_at: int
    finished_at: int = 0
    new_records: List[CVERecord] = field(default_factory=list)
    updated_pairs: List[Tuple[CVERecord, ChangeSet]] = field(default_factory=list)
    seen: int = 0
    new: int = 0
    updated: int = 0
    failed: int = 0
    duplicates: int = 0
    source_results: List[SourceFetchResult] = field(default_factory=list)
    ok: bool = True

    @property
    def summary(self) -> str:
        srcs = ",".join(f"{r.source}:{'ok' if r.ok else 'fail'}({r.record_count})"
                        for r in self.source_results)
        return (f"seen={self.seen} new={self.new} updated={self.updated} "
                f"failed={self.failed} dup={self.duplicates} | {srcs}")


class IngestionCoordinator:
    def __init__(self, config: CVETrackerConfig, repo, *,
                 registry: Optional[SourceRegistry] = None,
                 metrics: Optional[MetricsRegistry] = None,
                 audit=None):
        self.config = config
        self.repo = repo
        self.registry = registry or default_registry()
        self.metrics = metrics or MetricsRegistry()
        self.audit = audit
        self.pipeline = IngestionPipeline()
        self._limiters = RateLimiterRegistry()
        for sc in config.sources.values():
            self._limiters.configure(sc.name, sc.rate_limit_per_sec)
        self._sem = asyncio.Semaphore(config.max_concurrent_requests)

    # ---------------- one round ----------------

    async def run_round(self, *, only_source: Optional[str] = None) -> RoundResult:
        result = RoundResult(started_at=now_epoch())
        sources = self._build_sources(only_source)
        if not sources:
            result.finished_at = now_epoch()
            return result

        run_id = None
        if self.repo:
            try:
                run_id = self.repo.start_run([s.name for s in sources])
            except Exception:
                run_id = None

        fetcher = HttpFetcher(
            user_agent=self.config.user_agent,
            default_timeout=self.config.request_timeout,
            max_response_bytes=self.config.max_response_bytes,
            max_retries=int(self.config.max_retries),
            retry_base_delay=self.config.retry_base_delay,
            retry_max_delay=self.config.retry_max_delay,
            limiters=self._limiters,
        )
        # Note: the fetcher opens lazily on first use, so a source that needs no
        # network (or an environment without httpx) never forces it open.
        try:
            fetch_results = await asyncio.gather(
                *[self._run_source(src, fetcher) for src in sources],
                return_exceptions=True,
            )
        finally:
            await fetcher.aclose()

        clean_results: List[SourceFetchResult] = []
        for src, fr in zip(sources, fetch_results):
            if isinstance(fr, Exception):
                logger.error("CVE source %s crashed in gather: %s", src.name, fr)
                self.metrics.incr(M_SOURCE_FAIL)
                clean_results.append(SourceFetchResult(
                    source=src.name, ok=False, error=str(fr), health="failing"))
            else:
                clean_results.append(fr)
        result.source_results = clean_results

        # transform
        pipe_result = self.pipeline.process_fetch_results(clean_results)
        result.seen = pipe_result.total_in
        result.failed += pipe_result.rejected_count
        self.metrics.incr(M_RECORDS_SEEN, pipe_result.total_in)
        self.metrics.incr(M_RECORDS_FAILED, pipe_result.rejected_count)
        if pipe_result.total_in:
            dup = 1 - (pipe_result.total_out / pipe_result.total_in)
            self.metrics.gauge(M_DUPLICATE_RATE, round(max(0.0, dup), 3))
        result.duplicates = max(0, pipe_result.total_in - pipe_result.total_out)

        for rejected in pipe_result.rejected:
            if self.audit:
                self.audit.failure("pipeline", rejected[0], rejected[1])

        # reconcile with storage
        await self._reconcile(pipe_result.records, result)

        result.finished_at = now_epoch()
        self.metrics.incr(M_ROUND)
        if run_id is not None and self.repo:
            try:
                self.repo.finish_run(run_id, seen=result.seen, new=result.new,
                                     updated=result.updated, failed=result.failed,
                                     ok=result.ok, note=result.summary[:400])
            except Exception:
                pass
        return result

    # ---------------- source execution ----------------

    def _build_sources(self, only_source: Optional[str]) -> List[CVESource]:
        if only_source:
            src = self.registry.build_one(only_source, self.config)
            return [src] if src else []
        return self.registry.build_enabled(self.config)

    async def _run_source(self, source: CVESource, fetcher: HttpFetcher) -> SourceFetchResult:
        """Fetch one source under the global semaphore + a hard timeout, and
        persist its updated state/health. Never raises."""
        state = self._load_state(source.name)
        first_run = state.last_success_at is None and state.total_runs == 0
        ctx = FetchContext(
            fetcher=fetcher, config=source.config, state=state,
            max_records=2000, first_run=first_run)
        # timeout budget = request timeout * a generous multiple for pagination
        budget = max(30.0, source.config.timeout * 20)
        try:
            async with self._sem:
                fr = await asyncio.wait_for(source.fetch(ctx), timeout=budget)
        except asyncio.TimeoutError:
            fr = SourceFetchResult(source=source.name, ok=False,
                                   error=f"timeout after {budget:.0f}s", health="failing")
        except Exception as exc:
            logger.exception("CVE source %s raised", source.name)
            fr = SourceFetchResult(source=source.name, ok=False,
                                   error=f"{type(exc).__name__}: {exc}", health="failing")

        self._persist_state(source, state, fr)
        if fr.latency_ms:
            self.metrics.observe(M_SOURCE_LATENCY, fr.latency_ms)
        if not fr.ok:
            self.metrics.incr(M_SOURCE_FAIL)
        if self.audit:
            self.audit.source_sync(source.name, ok=fr.ok, seen=fr.record_count,
                                   new=0, updated=0, error=fr.error)
        return fr

    def _load_state(self, name: str) -> SourceState:
        if not self.repo:
            return SourceState(source=name)
        try:
            return self.repo.get_source_state(name)
        except Exception:
            return SourceState(source=name)

    def _persist_state(self, source: CVESource, state: SourceState,
                       fr: SourceFetchResult) -> None:
        now = now_epoch()
        state.total_runs += 1
        state.last_latency_ms = fr.latency_ms
        if fr.ok:
            state.last_success_at = now
            state.consecutive_failures = 0
            state.last_error = ""
            state.records_seen += fr.record_count
            if fr.new_cursor:
                state.last_cursor = fr.new_cursor
            if fr.new_etag:
                state.etag = fr.new_etag
            if fr.new_http_last_modified:
                state.http_last_modified = fr.new_http_last_modified
            if fr.new_last_modified_seen:
                state.last_modified_seen = fr.new_last_modified_seen
        else:
            state.last_failure_at = now
            state.consecutive_failures += 1
            state.last_error = fr.error
        state.health = evaluate_source(
            state, enabled=source.config.enabled)
        if not self.repo:
            return
        try:
            self.repo.save_source_state(state)
        except Exception:
            logger.debug("CVE could not persist source state for %s", source.name, exc_info=True)

    # ---------------- reconciliation ----------------

    async def _reconcile(self, records: List[CVERecord], result: RoundResult) -> None:
        """Merge each round record with its stored version, detect changes,
        prioritize, persist, and collect new/updated for alerting."""
        if not records:
            return
        for inc in records:
            try:
                old = self.repo.get_record(inc.cve_id) if self.repo else None
            except Exception:
                old = None

            if old is None:
                # Enrichment-only records (e.g. an EPSS-only row for a CVE we
                # don't yet track) carry no title/description/CVSS — they exist
                # to attach a signal to an EXISTING record, not to create one.
                # Skip persisting them standalone so EPSS can't flood the DB.
                if self._is_enrichment_only(inc):
                    continue
                prioritize(inc)
                self._save(inc)
                result.new_records.append(inc)
                result.new += 1
                self.metrics.incr(M_RECORDS_NEW)
                if self.audit:
                    self.audit.event("cve.discovered", inc.cve_id,
                                     {"sources": inc.source_names})
                    self.audit.cve_created(inc.cve_id, inc.source_names)
                continue

            old_snapshot = CVERecord.from_dict(old.to_dict())
            merged = merge_two(old, inc)
            enrich(merged)
            prioritize(merged)
            change_set = diff(old_snapshot, merged)
            self._save(merged)

            if change_set.changes:
                result.updated += 1
                self.metrics.incr(M_RECORDS_UPDATED)
                if self.audit:
                    for et in events_for(change_set):
                        self.audit.event(et, merged.cve_id)
                    self.audit.cve_updated(
                        merged.cve_id, [c.kind for c in change_set.changes])
                if should_notify_update(change_set, include_minor=False):
                    result.updated_pairs.append((merged, change_set))

    @staticmethod
    def _is_enrichment_only(rec: CVERecord) -> bool:
        """True when a record carries only an enrichment signal (EPSS and the
        like) with no substantive CVE content of its own."""
        enrichment_sources = {"epss"}
        srcs = set(rec.source_names)
        if not srcs or not srcs.issubset(enrichment_sources):
            return False
        return not (rec.title or rec.description or rec.cvss_scores
                    or rec.weaknesses or rec.references or rec.in_kev)

    def _save(self, rec: CVERecord) -> None:
        if not self.repo:
            return
        try:
            self.repo.save_record(rec)
        except Exception:
            logger.exception("CVE could not save record %s", rec.cve_id)
