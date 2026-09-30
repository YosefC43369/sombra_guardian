"""Tests for coordinator mechanics: round recording, not-modified handling,
enrichment-only skip, concurrency isolation, scheduler shutdown, fetcher guards."""

import asyncio
import os
import tempfile
import unittest
from dataclasses import replace

from cve_tracker.config import get_config
from cve_tracker.storage import CVERepository, migrations
from cve_tracker.coordinator import IngestionCoordinator
from cve_tracker.scheduler import CVEScheduler
from cve_tracker.sources.registry import SourceRegistry
from cve_tracker.sources.base import CVESource
from cve_tracker.ingestion.ratelimit import RateLimiterRegistry, TokenBucket
from cve_tracker.ingestion.fetcher import HttpFetcher, FetchResult
from cve_tracker.monitoring.metrics import MetricsRegistry
from cve_tracker.monitoring.audit import AuditLogger
from cve_tracker.models import CVERecord, SourceRecord
from cve_tracker.enrichment.epss import apply_epss, EPSSScore
from cve_tracker import fixtures


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _Src(CVESource):
    name = "fake"
    kind = "nvd"

    def __init__(self, sc, records, *, not_modified=False):
        super().__init__(sc)
        self._records = records
        self._nm = not_modified

    async def fetch(self, ctx):
        if self._nm:
            return self._empty(not_modified=True)
        return self._success(list(self._records), new_last_modified_seen=1789000000)


class CoordinatorTest(unittest.TestCase):
    def setUp(self):
        self.db = tempfile.mktemp(suffix=".db")
        migrations.apply(self.db)
        self.repo = CVERepository(self.db)
        self.cfg = get_config()
        self.cfg.sources["fake"] = replace(self.cfg.sources["nvd"], name="fake")

    def tearDown(self):
        os.remove(self.db)

    def _coord(self, recs, **kw):
        reg = SourceRegistry()
        reg.register("fake", lambda sc: _Src(sc, recs, **kw))
        return IngestionCoordinator(self.cfg, self.repo, registry=reg,
                                    metrics=MetricsRegistry(), audit=AuditLogger(self.repo))

    def test_round_records_run(self):
        _run(self._coord([fixtures.record("CVE-2026-0001")]).run_round(only_source="fake"))
        # ingestion run row written
        conn = self.repo._conn()
        try:
            n = conn.execute("SELECT COUNT(*) n FROM cve_ingestion_runs").fetchone()["n"]
        finally:
            conn.close()
        self.assertGreaterEqual(n, 1)

    def test_not_modified_no_records(self):
        res = _run(self._coord([], not_modified=True).run_round(only_source="fake"))
        self.assertEqual(res.new, 0)
        self.assertEqual(self.repo.count(), 0)

    def test_enrichment_only_not_persisted(self):
        thin = CVERecord(cve_id="CVE-2026-0001")
        apply_epss(thin, EPSSScore(cve_id="CVE-2026-0001", probability=0.5, percentile=0.5))
        thin.sources = [SourceRecord(source="epss")]
        res = _run(self._coord([thin]).run_round(only_source="fake"))
        self.assertEqual(res.new, 0)
        self.assertEqual(self.repo.count(), 0)  # EPSS-only not stored standalone

    def test_source_state_counters(self):
        _run(self._coord([fixtures.record("CVE-2026-0001")]).run_round(only_source="fake"))
        st = self.repo.get_source_state("fake")
        self.assertEqual(st.total_runs, 1)
        self.assertEqual(st.health, "healthy")
        self.assertIsNotNone(st.last_modified_seen)


class SchedulerTest(unittest.TestCase):
    def test_run_once_and_stop(self):
        db = tempfile.mktemp(suffix=".db")
        migrations.apply(db)
        repo = CVERepository(db)
        cfg = get_config()
        cfg.sources["fake"] = replace(cfg.sources["nvd"], name="fake")
        reg = SourceRegistry()
        reg.register("fake", lambda sc: _Src(sc, [fixtures.record("CVE-2026-0001")]))
        coord = IngestionCoordinator(cfg, repo, registry=reg,
                                     metrics=MetricsRegistry(), audit=AuditLogger(repo))
        sched = CVEScheduler(cfg, coord, dispatcher=None)
        result = _run(sched.run_once())
        self.assertEqual(result.new, 1)
        sched.stop()  # idempotent, no loop running
        os.remove(db)


class FetcherGuardTest(unittest.TestCase):
    def test_rate_limiter_registry(self):
        reg = RateLimiterRegistry()
        b = reg.configure("nvd", 2.0)
        self.assertIsInstance(b, TokenBucket)
        self.assertIs(reg.get("nvd"), b)

    def test_fetch_result_flags(self):
        self.assertTrue(FetchResult(status=200, url="x").ok)
        self.assertTrue(FetchResult(status=304, url="x", from_cache=True).not_modified)
        self.assertFalse(FetchResult(status=500, url="x").ok)

    def test_size_ceiling_clamped(self):
        f = HttpFetcher(user_agent="t", max_response_bytes=10 ** 12)
        from cve_tracker.constants import ABSOLUTE_MAX_RESPONSE_BYTES
        self.assertLessEqual(f.max_response_bytes, ABSOLUTE_MAX_RESPONSE_BYTES)


if __name__ == "__main__":
    unittest.main()
