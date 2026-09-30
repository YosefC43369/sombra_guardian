"""End-to-end integration: coordinator round, change detection, failure
isolation, engine sync, dispatch — all with fake sources and a fake bot."""

import asyncio
import os
import tempfile
import unittest
from dataclasses import replace

from cve_tracker.config import get_config
from cve_tracker.storage import CVERepository, migrations
from cve_tracker.coordinator import IngestionCoordinator
from cve_tracker.sources.registry import SourceRegistry
from cve_tracker.sources.base import CVESource
from cve_tracker.monitoring.metrics import MetricsRegistry
from cve_tracker.monitoring.audit import AuditLogger
from cve_tracker.models import Subscription
from cve_tracker import fixtures


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _FakeSource(CVESource):
    name = "fake"
    kind = "nvd"

    def __init__(self, sc, records):
        super().__init__(sc)
        self._records = records

    async def fetch(self, ctx):
        return self._success(list(self._records), new_last_modified_seen=1789000000)


class _FailingSource(CVESource):
    name = "boom"
    kind = "nvd"

    async def fetch(self, ctx):
        raise RuntimeError("simulated source crash")


class CoordinatorRoundTest(unittest.TestCase):
    def setUp(self):
        self.db = tempfile.mktemp(suffix=".db")
        migrations.apply(self.db)
        self.repo = CVERepository(self.db)
        self.cfg = get_config()
        self.cfg.sources["fake"] = replace(self.cfg.sources["nvd"], name="fake")
        self.cfg.sources["boom"] = replace(self.cfg.sources["nvd"], name="boom")

    def tearDown(self):
        os.remove(self.db)

    def _coord(self, records):
        reg = SourceRegistry()
        reg.register("fake", lambda sc: _FakeSource(sc, records))
        return IngestionCoordinator(self.cfg, self.repo, registry=reg,
                                    metrics=MetricsRegistry(), audit=AuditLogger(self.repo))

    def test_new_then_update(self):
        r1 = [fixtures.record("CVE-2026-0001", score=7.5,
                              vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                              source="nvd")]
        res1 = _run(self._coord(r1).run_round(only_source="fake"))
        self.assertEqual(res1.new, 1)
        self.assertEqual(self.repo.count(), 1)

        r2 = [fixtures.record("CVE-2026-0001", score=9.8,
                              vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                              kev=True, source="nvd")]
        res2 = _run(self._coord(r2).run_round(only_source="fake"))
        self.assertEqual(res2.new, 0)
        self.assertEqual(res2.updated, 1)
        self.assertTrue(res2.updated_pairs)
        kinds = {c.kind for c in res2.updated_pairs[0][1].changes}
        self.assertIn("kev_status", kinds)

    def test_source_failure_isolated(self):
        # One round with a working source AND a crashing source: the crash must
        # not stop the working source from ingesting (rule §46).
        reg = SourceRegistry()
        reg.register("fake", lambda sc: _FakeSource(sc, [fixtures.record("CVE-2026-0001")]))
        reg.register("boom", lambda sc: _FailingSource(sc))
        coord = IngestionCoordinator(self.cfg, self.repo, registry=reg,
                                     metrics=MetricsRegistry(), audit=AuditLogger(self.repo))
        res = _run(coord.run_round())  # both sources enabled in this cfg
        # fake still produced its new record despite boom crashing
        self.assertEqual(res.new, 1)
        self.assertTrue(any(not sr.ok for sr in res.source_results))   # boom failed
        self.assertTrue(any(sr.ok for sr in res.source_results))       # fake ok
        st = self.repo.get_source_state("boom")
        self.assertGreaterEqual(st.consecutive_failures, 1)

    def test_source_health_persisted(self):
        coord = self._coord([fixtures.record("CVE-2026-0001")])
        _run(coord.run_round(only_source="fake"))
        st = self.repo.get_source_state("fake")
        self.assertEqual(st.health, "healthy")
        self.assertIsNotNone(st.last_success_at)


class EngineDispatchTest(unittest.TestCase):
    def test_sync_now_and_dispatch(self):
        db = tempfile.mktemp(suffix=".db")
        migrations.apply(db)
        repo = CVERepository(db)
        cfg = get_config()
        cfg.sources["fake"] = replace(cfg.sources["nvd"], name="fake")
        repo.upsert_subscription(Subscription(chat_id=-100, min_severity="HIGH"))

        from cve_tracker.engine import CVETracker
        reg = SourceRegistry()
        reg.register("fake", lambda sc: _FakeSource(sc, [fixtures.record("CVE-2026-0001")]))

        tracker = CVETracker(cfg, db_path=db)
        tracker.registry = reg
        tracker.coordinator = IngestionCoordinator(
            cfg, repo, registry=reg, metrics=tracker.metrics, audit=tracker.audit)

        sent = []

        class FakeBot:
            async def send_message(self, **kw):
                sent.append(kw.get("chat_id"))

        tracker.bot = FakeBot()
        res = _run(tracker.sync_now(source="fake"))
        self.assertEqual(res["new"], 1)
        self.assertIn(-100, sent)
        # idempotent: second sync sends nothing new (already sent)
        sent.clear()
        _run(tracker.sync_now(source="fake"))
        self.assertEqual(sent, [])
        os.remove(db)


if __name__ == "__main__":
    unittest.main()
