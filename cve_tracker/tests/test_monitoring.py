"""Tests for monitoring: metrics, health, audit, diagnostics; plus EPSS + digest."""

import os
import tempfile
import unittest

from cve_tracker.config import get_config
from cve_tracker.monitoring.metrics import MetricsRegistry
from cve_tracker.monitoring.health import HealthTracker, evaluate_source
from cve_tracker.monitoring.audit import AuditLogger
from cve_tracker.monitoring.diagnostics import DiagnosticsService
from cve_tracker.enums import SourceHealthState
from cve_tracker.models import SourceState
from cve_tracker.storage import CVERepository, migrations
from cve_tracker import fixtures


class MetricsTest(unittest.TestCase):
    def test_counters_gauges_timers(self):
        m = MetricsRegistry()
        m.incr("x", 3)
        m.incr("x")
        m.gauge("g", 5)
        m.observe("t", 100)
        m.observe("t", 300)
        snap = m.snapshot()
        self.assertEqual(snap["counters"]["x"], 4)
        self.assertEqual(snap["gauges"]["g"], 5)
        self.assertEqual(snap["timers"]["t"]["avg_ms"], 200.0)
        self.assertEqual(snap["timers"]["t"]["max_ms"], 300.0)


class HealthTest(unittest.TestCase):
    def test_evaluate_source(self):
        self.assertEqual(evaluate_source(SourceState(source="x", consecutive_failures=5)),
                         SourceHealthState.FAILING.value)
        self.assertEqual(evaluate_source(SourceState(source="x", consecutive_failures=2)),
                         SourceHealthState.DEGRADED.value)
        import time
        self.assertEqual(evaluate_source(SourceState(source="x", last_success_at=int(time.time()))),
                         SourceHealthState.HEALTHY.value)
        self.assertEqual(evaluate_source(SourceState(source="x"), enabled=False),
                         SourceHealthState.DISABLED.value)

    def test_report(self):
        db = tempfile.mktemp(suffix=".db")
        migrations.apply(db)
        repo = CVERepository(db)
        import time
        repo.save_source_state(SourceState(source="nvd", last_success_at=int(time.time()),
                                           health="healthy"))
        repo.save_source_state(SourceState(source="cisa_kev", consecutive_failures=6,
                                           health="failing"))
        tracker = HealthTracker(repo, get_config())
        report = tracker.report()
        self.assertIn("nvd", report.sources)
        self.assertEqual(report.overall, SourceHealthState.FAILING.value)
        os.remove(db)


class AuditTest(unittest.TestCase):
    def test_audit_and_events(self):
        db = tempfile.mktemp(suffix=".db")
        migrations.apply(db)
        repo = CVERepository(db)
        emitted = []
        audit = AuditLogger(repo, emit=lambda et, p: emitted.append(et))
        audit.event("cve.discovered", "CVE-2026-0001", {"x": 1})
        audit.cve_created("CVE-2026-0001", ["nvd"])
        audit.source_sync("nvd", ok=True, seen=5, new=2, updated=1)
        self.assertIn("cve.discovered", emitted)
        self.assertGreaterEqual(len(repo.recent_events()), 1)
        os.remove(db)


class DiagnosticsTest(unittest.TestCase):
    def test_snapshot_and_selftest(self):
        db = tempfile.mktemp(suffix=".db")
        migrations.apply(db)
        repo = CVERepository(db)
        repo.save_record(fixtures.record("CVE-2026-0001"))
        diag = DiagnosticsService(repo, get_config())
        snap = diag.snapshot()
        self.assertEqual(snap["record_count"], 1)
        self.assertIn("health", snap)
        st = diag.selftest()
        self.assertTrue(st["storage"])
        self.assertTrue(st["schema"])
        os.remove(db)


class DigestTest(unittest.TestCase):
    def test_build_digest(self):
        from cve_tracker.alerts.digest import DigestBuilder, DigestOptions, build_digest
        recs = [fixtures.record("CVE-2026-0001", kev=True),
                fixtures.record_low("CVE-2026-0002"),
                fixtures.record_high("CVE-2026-0003")]
        from cve_tracker.intelligence import prioritize
        for r in recs:
            prioritize(r)
        text = build_digest(recs, DigestOptions(window_days=1))
        self.assertIn("สรุป CVE", text)
        self.assertIn("CVE-2026-0001", text)
        # KEV/critical should sort to the top
        self.assertLess(text.index("CVE-2026-0001"), text.index("CVE-2026-0002"))


class ReportingTest(unittest.TestCase):
    def test_report_build_and_render(self):
        from cve_tracker.monitoring.reporting import ReportBuilder
        db = tempfile.mktemp(suffix=".db")
        migrations.apply(db)
        repo = CVERepository(db)
        repo.save_record(fixtures.record("CVE-2026-0001", vendor="Apache", product="HTTP Server", kev=True))
        repo.save_record(fixtures.record("CVE-2026-0002", vendor="Apache", product="Tomcat"))
        rb = ReportBuilder(repo)
        rep = rb.build(window_days=7)
        self.assertEqual(rep.total, 2)
        self.assertEqual(rep.kev_total, 1)
        self.assertTrue(rep.top_vendors)
        self.assertTrue(rep.source_distribution)
        text = rb.render_thai(rep)
        self.assertIn("รายงาน CVE", text)
        self.assertIn("Apache", text)
        os.remove(db)


if __name__ == "__main__":
    unittest.main()
