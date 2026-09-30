"""Tests for the intelligence layer: scoring, prioritization, risk, exposure,
correlation, similarity, change detection."""

import os
import tempfile
import unittest

from cve_tracker.intelligence.scoring import compute_breakdown, compute_score
from cve_tracker.intelligence.prioritization import (
    prioritize, band_for_score, order_for_dispatch, event_priority_rank,
)
from cve_tracker.intelligence.risk import assess_risk
from cve_tracker.intelligence.exposure import assess
from cve_tracker.intelligence.similarity import title_similarity, record_similarity, is_likely_same
from cve_tracker.intelligence.correlation import CorrelationEngine
from cve_tracker.intelligence.change_detection import diff, should_notify_update, events_for
from cve_tracker.enums import Priority, ChangeKind
from cve_tracker.models import CVERecord, ChangeSet
from cve_tracker.storage import CVERepository, migrations
from cve_tracker import fixtures


class ScoringTest(unittest.TestCase):
    def test_kev_critical_is_urgent(self):
        rec = fixtures.record(kev=True)
        prioritize(rec)
        self.assertEqual(rec.priority, Priority.URGENT.value)
        self.assertGreaterEqual(rec.priority_score, 80)

    def test_low_is_low(self):
        rec = fixtures.record_low()
        prioritize(rec)
        self.assertIn(rec.priority, (Priority.INFO.value, Priority.LOW.value, Priority.MEDIUM.value))

    def test_breakdown_transparent(self):
        rec = fixtures.record(kev=True)
        bd = compute_breakdown(rec)
        labels = {c[0] for c in bd.components}
        self.assertIn("CVSS", labels)
        self.assertIn("KEV", labels)
        self.assertEqual(bd.total, compute_score(rec))

    def test_band_boundaries(self):
        self.assertEqual(band_for_score(80), Priority.URGENT)
        self.assertEqual(band_for_score(60), Priority.HIGH)
        self.assertEqual(band_for_score(40), Priority.MEDIUM)
        self.assertEqual(band_for_score(20), Priority.LOW)
        self.assertEqual(band_for_score(0), Priority.INFO)

    def test_order_for_dispatch(self):
        a = fixtures.record("CVE-2026-0001", kev=True)
        b = fixtures.record_low("CVE-2026-0002")
        prioritize(a); prioritize(b)
        ordered = order_for_dispatch([b, a])
        self.assertEqual(ordered[0].cve_id, a.cve_id)


class RiskExposureTest(unittest.TestCase):
    def test_risk_indicators(self):
        rec = fixtures.record(kev=True)
        ri = assess_risk(rec)
        self.assertTrue(ri.kev)
        self.assertGreaterEqual(ri.exploit_reference_count, 1)
        self.assertEqual(ri.source_confidence, "low")  # single source

    def test_exposure_wormable(self):
        rec = fixtures.record()  # AV:N/PR:N/UI:N
        prof = assess(rec)
        self.assertTrue(prof.is_wormable_shape)
        self.assertTrue(prof.network_reachable)


class SimilarityTest(unittest.TestCase):
    def test_title_similarity(self):
        self.assertGreater(
            title_similarity("Totolink A3002MU Buffer Overflow",
                             "Totolink A3002MU stack buffer overflow"), 0.3)

    def test_same_cve_is_one(self):
        a = fixtures.record("CVE-2026-0001")
        b = fixtures.record("CVE-2026-0001")
        self.assertEqual(record_similarity(a, b), 1.0)
        self.assertTrue(is_likely_same(a, b))


class CorrelationTest(unittest.TestCase):
    def setUp(self):
        self.db = tempfile.mktemp(suffix=".db")
        migrations.apply(self.db)
        self.repo = CVERepository(self.db)
        self.repo.save_record(fixtures.record("CVE-2026-0001", vendor="Apache", product="HTTP Server"))
        self.repo.save_record(fixtures.record("CVE-2026-0002", vendor="Apache", product="Tomcat"))
        self.repo.save_record(fixtures.record("CVE-2026-0003", kev=True))
        self.eng = CorrelationEngine(self.repo)

    def tearDown(self):
        os.remove(self.db)

    def test_by_vendor(self):
        res = self.eng.related_by_vendor("apache")
        self.assertEqual(res.total, 2)

    def test_by_cwe_and_kev(self):
        self.assertGreaterEqual(self.eng.related_by_cwe("CWE-121").total, 3)
        self.assertEqual(self.eng.in_kev().total, 1)

    def test_affected_by_version(self):
        from cve_tracker.models import AffectedProduct
        rec = fixtures.record("CVE-2026-0050", vendor="Apache", product="HTTP Server")
        rec.products = [AffectedProduct(
            vendor="Apache", product="HTTP Server",
            version_start_including="2.4.0", version_end_excluding="2.4.59")]
        self.repo.save_record(rec)
        hits = self.eng.affected_by("HTTP Server", "2.4.50", vendor="apache")
        self.assertTrue(any(r.cve_id == "CVE-2026-0050" for r in hits))
        # a version outside the range is not reported
        miss = self.eng.affected_by("HTTP Server", "2.4.60", vendor="apache")
        self.assertFalse(any(r.cve_id == "CVE-2026-0050" for r in miss))


class ChangeDetectionTest(unittest.TestCase):
    def test_significant_changes(self):
        old = fixtures.record("CVE-2026-0001", score=7.5,
                              vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        new = fixtures.record("CVE-2026-0001", score=9.8, kev=True,
                              vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        cs = diff(old, new)
        kinds = {c.kind for c in cs.changes}
        self.assertIn(ChangeKind.SEVERITY.value, kinds)
        self.assertIn(ChangeKind.KEV_STATUS.value, kinds)
        self.assertTrue(cs.has_significant)
        self.assertTrue(should_notify_update(cs))

    def test_no_change(self):
        rec = fixtures.record("CVE-2026-0001")
        cs = diff(rec, CVERecord.from_dict(rec.to_dict()))
        self.assertFalse(cs.changes)
        self.assertFalse(should_notify_update(cs))

    def test_event_priority_rank(self):
        kev_cs = ChangeSet(cve_id="x")
        from cve_tracker.models import FieldChange
        kev_cs.changes.append(FieldChange(kind=ChangeKind.KEV_STATUS.value, after=True))
        self.assertEqual(event_priority_rank(kev_cs), 100)
        self.assertIn("cve.kev_added", events_for(kev_cs))


if __name__ == "__main__":
    unittest.main()
