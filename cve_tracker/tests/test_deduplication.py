"""Tests for cross-source de-duplication and provenance-preserving merge."""

import unittest

from cve_tracker.ingestion.deduplicator import merge_two, dedupe_batch
from cve_tracker.enrichment import enrich
from cve_tracker.intelligence.change_detection import diff
from cve_tracker.models import CVERecord, SourceRecord, CVSSScore
from cve_tracker import fixtures


class MergeTest(unittest.TestCase):
    def test_kev_from_any_source_wins(self):
        base = fixtures.record("CVE-2026-0001", source="nvd")
        kev = fixtures.record("CVE-2026-0001", source="cisa_kev", kev=True,
                              vector="", score=None, cwe="", refs=[])
        merged = merge_two(base, kev)
        self.assertTrue(merged.in_kev)

    def test_conflict_keeps_both_scores(self):
        nvd = fixtures.record("CVE-2026-0001", source="nvd", score=8.8,
                              vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        vendor = fixtures.record("CVE-2026-0001", source="vendor_advisory", score=9.1,
                                 vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
        merged = merge_two(nvd, vendor)
        scores = {round(s.base_score, 1) for s in merged.cvss_scores if s.base_score}
        self.assertIn(8.8, scores)
        self.assertIn(9.1, scores)
        # display picks the higher-trust source (vendor=85 > nvd=90? nvd wins)
        self.assertIn("cvss_score", merged.provenance)

    def test_higher_trust_wins_display(self):
        nvd = fixtures.record("CVE-2026-0001", source="nvd", score=8.8,
                              vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        other = fixtures.record("CVE-2026-0001", source="other", score=5.0,
                                vector="CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N")
        merged = merge_two(nvd, other)
        # nvd trust (90) > other (40) → nvd's 8.8 on display
        self.assertEqual(merged.cvss_score, 8.8)

    def test_references_unioned(self):
        a = fixtures.record("CVE-2026-0001", source="nvd",
                            refs=[{"url": "https://a.example/1"}])
        b = fixtures.record("CVE-2026-0001", source="cve_org",
                            refs=[{"url": "https://b.example/2"}])
        merged = merge_two(a, b)
        urls = {r.url for r in merged.references}
        self.assertEqual(len(urls), 2)

    def test_dedupe_batch(self):
        recs = [
            fixtures.record("CVE-2026-0001", source="nvd"),
            fixtures.record("CVE-2026-0001", source="cisa_kev", kev=True,
                            vector="", score=None, cwe="", refs=[]),
            fixtures.record("CVE-2026-0002", source="nvd"),
        ]
        out = dedupe_batch(recs)
        self.assertEqual(len(out), 2)
        first = [r for r in out if r.cve_id == "CVE-2026-0001"][0]
        self.assertTrue(first.in_kev)

    def test_rescore_supersedes_same_source(self):
        old = fixtures.record("CVE-2026-0001", source="nvd", score=7.5,
                              vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        snap = CVERecord.from_dict(old.to_dict())
        inc = fixtures.record("CVE-2026-0001", source="nvd", score=9.8,
                              vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        merged = merge_two(old, inc)
        enrich(merged)
        self.assertEqual(merged.cvss_score, 9.8)
        cs = diff(snap, merged)
        kinds = {c.kind for c in cs.changes}
        self.assertIn("cvss", kinds)
        self.assertIn("severity", kinds)


class FixtureSetTest(unittest.TestCase):
    """Exercise the explicit §43 fixture set through the pipeline."""

    def test_named_fixtures(self):
        self.assertEqual(fixtures.record_critical().severity, "CRITICAL")
        self.assertTrue(fixtures.record_kev().in_kev)
        self.assertEqual(fixtures.record_no_cwe().cwe_ids, [])
        self.assertEqual(fixtures.record_no_cpe().products, [])
        self.assertGreaterEqual(len(fixtures.record_multi_ref().references), 4)

    def test_duplicate_sources_merge_to_one(self):
        from cve_tracker.ingestion.pipeline import IngestionPipeline
        recs = fixtures.records_duplicate_sources()
        out = IngestionPipeline().process(recs)
        self.assertEqual(out.total_out, 1)
        merged = out.records[0]
        self.assertTrue(merged.in_kev)
        self.assertEqual(sorted(merged.source_names), ["cisa_kev", "cve_org", "nvd"])

    def test_updated_cvss_pair_detects_change(self):
        old, new = fixtures.record_updated_cvss()
        cs = diff(old, new)
        self.assertIn("cvss", {c.kind for c in cs.changes})


if __name__ == "__main__":
    unittest.main()
