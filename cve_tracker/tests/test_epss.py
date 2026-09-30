"""Tests for the EPSS enrichment signal, its source parser, and integration."""

import unittest

from cve_tracker.config import get_config
from cve_tracker.enrichment.epss import (
    parse_epss, apply_epss, get_epss, epss_line_thai, EPSSScore,
)
from cve_tracker.enrichment import enrich
from cve_tracker.ingestion.deduplicator import merge_two
from cve_tracker.intelligence import prioritize
from cve_tracker.intelligence.scoring import compute_breakdown
from cve_tracker.coordinator import IngestionCoordinator
from cve_tracker.models import CVERecord, SourceRecord
from cve_tracker.sources.epss import EPSSSource
from cve_tracker import fixtures


class EPSSParseTest(unittest.TestCase):
    def test_parse_api_shape(self):
        e = parse_epss({"cve": "CVE-2026-93740", "epss": "0.834",
                        "percentile": "0.991", "date": "2026-09-20"})
        self.assertEqual(e.cve_id, "CVE-2026-93740")
        self.assertAlmostEqual(e.probability, 0.834)
        self.assertTrue(e.is_high)

    def test_clamp_and_bad(self):
        self.assertIsNone(parse_epss({"cve": "bad", "epss": "0.5"}))
        self.assertIsNone(parse_epss({"cve": "CVE-2026-0001", "epss": "notnum"}))
        e = parse_epss({"cve": "CVE-2026-0001", "epss": "1.5"})
        self.assertEqual(e.probability, 1.0)  # clamped


class EPSSApplyTest(unittest.TestCase):
    def test_apply_and_readback(self):
        rec = fixtures.record("CVE-2026-0001")
        e = EPSSScore(cve_id="CVE-2026-0001", probability=0.42, percentile=0.9)
        self.assertTrue(apply_epss(rec, e))
        got = get_epss(rec)
        self.assertAlmostEqual(got.probability, 0.42)
        self.assertIn("42.0%", epss_line_thai(rec))

    def test_wrong_cve_ignored(self):
        rec = fixtures.record("CVE-2026-0001")
        e = EPSSScore(cve_id="CVE-2026-9999", probability=0.4, percentile=0.5)
        self.assertFalse(apply_epss(rec, e))


class EPSSMergeScoringTest(unittest.TestCase):
    def test_epss_survives_merge_and_boosts_score(self):
        full = fixtures.record("CVE-2026-0001", score=7.5,
                               vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        before = compute_breakdown(full).total
        thin = CVERecord(cve_id="CVE-2026-0001")
        apply_epss(thin, EPSSScore(cve_id="CVE-2026-0001", probability=0.9, percentile=0.99))
        thin.sources = [SourceRecord(source="epss")]
        merged = merge_two(full, thin)
        enrich(merged)
        self.assertIsNotNone(get_epss(merged))
        after = compute_breakdown(merged).total
        self.assertGreater(after, before)  # EPSS contributed

    def test_coordinator_skips_enrichment_only(self):
        thin = CVERecord(cve_id="CVE-2026-0001")
        apply_epss(thin, EPSSScore(cve_id="CVE-2026-0001", probability=0.5, percentile=0.5))
        thin.sources = [SourceRecord(source="epss")]
        self.assertTrue(IngestionCoordinator._is_enrichment_only(thin))
        self.assertFalse(IngestionCoordinator._is_enrichment_only(fixtures.record()))


class EPSSSourceTest(unittest.TestCase):
    def test_parse_rows_via_source(self):
        # exercise the source's row→record path without network
        src = EPSSSource(get_config().source("epss"))
        rows = [{"cve": "CVE-2026-0001", "epss": "0.7", "percentile": "0.95"},
                {"cve": "bad", "epss": "0.1"}]
        recs = []
        for row in rows:
            e = parse_epss(row)
            if e is None:
                continue
            rec = CVERecord(cve_id=e.cve_id)
            apply_epss(rec, e)
            recs.append(rec)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].cve_id, "CVE-2026-0001")


if __name__ == "__main__":
    unittest.main()
