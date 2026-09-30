"""Tests for the source adapters' parsers, using mocked payloads (no network)."""

import unittest

from cve_tracker.config import get_config
from cve_tracker.sources.nvd import NVDSource
from cve_tracker.sources.cve_org import CVEOrgSource
from cve_tracker.sources.github_advisories import GitHubAdvisorySource
from cve_tracker.enrichment.kev import parse_kev_entry
from cve_tracker import fixtures


class NVDParserTest(unittest.TestCase):
    def setUp(self):
        self.src = NVDSource(get_config().source("nvd"))

    def test_full_parse(self):
        rec = self.src._parse_vuln(fixtures.nvd_vuln())
        self.assertEqual(rec.cve_id, "CVE-2026-93740")
        self.assertEqual(rec.cvss_scores[0].base_score, 9.8)
        self.assertIn("CWE-121", rec.cwe_ids)
        self.assertTrue(any(p.product for p in rec.products))
        self.assertTrue(len(rec.references) >= 2)
        self.assertEqual(rec.sources[0].source, "nvd")

    def test_missing_metrics_ok(self):
        rec = self.src._parse_vuln(
            fixtures.nvd_vuln("CVE-2026-0001", score=None, vector="", severity=""))
        self.assertEqual(rec.cve_id, "CVE-2026-0001")
        self.assertEqual(rec.cvss_scores, [])

    def test_malformed_item_skipped(self):
        data = fixtures.nvd_malformed()
        parsed = [self.src._parse_vuln(x) for x in data["vulnerabilities"]]
        parsed = [p for p in parsed if p is not None]
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].cve_id, "CVE-2026-00042")


class CVEOrgParserTest(unittest.TestCase):
    def setUp(self):
        self.src = CVEOrgSource(get_config().source("cve_org"))

    def test_parse_5x(self):
        rec = self.src._parse_record(fixtures.cve_org_record())
        self.assertEqual(rec.cve_id, "CVE-2026-93740")
        self.assertEqual(rec.cvss_scores[0].base_score, 9.1)
        self.assertIn("CWE-121", rec.cwe_ids)
        self.assertIn("TOTOLINK", [p.vendor for p in rec.products])


class GitHubParserTest(unittest.TestCase):
    def setUp(self):
        self.src = GitHubAdvisorySource(get_config().source("github_advisory"))

    def test_parse_advisory(self):
        rec = self.src._parse_advisory(fixtures.ghsa_advisory())
        self.assertEqual(rec.cve_id, "CVE-2026-93740")
        self.assertTrue(any(s.base_score == 9.8 for s in rec.cvss_scores))
        self.assertIn("CWE-121", rec.cwe_ids)
        self.assertTrue(rec.aliases)  # GHSA alias captured


class KEVParserTest(unittest.TestCase):
    def test_parse_entry(self):
        k = parse_kev_entry(fixtures.kev_entry())
        self.assertTrue(k.in_kev)
        self.assertEqual(k.product, "A3002MU")
        self.assertIsNotNone(k.date_added)
        self.assertEqual(k.required_action, "Apply mitigations per vendor instructions.")

    def test_bad_entry(self):
        self.assertIsNone(parse_kev_entry({"no": "id"}))


if __name__ == "__main__":
    unittest.main()
