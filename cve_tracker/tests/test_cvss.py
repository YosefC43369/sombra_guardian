"""Tests for the CVSS engine — parsing, official scoring, decode, explain."""

import unittest

from cve_tracker.enrichment import cvss
from cve_tracker.enums import Severity


class CVSSParseTest(unittest.TestCase):
    def test_v31_critical_score(self):
        s = cvss.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(s.version, "3.1")
        self.assertEqual(s.base_score, 9.8)
        self.assertEqual(s.base_severity, "CRITICAL")
        self.assertEqual(s.attack_vector, "Network")
        self.assertEqual(s.privileges_required, "None")
        self.assertEqual(s.exploitability_score, 3.9)
        self.assertEqual(s.impact_score, 5.9)

    def test_v31_scope_changed(self):
        s = cvss.parse_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N")
        self.assertEqual(s.base_score, 6.4)
        self.assertEqual(s.scope, "Changed")

    def test_v31_low(self):
        s = cvss.parse_vector("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
        self.assertEqual(s.base_score, 1.8)
        self.assertEqual(s.base_severity, "LOW")

    def test_v30_detected(self):
        s = cvss.parse_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(s.version, "3.0")
        self.assertEqual(s.base_score, 9.8)

    def test_provided_score_wins(self):
        s = cvss.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                              provided_score=9.1)
        self.assertEqual(s.base_score, 9.1)  # not recomputed

    def test_v2_not_computed_but_decoded(self):
        s = cvss.parse_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P", provided_score=7.5)
        self.assertEqual(s.version, "2.0")
        self.assertEqual(s.base_score, 7.5)
        self.assertEqual(s.attack_vector, "Network")
        self.assertEqual(s.privileges_required, "None")

    def test_v4_decoded_score_carried(self):
        s = cvss.parse_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            provided_score=9.3)
        self.assertEqual(s.version, "4.0")
        self.assertEqual(s.base_score, 9.3)
        self.assertEqual(s.attack_vector, "Network")

    def test_invalid_vector_returns_none(self):
        self.assertIsNone(cvss.parse_vector("not a vector"))
        self.assertIsNone(cvss.parse_vector(""))

    def test_no_invented_score_for_v2_without_provided(self):
        s = cvss.parse_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P")
        self.assertIsNone(s.base_score)  # never invents a v2 score


class CVSSPickAndExplainTest(unittest.TestCase):
    def test_pick_primary_prefers_newer_version(self):
        v2 = cvss.build_score(version="2.0", base_score=7.5, source="nvd")
        v31 = cvss.build_score(version="3.1", base_score=9.8, source="nvd")
        self.assertEqual(cvss.pick_primary([v2, v31]).version, "3.1")

    def test_explain_lines(self):
        s = cvss.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        lines = cvss.explain(s)
        self.assertIn("CVSS 3.1: 9.8 (CRITICAL)", lines[0])
        self.assertTrue(any("Attack Vector: Network" in l for l in lines))


class SeverityBandTest(unittest.TestCase):
    def test_from_score_v3(self):
        self.assertEqual(Severity.from_cvss_score(9.8), Severity.CRITICAL)
        self.assertEqual(Severity.from_cvss_score(7.0), Severity.HIGH)
        self.assertEqual(Severity.from_cvss_score(4.0), Severity.MEDIUM)
        self.assertEqual(Severity.from_cvss_score(0.1), Severity.LOW)
        self.assertEqual(Severity.from_cvss_score(0.0), Severity.NONE)
        self.assertEqual(Severity.from_cvss_score(None), Severity.UNKNOWN)

    def test_from_score_v2_bands(self):
        self.assertEqual(Severity.from_cvss_score(7.0, version="2.0"), Severity.HIGH)
        self.assertEqual(Severity.from_cvss_score(4.0, version="2.0"), Severity.MEDIUM)

    def test_ordering(self):
        self.assertTrue(Severity.CRITICAL >= Severity.HIGH)
        self.assertTrue(Severity.LOW < Severity.MEDIUM)


if __name__ == "__main__":
    unittest.main()
