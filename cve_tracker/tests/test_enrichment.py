"""Tests for enrichment engines: CWE, CPE, references, exploit-status, timeline."""

import unittest

from cve_tracker.enrichment.cwe import (
    make_weakness, catalog_name, format_cwe_label, merge_weaknesses,
)
from cve_tracker.enrichment.cpe import (
    parse_cpe, products_from_nvd_configurations, format_product_label,
    version_range_label, merge_products,
)
from cve_tracker.enrichment.references import classify_reference, classify_references, count_by_type
from cve_tracker.enrichment.exploit_status import (
    compute, exploit_line_thai, exploit_reference_count, from_references,
)
from cve_tracker.enrichment import timeline
from cve_tracker.enrichment.vendors import canonical_vendor, match_vendor
from cve_tracker.enums import ReferenceType, ExploitMaturity
from cve_tracker.models import Reference, KEVInfo
from cve_tracker import fixtures


class CWETest(unittest.TestCase):
    def test_make_weakness_fills_name(self):
        w = make_weakness("CWE-79")
        self.assertEqual(w.cwe_id, "CWE-79")
        self.assertIn("XSS", w.name + format_cwe_label("CWE-79"))

    def test_nvd_special_tokens(self):
        self.assertEqual(make_weakness("NVD-CWE-noinfo").cwe_id, "CWE-noinfo")
        self.assertEqual(make_weakness("NVD-CWE-Other").cwe_id, "CWE-Other")

    def test_merge(self):
        a = [make_weakness("CWE-79")]
        b = [make_weakness("CWE-79"), make_weakness("CWE-89")]
        merged = merge_weaknesses(a, b)
        self.assertEqual({w.cwe_id for w in merged}, {"CWE-79", "CWE-89"})

    def test_catalog_expanded(self):
        # verify some of the expanded catalogue entries resolve
        for cid in ("CWE-918", "CWE-502", "CWE-1333", "CWE-639", "CWE-295"):
            self.assertTrue(catalog_name(cid), cid)


class CPETest(unittest.TestCase):
    def test_parse_cpe23(self):
        ap = parse_cpe("cpe:2.3:o:totolink:a3002mu_firmware:1.1.0:*:*:*:*:*:*:*")
        self.assertEqual(ap.vendor, "totolink")
        self.assertIn("a3002mu", ap.product)
        self.assertEqual(ap.versions_affected, ["1.1.0"])

    def test_nvd_configurations_with_range(self):
        cfg = [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.59"}]}]}]
        prods = products_from_nvd_configurations(cfg)
        self.assertEqual(len(prods), 1)
        self.assertEqual(prods[0].version_start_including, "2.4.0")
        self.assertIn("< 2.4.59", version_range_label(prods[0]))

    def test_non_vulnerable_skipped(self):
        cfg = [{"nodes": [{"cpeMatch": [{
            "vulnerable": False, "criteria": "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}]}]}]
        self.assertEqual(products_from_nvd_configurations(cfg), [])


class ReferenceTest(unittest.TestCase):
    def test_classify_exploit_db(self):
        r = classify_reference("https://www.exploit-db.com/exploits/50000")
        self.assertEqual(r.ref_type, ReferenceType.EXPLOIT_DB.value)

    def test_classify_patch(self):
        r = classify_reference("https://github.com/x/y/commit/abc123")
        self.assertIn(r.ref_type, (ReferenceType.PATCH.value, ReferenceType.GITHUB_REPO.value))

    def test_classify_vendor(self):
        r = classify_reference("https://msrc.microsoft.com/advisory/1")
        self.assertEqual(r.ref_type, ReferenceType.VENDOR_ADVISORY.value)

    def test_exploit_tag_wins(self):
        r = classify_reference("https://github.com/x/poc", tags=["Exploit"])
        self.assertIn(r.ref_type, (ReferenceType.POC.value, ReferenceType.EXPLOIT.value))

    def test_count_by_type(self):
        refs = classify_references([
            {"url": "https://exploit-db.com/exploits/1"},
            {"url": "https://vendor.example.com/advisory"},
        ])
        counts = count_by_type(refs)
        self.assertGreaterEqual(sum(counts.values()), 2)


class ExploitStatusTest(unittest.TestCase):
    def test_kev_confirms(self):
        rec = fixtures.record(kev=True)
        self.assertEqual(rec.exploit_maturity, ExploitMaturity.CONFIRMED.value)
        self.assertIn("KEV", exploit_line_thai(rec))

    def test_from_references(self):
        refs = [Reference(url="https://exploit-db.com/1", ref_type=ReferenceType.EXPLOIT_DB.value)]
        self.assertEqual(from_references(refs), ExploitMaturity.CONFIRMED.value)

    def test_no_refs_unknown(self):
        rec = fixtures.record(refs=[], kev=False)
        self.assertEqual(rec.exploit_maturity, ExploitMaturity.UNKNOWN.value)

    def test_reference_count(self):
        rec = fixtures.record()  # has a PoC ref
        self.assertGreaterEqual(exploit_reference_count(rec), 1)


class TimelineTest(unittest.TestCase):
    def test_rebuild_and_render(self):
        rec = fixtures.record(kev=True)
        timeline.rebuild(rec)
        lines = timeline.render_thai(rec)
        self.assertTrue(any("เผยแพร่" in l for l in lines))
        self.assertTrue(any("KEV" in l for l in lines))


class VendorTest(unittest.TestCase):
    def test_canonical(self):
        self.assertEqual(canonical_vendor("microsoft"), "Microsoft")
        self.assertEqual(canonical_vendor("Red Hat"), "Red Hat")
        self.assertEqual(canonical_vendor("UnknownCo"), "UnknownCo")

    def test_match(self):
        self.assertTrue(match_vendor("Microsoft Corporation", ["microsoft"]))
        self.assertFalse(match_vendor("Apple", ["microsoft"]))


if __name__ == "__main__":
    unittest.main()
