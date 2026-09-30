"""Tests for the pure utils — ids, versioning, urls, timeparse, text."""

import unittest

from cve_tracker.utils import (
    normalize_cve_id, is_valid_cve_id, cve_year, cve_sort_key,
    normalize_ghsa_id, normalize_url, url_host, is_safe_public_url,
    registrable_domain, parse_version, compare_versions, version_in_range,
    thai_date, humanize_ago, truncate, strip_html, escape_html,
    escape_markdown_v2, safe_json_loads, slugify, dedupe_preserve_order,
)


class IdsTest(unittest.TestCase):
    def test_valid_and_year(self):
        self.assertTrue(is_valid_cve_id("CVE-2026-93740"))
        self.assertEqual(cve_year("CVE-2026-93740"), 2026)
        self.assertIsNone(cve_year("garbage"))

    def test_sort_key(self):
        self.assertGreater(cve_sort_key("CVE-2026-0002"), cve_sort_key("CVE-2026-0001"))
        self.assertGreater(cve_sort_key("CVE-2026-0001"), cve_sort_key("CVE-2025-9999"))

    def test_ghsa(self):
        self.assertEqual(normalize_ghsa_id("ghsa-2345-6789-cfgh"), "GHSA-2345-6789-CFGH")
        self.assertIsNone(normalize_ghsa_id("not-ghsa"))


class VersioningTest(unittest.TestCase):
    def test_compare(self):
        self.assertEqual(compare_versions("1.2.3", "1.2.10"), -1)
        self.assertEqual(compare_versions("2.0", "2.0.0"), 0)
        self.assertEqual(compare_versions("1.2.3", "1.2.3-rc1"), 1)  # rc < release
        self.assertIsNone(compare_versions("abc", "1.0"))

    def test_range(self):
        self.assertTrue(version_in_range("1.5", introduced="1.0", fixed="2.0"))
        self.assertFalse(version_in_range("2.5", introduced="1.0", fixed="2.0"))
        self.assertFalse(version_in_range("0.9", introduced="1.0", fixed="2.0"))
        self.assertIsNone(version_in_range("1.5"))  # no bounds → cannot determine

    def test_parse_none(self):
        self.assertIsNone(parse_version("*"))
        self.assertIsNone(parse_version(""))


class UrlsTest(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(
            normalize_url("HTTPS://Example.com:443/a?utm_source=x&id=1#frag"),
            "https://example.com/a?id=1")
        self.assertIsNone(normalize_url("ftp://x/y"))

    def test_host_and_domain(self):
        self.assertEqual(url_host("https://a.b.example.com/x"), "a.b.example.com")
        self.assertEqual(registrable_domain("https://a.b.example.com/x"), "example.com")
        self.assertEqual(registrable_domain("https://foo.co.uk/x"), "foo.co.uk")

    def test_ssrf_guard(self):
        self.assertFalse(is_safe_public_url("http://127.0.0.1/x"))
        self.assertFalse(is_safe_public_url("http://localhost/x"))
        self.assertFalse(is_safe_public_url("http://10.0.0.1/x"))
        self.assertFalse(is_safe_public_url("http://169.254.1.1/x"))
        self.assertTrue(is_safe_public_url("https://nvd.nist.gov/x"))


class TimeTest(unittest.TestCase):
    def test_thai_date(self):
        # 2026-09-18 UTC → 18 กันยายน 2569 (พ.ศ.)
        self.assertEqual(thai_date(1758153600 + 365 * 86400).split()[-1], "2569")

    def test_humanize(self):
        import time
        now = int(time.time())
        self.assertEqual(humanize_ago(now - 10, now=now), "เมื่อสักครู่")
        self.assertIn("นาที", humanize_ago(now - 300, now=now))
        self.assertIn("วัน", humanize_ago(now - 3 * 86400, now=now))


class TextTest(unittest.TestCase):
    def test_truncate_word_boundary(self):
        out = truncate("the quick brown fox jumps", 15)
        self.assertLessEqual(len(out), 15)
        self.assertTrue(out.endswith("…"))

    def test_strip_html(self):
        self.assertEqual(strip_html("<p>hello <b>world</b></p>"), "hello world")

    def test_escape_html(self):
        self.assertEqual(escape_html("<a> & <b>"), "&lt;a&gt; &amp; &lt;b&gt;")

    def test_escape_mdv2(self):
        self.assertEqual(escape_markdown_v2("a_b*c"), "a\\_b\\*c")

    def test_safe_json(self):
        self.assertEqual(safe_json_loads('```json\n{"a":1}\n```'), {"a": 1})
        self.assertEqual(safe_json_loads("prefix {\"a\": 2} suffix"), {"a": 2})
        self.assertIsNone(safe_json_loads("not json", default=None))

    def test_slugify_and_dedupe(self):
        self.assertEqual(slugify("Apache HTTP Server!"), "apache-http-server")
        self.assertEqual(dedupe_preserve_order([1, 2, 2, 3, 1]), [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
