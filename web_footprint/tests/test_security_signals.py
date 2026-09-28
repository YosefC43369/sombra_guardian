import unittest

from web_footprint.analysis import security_signals as ss


class TestSecuritySignals(unittest.TestCase):
    def test_parse_security_txt(self):
        text = ("Contact: mailto:security@example.com\n"
                "Expires: 2025-12-31T23:59:59Z\n"
                "Policy: https://example.com/policy\n# comment\n")
        parsed = ss.parse_security_txt(text, "https://example.com/.well-known/security.txt")
        self.assertTrue(parsed["present"])
        self.assertEqual(parsed["contact"], ["mailto:security@example.com"])
        self.assertEqual(parsed["expires"], "2025-12-31T23:59:59Z")
        self.assertEqual(parsed["policy"], ["https://example.com/policy"])

    def test_analyze_headers_presence(self):
        recs = ss.analyze_headers({"Strict-Transport-Security": "max-age=1",
                                   "Content-Security-Policy": "default-src 'self'"},
                                  "https://example.com/")
        by_label = {r["value"]: r for r in recs if r["type"] == "security_header"}
        self.assertTrue(by_label["HSTS"]["present"])
        self.assertTrue(by_label["CSP"]["present"])
        self.assertFalse(by_label["X-Frame-Options"]["present"])
        transport = [r for r in recs if r["type"] == "transport"][0]
        self.assertTrue(transport["present"])

    def test_detect_bug_bounty(self):
        recs = ss.detect_bug_bounty(["see https://hackerone.com/exampleinc for details",
                                     "/security"])
        providers = {r["provider"] for r in recs}
        self.assertIn("hackerone", providers)
        self.assertIn("self-hosted", providers)
        for r in recs:
            self.assertTrue(r.get("note"))  # every record carries a clarifying note

    def test_status_page(self):
        recs = ss.detect_status_page("status.example.com", [])
        self.assertTrue(any(r["type"] == "status_page" for r in recs))
        recs2 = ss.detect_status_page("www.example.com",
                                      ["hosted at exampleinc.statuspage.io"])
        self.assertTrue(any("statuspage.io" in r["value"] for r in recs2))


if __name__ == "__main__":
    unittest.main()
