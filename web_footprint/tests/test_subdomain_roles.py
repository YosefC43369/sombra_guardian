import unittest

from web_footprint.analysis import subdomain_roles as sr


class TestSubdomainRoles(unittest.TestCase):
    def test_classify_label(self):
        self.assertEqual(sr.classify_label("api"), "api")
        self.assertEqual(sr.classify_label("www"), "web")
        self.assertEqual(sr.classify_label("admin"), "admin")
        self.assertIsNone(sr.classify_label("randomlabel"))

    def test_numbered_variants(self):
        self.assertEqual(sr.classify_label("api-2"), "api")
        self.assertEqual(sr.classify_label("web01"), "web")
        self.assertEqual(sr.classify_label("staging-eu"), "staging")

    def test_classify_host_most_specific_first(self):
        info = sr.classify_host("api.dev.example.com")
        self.assertEqual(info["role"], "api")     # leftmost recognised wins
        self.assertEqual(info["matched_label"], "api")
        self.assertEqual(info["base_domain"], "example.com")

    def test_sensitive_flag(self):
        self.assertTrue(sr.classify_host("admin.example.com")["sensitive"])
        self.assertTrue(sr.is_sensitive_role("vpn"))
        self.assertFalse(sr.classify_host("www.example.com")["sensitive"])

    def test_apex_has_no_role(self):
        info = sr.classify_host("example.com")
        self.assertEqual(info["role"], "")
        self.assertEqual(info["labels"], [])


if __name__ == "__main__":
    unittest.main()
