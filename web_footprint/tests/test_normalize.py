import unittest

from web_footprint import normalize as n


class TestNormalize(unittest.TestCase):
    def test_domain(self):
        self.assertEqual(n.normalize_domain("HTTPS://WWW.Example.com./x"), "www.example.com")
        self.assertEqual(n.normalize_domain("*.example.com"), "example.com")
        self.assertIsNone(n.normalize_domain("user:pass@example.com"))
        self.assertIsNone(n.normalize_domain("not a domain"))

    def test_url(self):
        self.assertEqual(n.normalize_url("HTTP://Example.com:80/"), "http://example.com/")
        self.assertEqual(n.normalize_url("example.com/path?q=1#frag"),
                         "http://example.com/path?q=1")
        self.assertEqual(n.normalize_url("https://a.example.com:443/x"),
                         "https://a.example.com/x")
        self.assertIsNone(n.normalize_url("ftp://example.com"))
        self.assertIsNone(n.normalize_url("https://user:pw@example.com"))

    def test_host_of_url(self):
        self.assertEqual(n.host_of_url("https://api.example.com/v1"), "api.example.com")
        self.assertIsNone(n.host_of_url("mailto:x@y.com"))

    def test_email(self):
        self.assertEqual(n.normalize_email("  Foo@Example.COM "), "foo@example.com")
        self.assertEqual(n.normalize_email("Name <a.b@x.co.uk>"), "a.b@x.co.uk")
        self.assertEqual(n.domain_of_email("a@sub.example.com"), "sub.example.com")
        self.assertIsNone(n.normalize_email("nope"))

    def test_username(self):
        self.assertEqual(n.normalize_username("@Alice_01"), "alice_01")
        self.assertIsNone(n.normalize_username("a b"))

    def test_registrable(self):
        self.assertEqual(n.registrable_domain("api.staging.example.co.uk"), "example.co.uk")
        self.assertEqual(n.registrable_domain("a.b.example.com"), "example.com")
        self.assertEqual(n.registrable_domain("example.com"), "example.com")
        self.assertEqual(n.registrable_domain("shop.example.com.au"), "example.com.au")

    def test_subdomain_of(self):
        self.assertTrue(n.is_subdomain_of("api.example.com", "example.com"))
        self.assertTrue(n.is_subdomain_of("example.com", "example.com"))
        self.assertFalse(n.is_subdomain_of("evil-example.com", "example.com"))
        self.assertFalse(n.is_subdomain_of("example.com.evil.com", "example.com"))

    def test_split_labels(self):
        labels, base = n.split_host_labels("api.dev.example.com")
        self.assertEqual(labels, ["api", "dev"])
        self.assertEqual(base, "example.com")
        labels, base = n.split_host_labels("example.com")
        self.assertEqual(labels, [])
        self.assertEqual(base, "example.com")

    def test_public_ip(self):
        self.assertTrue(n.is_public_ip("93.184.216.34"))
        self.assertFalse(n.is_public_ip("10.0.0.1"))
        self.assertFalse(n.is_public_ip("127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
