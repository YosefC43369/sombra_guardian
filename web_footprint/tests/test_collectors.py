import unittest

from web_footprint.collectors.certs import CertificateCollector
from web_footprint.collectors.passive_dns import PassiveDNSCollector
from web_footprint.collectors.archive import ArchiveCollector
from web_footprint.collectors.wellknown import WellKnownCollector
from web_footprint.collectors.repos import RepositoryCollector


class TestCertParse(unittest.TestCase):
    def test_flatten_and_scope(self):
        rows = [
            {"name_value": "api.example.com\n*.example.com", "common_name": "example.com",
             "issuer_name": "C=US, O=Let's Encrypt", "serial_number": "AB",
             "not_before": "2024-01-01", "not_after": "2024-04-01"},
            {"name_value": "unrelated.other.com", "common_name": "other.com"},
        ]
        recs = CertificateCollector.parse(rows, "example.com")
        subs = {r["value"] for r in recs if r["type"] == "subdomain"}
        certs = [r for r in recs if r["type"] == "certificate"]
        self.assertIn("api.example.com", subs)
        self.assertNotIn("unrelated.other.com", subs)  # out-of-domain dropped
        self.assertEqual(len(certs), 1)
        self.assertIn("api.example.com", certs[0]["sans"])


class TestDNSParse(unittest.TestCase):
    def test_a_and_cname(self):
        payload = {"Answer": [
            {"type": 1, "data": "93.184.216.34"},
            {"type": 5, "data": "cdn.provider.net."},
            {"type": 2, "data": "ns1.provider.net."},
        ]}
        recs = PassiveDNSCollector.parse(payload, "example.com", "A")
        types = {r["type"] for r in recs}
        self.assertIn("dns_record", types)
        self.assertIn("ip", types)
        self.assertIn("related_host", types)
        ips = [r for r in recs if r["type"] == "ip"]
        self.assertEqual(ips[0]["value"], "93.184.216.34")

    def test_private_ip_skipped(self):
        payload = {"Answer": [{"type": 1, "data": "10.0.0.1"}]}
        recs = PassiveDNSCollector.parse(payload, "example.com", "A")
        self.assertFalse([r for r in recs if r["type"] == "ip"])


class TestArchiveParse(unittest.TestCase):
    def test_cdx_rows(self):
        rows = [
            ["timestamp", "original", "mimetype", "statuscode"],
            ["20180101000000", "http://old.example.com/", "text/html", "200"],
            ["20190101000000", "http://example.com/report.pdf", "application/pdf", "200"],
        ]
        recs = ArchiveCollector.parse(rows, "example.com")
        types = {r["type"] for r in recs}
        self.assertIn("historical_url", types)
        self.assertIn("subdomain", types)   # old.example.com
        self.assertIn("document", types)     # report.pdf
        doc = [r for r in recs if r["type"] == "document"][0]
        self.assertEqual(doc["ext"], "pdf")

    def test_empty_cdx(self):
        self.assertEqual(ArchiveCollector.parse([["header"]], "example.com"), [])


class TestWellKnownParse(unittest.TestCase):
    def test_page_title_and_headers(self):
        recs = WellKnownCollector.parse("/", "https://example.com/", 200,
                                        {"Server": "nginx"}, "<title>Hi</title>",
                                        "example.com")
        page = [r for r in recs if r["type"] == "page"][0]
        self.assertEqual(page["title"], "Hi")
        self.assertEqual(page["headers"]["server"], "nginx")

    def test_robots_and_sitemap(self):
        robots = "Sitemap: https://example.com/sitemap.xml\nDisallow: /admin"
        recs = WellKnownCollector.parse("/robots.txt", "https://example.com/robots.txt",
                                        200, {}, robots, "example.com")
        self.assertTrue(any(r["type"] == "sitemap_ref" for r in recs))
        sm = "<urlset><url><loc>https://example.com/a</loc></url></urlset>"
        recs2 = WellKnownCollector.parse("/sitemap.xml", "https://example.com/sitemap.xml",
                                         200, {}, sm, "example.com")
        self.assertTrue(any(r["type"] == "url" and "/a" in r["value"] for r in recs2))


class TestRepoParse(unittest.TestCase):
    def test_relevance_filter(self):
        payload = {"total_count": 2, "items": [
            {"full_name": "exampleinc/site", "description": "example.com website",
             "html_url": "https://github.com/exampleinc/site", "stargazers_count": 5,
             "language": "Python"},
            {"full_name": "someone/unrelated", "description": "nothing",
             "html_url": "https://github.com/someone/unrelated", "stargazers_count": 100},
        ]}
        recs = RepositoryCollector.parse(payload, "example.com", "example")
        by_name = {r["value"]: r for r in recs}
        self.assertTrue(by_name["exampleinc/site"]["relevant"])
        self.assertFalse(by_name["someone/unrelated"]["relevant"])
        # relevant repos are sorted first
        self.assertEqual(recs[0]["value"], "exampleinc/site")


if __name__ == "__main__":
    unittest.main()
