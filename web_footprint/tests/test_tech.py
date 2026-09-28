import unittest

from web_footprint.analysis import tech


class TestTechFingerprint(unittest.TestCase):
    def test_header_and_version(self):
        headers = {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"}
        found = {t["name"]: t for t in tech.fingerprint(headers, "", "")}
        self.assertIn("nginx", found)
        self.assertEqual(found["nginx"]["version"], "1.18.0")
        self.assertIn("PHP", found)
        self.assertEqual(found["PHP"]["version"], "7.4.3")

    def test_body_signatures(self):
        body = ('<meta name="generator" content="WordPress 6.2">'
                '<script src="/wp-content/x.js"></script>'
                '<script src="https://cdn/jquery-3.6.0.min.js"></script>')
        names = {t["name"] for t in tech.fingerprint({}, body, "")}
        self.assertIn("WordPress", names)
        self.assertIn("jQuery", names)

    def test_cookie_signatures(self):
        headers = {"Set-Cookie": "PHPSESSID=abc; Path=/"}
        names = {t["name"] for t in tech.fingerprint(headers, "", "")}
        self.assertIn("PHP", names)

    def test_versions_filter(self):
        headers = {"Server": "nginx/1.18.0"}
        techs = tech.fingerprint(headers, "", "")
        versions = tech.technology_versions(techs)
        self.assertTrue(any(v["technology"] == "nginx" and v["version"] == "1.18.0"
                            for v in versions))

    def test_cdn_detection(self):
        names = {t["name"] for t in tech.fingerprint({"CF-RAY": "abc"}, "", "")}
        self.assertIn("Cloudflare", names)

    def test_empty(self):
        self.assertEqual(tech.fingerprint({}, "", ""), [])


if __name__ == "__main__":
    unittest.main()
