import unittest

from web_footprint.analysis import extract


class TestExtract(unittest.TestCase):
    def test_urls_and_hosts(self):
        text = "visit https://api.example.com/v1 and http://blog.example.com"
        recs = extract.extract(text, base_domain="example.com")
        urls = {r["value"] for r in recs if r["type"] == "url"}
        self.assertIn("https://api.example.com/v1", urls)
        subs = {r["value"] for r in recs if r["type"] == "subdomain"}
        self.assertIn("api.example.com", subs)

    def test_emails_and_ips(self):
        text = "mail security@example.com ip 93.184.216.34 private 10.0.0.1"
        recs = extract.extract(text, base_domain="example.com")
        emails = {r["value"] for r in recs if r["type"] == "email"}
        ips = {r["value"] for r in recs if r["type"] == "ip"}
        self.assertIn("security@example.com", emails)
        self.assertIn("93.184.216.34", ips)
        self.assertNotIn("10.0.0.1", ips)  # private IPs excluded

    def test_cloud_and_api_and_package(self):
        text = ("storage assets.s3.amazonaws.com and https://x.blob.core.windows.net "
                "docs at /api/v1/users swagger.json  pip install requests")
        recs = extract.extract(text, base_domain="example.com")
        clouds = {r["provider"] for r in recs if r["type"] == "cloud_reference"}
        apis = {r["kind"] for r in recs if r["type"] == "api_reference"}
        pkgs = {(r["ecosystem"], r["value"]) for r in recs if r["type"] == "package_reference"}
        self.assertIn("aws-s3", clouds)
        self.assertIn("azure-blob", clouds)
        self.assertTrue({"openapi", "rest-endpoint"} & apis)
        self.assertIn(("pypi", "requests"), pkgs)

    def test_internal_naming_signal(self):
        recs = extract.extract("host db.internal and vpn.corp seen",
                               base_domain="example.com")
        internal = {r["value"] for r in recs if r["type"] == "internal_naming_signal"}
        self.assertTrue(any(".internal" in v or ".corp" in v for v in internal))

    def test_secret_redaction_never_leaks(self):
        raw = "AKIAIOSFODNN7EXAMPLE"
        text = f"aws_key = {raw} and token: xoxb-1234567890-abcdefghij"
        recs = extract.extract(text)
        secrets = [r for r in recs if r["type"] == "secret_signal"]
        self.assertTrue(secrets)
        for s in secrets:
            # The raw secret must never appear in any field of the record.
            self.assertNotIn(raw, str(s))
            self.assertIn("*", s["redacted"])
            self.assertEqual(s["handling"], "redacted; not validated")

    def test_redact_secrets_direct(self):
        out = extract.redact_secrets("-----BEGIN RSA PRIVATE KEY-----\nMIIB...")
        self.assertTrue(any(s["kind"] == "private-key-block" for s in out))


if __name__ == "__main__":
    unittest.main()
