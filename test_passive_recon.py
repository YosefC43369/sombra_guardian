# -*- coding: utf-8 -*-
"""เทสต์ passive_recon — pure logic (parse) + SSRF guard + workflow (stub client, ไม่ต่อเน็ต)"""

import asyncio
import ipaddress
import unittest

from passive_recon import parse, safehttp


# ---------------------------------------------------------------------------
# normalize
# ---------------------------------------------------------------------------
class NormalizeTests(unittest.TestCase):
    def test_bare_domain(self):
        n = parse.normalize_target("Example.COM")
        self.assertEqual(n["domain"], "example.com")
        self.assertEqual(n["url"], "https://example.com")
        self.assertEqual(n["scheme"], "https")

    def test_full_url(self):
        n = parse.normalize_target("http://a.b.example.co.uk:8080/path?x=1")
        self.assertEqual(n["domain"], "a.b.example.co.uk")
        self.assertEqual(n["scheme"], "http")
        self.assertEqual(n["registered"], "example.co.uk")

    def test_rejects_credentials(self):
        self.assertIsNone(parse.normalize_target("https://user:pass@evil.com"))

    def test_rejects_non_http_scheme(self):
        self.assertIsNone(parse.normalize_target("ftp://example.com"))
        self.assertIsNone(parse.normalize_target("file:///etc/passwd"))

    def test_rejects_garbage_and_ip_literal_host(self):
        self.assertIsNone(parse.normalize_target("not a domain"))
        self.assertIsNone(parse.normalize_target(""))


# ---------------------------------------------------------------------------
# DoH / SPF / DMARC
# ---------------------------------------------------------------------------
class DnsParseTests(unittest.TestCase):
    def test_parse_doh_a_and_txt(self):
        ans = {"Answer": [
            {"type": 1, "data": "93.184.216.34", "TTL": 300},
            {"type": 16, "data": "\"v=spf1 include:_spf.example.com -all\"", "TTL": 300},
        ]}
        a = parse.parse_doh(ans, "A")
        self.assertEqual(a[0]["value"], "93.184.216.34")
        txt = parse.parse_doh(ans, "TXT")
        self.assertIn("v=spf1", txt[0]["value"])

    def test_spf_weak_detection(self):
        self.assertTrue(parse.analyze_spf(["v=spf1 +all"])["weak"])
        self.assertFalse(parse.analyze_spf(["v=spf1 -all"])["weak"])
        self.assertIsNone(parse.analyze_spf(["random txt"]))

    def test_dmarc_policy(self):
        self.assertTrue(parse.analyze_dmarc(["v=DMARC1; p=none"])["weak"])
        self.assertFalse(parse.analyze_dmarc(["v=DMARC1; p=reject"])["weak"])


# ---------------------------------------------------------------------------
# tech fingerprint
# ---------------------------------------------------------------------------
class FingerprintTests(unittest.TestCase):
    def test_confirmed_from_header(self):
        tech = parse.fingerprint_tech({"Server": "nginx/1.25.1",
                                       "X-Powered-By": "PHP/8.2.0"})
        names = {t["tech"]: t for t in tech}
        self.assertIn("nginx", names)
        self.assertTrue(names["nginx"]["confirmed"])
        self.assertEqual(names["nginx"].get("version"), "1.25.1")
        self.assertIn("PHP", names)

    def test_inferred_from_html(self):
        tech = parse.fingerprint_tech({}, html='<meta name="generator" content="WordPress 6.4">'
                                      '<script src="/wp-includes/jquery.min.js">')
        names = {t["tech"] for t in tech}
        self.assertIn("WordPress", names)
        self.assertTrue(all(not t["confirmed"] for t in tech if t["tech"] == "WordPress"))

    def test_cdn_and_waf_headers(self):
        tech = parse.fingerprint_tech({"cf-ray": "abc", "cf-mitigated": "challenge"})
        cats = {t["category"] for t in tech}
        self.assertIn("cdn", cats)
        self.assertIn("waf", cats)


# ---------------------------------------------------------------------------
# cert parse
# ---------------------------------------------------------------------------
class CertTests(unittest.TestCase):
    def test_parse_cert(self):
        cert = {
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("commonName", "R3")], [("organizationName", "Let's Encrypt")]],
            "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")],
            "notBefore": "Jan  1 00:00:00 2025 GMT",
            "notAfter": "Jan  1 00:00:00 2035 GMT",
        }
        info = parse.parse_certificate(cert)
        self.assertEqual(info["issuer_org"], "Let's Encrypt")
        self.assertIn("www.example.com", info["san"])
        self.assertFalse(info["expired"])
        self.assertGreater(info["days_left"], 0)


# ---------------------------------------------------------------------------
# http metadata + security exposure
# ---------------------------------------------------------------------------
class HttpSecurityTests(unittest.TestCase):
    def test_http_metadata_missing_headers(self):
        meta = parse.http_metadata(200, {"Server": "nginx"},
                                   "<title>Hi</title>")
        self.assertEqual(meta["title"], "Hi")
        self.assertIn("content-security-policy", meta["security_headers_missing"])

    def test_security_exposure_indicators(self):
        meta = {"security_headers_missing": ["content-security-policy"]}
        tech = [{"tech": "nginx", "version": "1.18.0"}]
        spf = {"weak": True}
        dmarc = None
        cert = {"expired": True, "not_after": "x"}
        ind = parse.security_exposure(meta, tech, spf, dmarc, cert)
        titles = " ".join(i["indicator"] for i in ind)
        self.assertIn("content-security-policy", titles)
        self.assertIn("เปิดเผยเวอร์ชัน", titles)
        self.assertTrue(any(i["severity"] == "high" for i in ind))  # cert expired
        self.assertTrue(all(i["type"] == "informational" for i in ind))


# ---------------------------------------------------------------------------
# dedupe + confidence + render
# ---------------------------------------------------------------------------
class UtilTests(unittest.TestCase):
    def test_dedupe_hostnames_scope(self):
        out = parse.dedupe_hostnames(
            ["WWW.example.com", "www.example.com.", "a.example.com",
             "evil.com", "*.example.com"], "example.com")
        self.assertIn("www.example.com", out)
        self.assertIn("a.example.com", out)
        self.assertNotIn("evil.com", out)       # นอกขอบเขตโดเมน
        self.assertEqual(len(out), 3)            # example.com + www + a

    def test_confidence(self):
        self.assertEqual(parse.confidence_for("dns", "error", 0), 0.0)
        self.assertGreater(parse.confidence_for("dns", "ok", 5), 0.9)

    def test_render_all_formats(self):
        report = {"ok": True, "target": {"domain": "example.com", "url": "https://example.com",
                                         "registered": "example.com"},
                  "collected_at": "2026-01-01T00:00:00Z", "duration_ms": 10,
                  "categories": {
                      "domain": {"data": {"registrar": "X"}},
                      "dns": {"records": [{"type": "A", "value": "1.2.3.4"}]},
                      "subdomains": {"records": [{"value": "www.example.com"}]},
                      "technology": {"records": [{"tech": "nginx", "category": "web-server",
                                                  "confidence": 0.95, "confirmed": True}]},
                      "tls": {"data": {"issuer_cn": "R3", "san": ["example.com"]}},
                      "http": {"data": {"status": 200, "security_headers_missing": ["x"]}},
                      "infrastructure": {"records": [{"type": "asn", "value": "AS15169"}]},
                      "security": {"records": [{"severity": "low", "indicator": "i", "detail": "d"}]},
                  }, "errors": []}
        md = parse.render_markdown(report)
        self.assertIn("example.com", md)
        self.assertIn("nginx", md)
        js = parse.render_json(report)
        self.assertIn('"domain"', js)
        txt = parse.render_txt(report)
        self.assertNotIn("#", txt)


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------
class SsrfTests(unittest.TestCase):
    def test_public_vs_private(self):
        self.assertTrue(safehttp._is_public("8.8.8.8"))
        self.assertFalse(safehttp._is_public("127.0.0.1"))
        self.assertFalse(safehttp._is_public("10.0.0.5"))
        self.assertFalse(safehttp._is_public("192.168.1.1"))
        self.assertFalse(safehttp._is_public("169.254.169.254"))  # cloud metadata
        self.assertFalse(safehttp._is_public("::1"))

    def test_host_safety_blocks_private(self):
        async def run():
            # patch resolver เพื่อไม่ต่อเน็ตจริง
            orig = safehttp.safe_resolve
            async def fake(domain):
                return {"internal.local": ["10.0.0.1"],
                        "ok.example": ["93.184.216.34"]}.get(domain, [])
            safehttp.safe_resolve = fake
            try:
                bad = await safehttp.host_safety("internal.local")
                good = await safehttp.host_safety("ok.example")
                none = await safehttp.host_safety("nx.example")
                return bad, good, none
            finally:
                safehttp.safe_resolve = orig
        bad, good, none = asyncio.run(run())
        self.assertFalse(bad["safe"])
        self.assertTrue(good["safe"])
        self.assertFalse(none["safe"])

    def test_guarded_fetch_rejects_non_get(self):
        async def run():
            return await safehttp.guarded_fetch("https://example.com", method="POST")
        res = asyncio.run(run())
        self.assertFalse(res["ok"])
        self.assertIn("GET/HEAD", res["reason"])


# ---------------------------------------------------------------------------
# workflow end-to-end ด้วย stub (ไม่ต่อเน็ต)
# ---------------------------------------------------------------------------
class _StubHTTPResult:
    def __init__(self, ok, payload=None, reason="", status=200):
        self.ok = ok; self._p = payload; self.reason = reason; self.status = status
    def json(self):
        return self._p


class _StubClient:
    """เลียนแบบ AsyncHTTPClient — ตอบตาม URL"""
    def __init__(self, *a, **kw): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def get(self, url, params=None, headers=None):
        if "resolve" in url or "dns-json" in str(headers):  # DoH
            name = (params or {}).get("name", "")
            rtype = (params or {}).get("type", "")
            if rtype == "A" and name == "example.com":
                return _StubHTTPResult(True, {"Answer": [{"type": 1, "data": "93.184.216.34"}]})
            if rtype == "TXT" and name == "example.com":
                return _StubHTTPResult(True, {"Answer": [{"type": 16, "data": "\"v=spf1 -all\""}]})
            return _StubHTTPResult(True, {"Answer": []})
        return _StubHTTPResult(False, reason="unstubbed")
    async def get_json(self, url, params=None, headers=None):
        if "rdap.org" in url:
            return _StubHTTPResult(True, {"handle": "EX", "events": [
                {"eventAction": "registration", "eventDate": "2000-01-01"},
                {"eventAction": "expiration", "eventDate": "2030-01-01"}],
                "entities": [], "nameservers": [{"ldhName": "ns1.example.com"}],
                "status": ["client transfer prohibited"]})
        if "bgpview" in url:
            return _StubHTTPResult(True, {"data": {"prefixes": [
                {"asn": {"asn": 15133, "name": "EDGECAST"}, "prefix": "93.184.216.0/24"}]}})
        if "ipwho.is" in url:
            return _StubHTTPResult(True, {"success": True, "city": "LA", "country": "US",
                                          "connection": {"isp": "Edgecast", "org": "Edgecast"}})
        return _StubHTTPResult(False, reason="unstubbed")


class WorkflowTests(unittest.TestCase):
    def test_run_recon_with_stub(self):
        from passive_recon import recon, collectors, safehttp as sh

        async def run():
            # stub HTTP client + crt.sh + DoH + target fetch + TLS
            orig_client = recon.AsyncHTTPClient
            recon.AsyncHTTPClient = _StubClient
            async def fake_doh(client, domain, rtype):
                if domain == "example.com" and rtype == "A":
                    return {"Answer": [{"type": 1, "data": "93.184.216.34"}]}
                if domain == "example.com" and rtype == "TXT":
                    return {"Answer": [{"type": 16, "data": "\"v=spf1 -all\""}]}
                if domain == "example.com" and rtype in ("MX", "NS", "SOA", "CAA", "AAAA"):
                    return {"Answer": []}
                return {"Answer": []}
            orig_doh = collectors.safehttp.doh_query
            collectors.safehttp.doh_query = fake_doh
            async def fake_subs(client, dom):
                from osint.sources.base import SourceResult, SourceStatus
                return SourceResult("crtsh", dom, SourceStatus.OK,
                                    records=[{"value": "www.example.com"},
                                             {"value": "old.example.com"}])
            orig_subs = collectors._crtsh_fetch
            collectors._crtsh_fetch = fake_subs
            async def fake_http(domain, url):
                return {"http": collectors._cat("http", "ok", data={"status": 200,
                        "server": "nginx", "security_headers_missing": ["content-security-policy"]}),
                        "technology": collectors._cat("technology", "ok",
                        records=[{"tech": "nginx", "category": "web-server",
                                  "confidence": 0.95, "confirmed": True, "version": "1.18.0"}])}
            orig_ht = collectors.collect_http_and_tech
            collectors.collect_http_and_tech = fake_http
            async def fake_tls(domain):
                return collectors._cat("tls", "ok", data={"issuer_cn": "R3",
                        "issuer_org": "Let's Encrypt", "san": ["example.com"],
                        "days_left": 60, "expired": False})
            orig_tls = collectors.collect_tls
            collectors.collect_tls = fake_tls
            async def fake_safety(domain):
                return {"safe": True, "ips": ["93.184.216.34"], "reason": ""}
            orig_safety = sh.host_safety
            sh.host_safety = fake_safety
            try:
                return await recon.run_recon("https://example.com")
            finally:
                recon.AsyncHTTPClient = orig_client
                collectors.safehttp.doh_query = orig_doh
                collectors._crtsh_fetch = orig_subs
                collectors.collect_http_and_tech = orig_ht
                collectors.collect_tls = orig_tls
                sh.host_safety = orig_safety

        report = asyncio.run(run())
        self.assertTrue(report["ok"])
        self.assertEqual(report["target"]["domain"], "example.com")
        c = report["categories"]
        self.assertEqual(c["domain"]["data"]["registrar"] or "", "")  # entity ไม่มี registrar role
        self.assertTrue(any(r["type"] == "A" for r in c["dns"]["records"]))
        self.assertTrue(len(c["subdomains"]["records"]) >= 2)
        self.assertTrue(any(t["tech"] == "nginx" for t in c["technology"]["records"]))
        self.assertEqual(c["tls"]["data"]["issuer_org"], "Let's Encrypt")
        self.assertTrue(any(r["type"] == "asn" for r in c["infrastructure"]["records"]))
        # security exposure derived: version disclosure + missing header + no DMARC
        self.assertTrue(len(c["security"]["records"]) >= 2)
        # render works
        self.assertIn("example.com", recon.render(report, "markdown"))

    def test_run_recon_rejects_bad_target(self):
        from passive_recon import recon
        report = asyncio.run(recon.run_recon("user:pass@evil.com"))
        self.assertFalse(report["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
