"""
test_osint_collector.py — tests for the OSINT collector pipeline and its new
passive sources (DNS-over-HTTPS, RDAP, site-tech, HIBP, Google-dork planner),
the risk model, the profile builder, and the case report / redaction.

No network: an in-memory fake HTTP client (matching AsyncHTTPClient's surface)
feeds canned responses. (python -m unittest test_osint_collector)
"""

import json
import asyncio
import unittest

from osint.utils.async_http import HTTPResult
from osint.sources.base import SourceStatus, Source, SourceResult
from osint.sources.dns_records import DnsRecordsSource
from osint.sources.rdap import RdapSource
from osint.sources.site_tech import SiteTechSource
from osint.sources.hibp import HibpSource
from osint.sources.google_dork import GoogleDorkSource, plan_dorks
from osint.orchestrator import Orchestrator
from osint import risk as risk_mod
from osint import profile as profile_mod
from osint import collector as collector_mod
from osint import case_report


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class FakeClient:
    """เลียนแบบ AsyncHTTPClient เท่าที่ source ใช้: get / get_json คืน HTTPResult
    โดยเรียก responder(method, url, params, headers) ที่เทสต์กำหนด"""

    def __init__(self, responder):
        self._responder = responder

    async def get(self, url, *, params=None, headers=None):
        return self._responder("GET", url, params or {}, headers or {})

    async def get_json(self, url, *, params=None, headers=None):
        r = await self.get(url, params=params, headers=headers)
        if r.ok:
            try:
                r.json()
            except Exception:
                return HTTPResult(ok=False, status=r.status, url=r.url,
                                  reason="invalid JSON")
        return r


def _ok(text, headers=None, url="http://x/"):
    return HTTPResult(ok=True, status=200, url=url, text=text,
                      headers=headers or {})


class DnsRecordsTest(unittest.TestCase):
    def test_parses_a_and_mx(self):
        def responder(method, url, params, headers):
            rtype = params.get("type")
            answers = {
                "A": [{"type": 1, "data": "1.2.3.4"}],
                "MX": [{"type": 15, "data": "10 mail.example.com."}],
                "NS": [{"type": 2, "data": "ns1.example.com."}],
            }.get(rtype, [])
            return _ok(json.dumps({"Answer": answers}))

        res = run(DnsRecordsSource().fetch(FakeClient(responder), "example.com"))
        self.assertEqual(res.status, SourceStatus.OK)
        values = {(r["type"], r["value"]) for r in res.records}
        self.assertIn(("ip", "1.2.3.4"), values)
        self.assertIn(("hostname", "mail.example.com"), values)
        self.assertIn(("hostname", "ns1.example.com"), values)


class RdapTest(unittest.TestCase):
    def test_flattens_registrar_events_ns(self):
        doc = {
            "status": ["client transfer prohibited"],
            "events": [
                {"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
            ],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
            }],
        }

        def responder(method, url, params, headers):
            return _ok(json.dumps(doc), url=url)

        res = run(RdapSource().fetch(FakeClient(responder), "example.com"))
        self.assertEqual(res.status, SourceStatus.OK)
        self.assertEqual(res.meta.get("registrar"), "Example Registrar")
        self.assertEqual(res.meta.get("registered"), "2010-01-01T00:00:00Z")
        self.assertIn("ns1.example.com", res.meta.get("nameservers", []))


class SiteTechTest(unittest.TestCase):
    def test_headers_tech_and_missing_security(self):
        html = ('<html><head><meta name="generator" content="WordPress 5.2">'
                '<script src="/js/jquery-2.1.4.min.js"></script></head></html>')

        def responder(method, url, params, headers):
            if url.endswith("/robots.txt"):
                return _ok("User-agent: *\nDisallow: /wp-admin/\n", url=url)
            return _ok(html, headers={"Server": "Apache/2.4.29",
                                      "X-Frame-Options": "DENY"},
                       url="https://example.com/")

        res = run(SiteTechSource().fetch(FakeClient(responder), "example.com"))
        self.assertEqual(res.status, SourceStatus.OK)
        techs = {r["value"] for r in res.records if r["type"] == "tech"}
        self.assertTrue(any("WordPress" in t for t in techs))
        self.assertTrue(any("Apache" in t for t in techs))
        self.assertIn("HSTS", res.meta["security_headers_missing"])
        self.assertIn("X-Frame-Options", res.meta["security_headers_present"])
        self.assertIn("/wp-admin/", res.meta.get("robots_disallow", []))

    def test_no_https_flag(self):
        def responder(method, url, params, headers):
            return _ok("<html></html>", url="http://example.com/")
        res = run(SiteTechSource().fetch(FakeClient(responder), "example.com"))
        self.assertFalse(res.meta["https"])


class HibpTest(unittest.TestCase):
    def test_domain_breaches(self):
        breaches = [{"Name": "Acme", "PwnCount": 1000, "BreachDate": "2019-01-01",
                     "DataClasses": ["Emails", "Passwords"], "IsVerified": True}]

        def responder(method, url, params, headers):
            return _ok(json.dumps(breaches), url=url)

        res = run(HibpSource().fetch(FakeClient(responder), "example.com"))
        self.assertEqual(res.status, SourceStatus.OK)
        self.assertEqual(res.meta["breach_count"], 1)
        self.assertEqual(res.records[0]["value"], "Acme")

    def test_email_needs_key(self):
        def responder(method, url, params, headers):
            return _ok("[]", url=url)
        res = run(HibpSource().fetch(FakeClient(responder), "a@b.com"))
        self.assertEqual(res.status, SourceStatus.AUTH_REQUIRED)


class GoogleDorkTest(unittest.TestCase):
    def test_plan_without_key(self):
        def responder(method, url, params, headers):
            return _ok("{}", url=url)
        res = run(GoogleDorkSource().fetch(FakeClient(responder), "example.com"))
        self.assertEqual(res.status, SourceStatus.AUTH_REQUIRED)
        self.assertTrue(any(r["type"] == "dork_query" for r in res.records))
        self.assertIn("site:example.com", plan_dorks("example.com"))


class RiskModelTest(unittest.TestCase):
    def test_missing_headers_lowers_security(self):
        meta = {"https": True,
                "security_headers_missing": ["HSTS", "CSP", "X-Frame-Options"],
                "security_headers_present": []}
        tech = [{"type": "tech", "product": "WordPress", "version": "4.9",
                 "value": "WordPress 4.9"}]
        out = risk_mod.assess(meta, tech, {"breach_count": 2})
        self.assertLess(out["score"], 85)
        self.assertIn(out["security_level"],
                      (risk_mod.LEVEL_LOW, risk_mod.LEVEL_MEDIUM, risk_mod.LEVEL_HIGH))
        codes = {r["code"] for r in out["reasons"]}
        self.assertIn("missing_header", codes)
        self.assertIn("outdated_software", codes)
        self.assertIn("breach_history", codes)

    def test_clean_site_high_security(self):
        meta = {"https": True, "security_headers_missing": [],
                "security_headers_present": list(risk_mod._HEADER_PENALTY.keys())}
        out = risk_mod.assess(meta, [], {})
        self.assertEqual(out["score"], 100)
        self.assertEqual(out["security_level"], risk_mod.LEVEL_VERY_HIGH)
        self.assertEqual(out["risk_level"], risk_mod.LEVEL_LOW)


# ---- an end-to-end style build_case test using fake sources via Orchestrator ----

class _FakeSource(Source):
    def __init__(self, name, records, meta=None):
        self.name = name
        self.kind = "domain"
        self._records = records
        self._meta = meta or {}

    async def fetch(self, client, target):
        return SourceResult(self.name, target, SourceStatus.OK,
                            records=self._records, meta=self._meta)


class BuildCaseTest(unittest.TestCase):
    def _intel(self):
        sources = [
            _FakeSource("dns_records", [
                {"type": "ip", "value": "1.2.3.4", "record": "A"},
                {"type": "hostname", "value": "ns1.example.com", "record": "NS"},
            ]),
            _FakeSource("site_tech", [
                {"type": "tech", "value": "WordPress 4.9", "product": "WordPress",
                 "version": "4.9"},
                {"type": "security_header", "value": "HSTS", "present": False},
            ], meta={"https": True, "security_headers_missing": ["HSTS"],
                     "security_headers_present": []}),
            _FakeSource("hibp", [{"type": "breach", "value": "Acme"}],
                        meta={"breach_count": 1}),
            _FakeSource("crtsh", [
                {"type": "subdomain", "value": "mail.example.com"},
            ]),
        ]
        orch = Orchestrator(sources)
        return run(orch.run("example.com", "domain", client=object()))

    def test_build_case_shape(self):
        intel = self._intel()
        case = collector_mod.build_case("example.com", "domain", intel, actor=7)
        self.assertTrue(case["case_id"].startswith("OSINT-"))
        self.assertEqual(case["target"], "example.com")
        self.assertEqual(case["collected_by"], 7)
        infra = case["profile"]["infrastructure"]
        self.assertIn("1.2.3.4", infra["ips"])
        self.assertIn("ns1.example.com", infra["nameservers"])
        self.assertIn("mail.example.com", infra["subdomains"])
        self.assertEqual(case["profile"]["exposure"]["breach_count"], 1)
        self.assertLess(case["assessment"]["score"], 100)

    def test_reports_render(self):
        intel = self._intel()
        case = collector_mod.build_case("example.com", "domain", intel)
        summary = case_report.group_summary(case)
        self.assertIn("example.com", summary)
        self.assertIn("Sha256", summary)
        # redaction: the group summary must not leak the raw subdomain
        self.assertNotIn("mail.example.com", summary)
        full = case_report.full_report(case)
        self.assertIn("mail.example.com", full)
        self.assertIn("WordPress", full)

    def test_detect_kind(self):
        self.assertEqual(collector_mod.detect_kind("example.com"), "domain")
        self.assertEqual(collector_mod.detect_kind("8.8.8.8"), "ip")
        self.assertIsNone(collector_mod.detect_kind("not a target"))


if __name__ == "__main__":
    unittest.main()
