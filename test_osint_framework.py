"""
test_osint_framework.py — tests for the osint/ framework foundation (async HTTP
backbone, validators, and the crt.sh source). No network: the HTTP layer is
exercised with in-memory fakes.

Standalone unittest, same convention as the other top-level suites
(python -m unittest test_osint_framework).
"""

import time
import asyncio
import unittest

from osint.utils.async_http import AsyncHTTPClient, RateLimiter, HTTPResult
from osint.utils import validators
from osint.sources.base import SourceStatus
from osint.sources.crtsh import CrtShSource


class ValidatorsTest(unittest.TestCase):
    def test_domain_normalization(self):
        self.assertEqual(validators.normalize_domain("https://Sub.Example.COM/path?x=1"),
                         "sub.example.com")
        self.assertEqual(validators.normalize_domain("*.example.com"), "example.com")
        self.assertEqual(validators.normalize_domain("example.com."), "example.com")
        self.assertEqual(validators.normalize_domain("example.com:8443"), "example.com")

    def test_domain_rejects_junk_and_credentials(self):
        self.assertIsNone(validators.normalize_domain("not a domain"))
        self.assertIsNone(validators.normalize_domain(""))
        self.assertIsNone(validators.normalize_domain("user:pass@example.com"))
        self.assertIsNone(validators.normalize_domain("localhost"))   # single label

    def test_ip_validation_and_public_check(self):
        self.assertTrue(validators.is_valid_ip("8.8.8.8"))
        self.assertEqual(validators.normalize_ip("2001:4860:4860::8888"),
                         "2001:4860:4860::8888")
        self.assertFalse(validators.is_valid_ip("999.1.1.1"))
        # SSRF guard: private/loopback/link-local are not "public".
        self.assertTrue(validators.is_public_ip("8.8.8.8"))
        self.assertFalse(validators.is_public_ip("127.0.0.1"))
        self.assertFalse(validators.is_public_ip("10.0.0.5"))
        self.assertFalse(validators.is_public_ip("169.254.1.1"))

    def test_asn_normalization(self):
        self.assertEqual(validators.normalize_asn("AS15169"), 15169)
        self.assertEqual(validators.normalize_asn("as15169"), 15169)
        self.assertEqual(validators.normalize_asn("15169"), 15169)
        self.assertIsNone(validators.normalize_asn("0"))
        self.assertIsNone(validators.normalize_asn("nope"))


class RateLimiterTest(unittest.IsolatedAsyncioTestCase):
    async def test_rate_limiter_throttles(self):
        # burst=1, rate=20/s -> after the first immediate token, each subsequent
        # acquire waits ~1/20س = 50ms. 3 acquires => at least ~100ms total.
        limiter = RateLimiter(rate=20, burst=1)
        start = time.monotonic()
        for _ in range(3):
            await limiter.acquire()
        elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 0.08)

    async def test_burst_allows_immediate(self):
        limiter = RateLimiter(rate=1, burst=5)
        start = time.monotonic()
        for _ in range(5):
            await limiter.acquire()
        # 5 tokens available immediately -> effectively no wait.
        self.assertLess(time.monotonic() - start, 0.2)


class _FakeResponse:
    def __init__(self, status_code, text="", headers=None, url="http://x"):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _FakeHTTPX:
    """Stands in for httpx.AsyncClient: returns queued responses or raises
    queued exceptions, in order, recording how many times it was called."""
    def __init__(self, script):
        self._script = list(script)
        self.calls = 0

    async def request(self, method, url, params=None, headers=None):
        self.calls += 1
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    async def aclose(self):
        pass


class AsyncHTTPClientTest(unittest.IsolatedAsyncioTestCase):
    def _client(self, script):
        c = AsyncHTTPClient(rate=1000, max_retries=3,
                            backoff_base=0.001, backoff_cap=0.01)
        c._client = _FakeHTTPX(script)
        return c

    async def test_success_first_try(self):
        c = self._client([_FakeResponse(200, '{"a":1}')])
        r = await c.get_json("https://api.example.com/x")
        self.assertTrue(r.ok)
        self.assertEqual(r.json(), {"a": 1})
        self.assertEqual(r.attempts, 1)

    async def test_retries_on_500_then_succeeds(self):
        c = self._client([_FakeResponse(500), _FakeResponse(200, "ok")])
        r = await c.get("https://api.example.com/x")
        self.assertTrue(r.ok)
        self.assertEqual(r.attempts, 2)
        self.assertEqual(c._client.calls, 2)

    async def test_retries_on_transport_error_then_succeeds(self):
        c = self._client([ConnectionError("boom"), _FakeResponse(200, "ok")])
        r = await c.get("https://api.example.com/x")
        self.assertTrue(r.ok)
        self.assertEqual(r.attempts, 2)

    async def test_gives_up_after_max_retries(self):
        c = self._client([_FakeResponse(503)] * 4)   # max_retries=3 -> 4 attempts
        r = await c.get("https://api.example.com/x")
        self.assertFalse(r.ok)
        self.assertEqual(r.status, 503)
        self.assertEqual(r.attempts, 4)

    async def test_non_retryable_4xx_not_retried(self):
        c = self._client([_FakeResponse(404, "nope")])
        r = await c.get("https://api.example.com/x")
        self.assertFalse(r.ok)
        self.assertEqual(r.status, 404)
        self.assertEqual(r.attempts, 1)

    async def test_invalid_json_becomes_failure(self):
        c = self._client([_FakeResponse(200, "not json")])
        r = await c.get_json("https://api.example.com/x")
        self.assertFalse(r.ok)
        self.assertIn("invalid JSON", r.reason)


class _FakeClientReturning:
    """Minimal client exposing get_json, for testing sources without HTTP."""
    def __init__(self, result: HTTPResult):
        self._result = result

    async def get_json(self, url, params=None, headers=None):
        return self._result

    async def get(self, url, params=None, headers=None):
        return self._result


class CrtShSourceTest(unittest.IsolatedAsyncioTestCase):
    async def test_parses_and_dedupes_subdomains(self):
        body = (
            '[{"name_value": "www.example.com\\n*.example.com"},'
            ' {"name_value": "api.example.com"},'
            ' {"name_value": "www.example.com"},'
            ' {"name_value": "unrelated.other.com"},'
            ' {"name_value": "mail.example.com,shop.example.com"}]'
        )
        client = _FakeClientReturning(HTTPResult(ok=True, status=200, text=body))
        result = await CrtShSource().run(client, "example.com")
        self.assertEqual(result.status, SourceStatus.OK)
        values = sorted(r["value"] for r in result.records)
        self.assertEqual(values, ["api.example.com", "example.com",
                                  "mail.example.com", "shop.example.com",
                                  "www.example.com"])
        # unrelated.other.com must be excluded; wildcard collapses to base.
        self.assertNotIn("unrelated.other.com", values)

    async def test_invalid_domain_rejected_without_http(self):
        client = _FakeClientReturning(HTTPResult(ok=False, reason="should not be called"))
        result = await CrtShSource().run(client, "not a domain")
        self.assertEqual(result.status, SourceStatus.INVALID_TARGET)

    async def test_rate_limited_surfaced(self):
        client = _FakeClientReturning(HTTPResult(ok=False, status=429, reason="HTTP 429"))
        result = await CrtShSource().run(client, "example.com")
        self.assertEqual(result.status, SourceStatus.RATE_LIMITED)

    async def test_empty_when_no_certs(self):
        client = _FakeClientReturning(HTTPResult(ok=True, status=200, text="[]"))
        result = await CrtShSource().run(client, "example.com")
        self.assertEqual(result.status, SourceStatus.EMPTY)


class _RoutingClient:
    """Fake client that returns a canned HTTPResult per URL substring."""
    def __init__(self, routes: dict):
        self._routes = routes            # substring -> HTTPResult
        self.requested = []

    def _match(self, url):
        for frag, result in self._routes.items():
            if frag in url:
                return result
        return HTTPResult(ok=False, status=404, reason="no route")

    async def get_json(self, url, params=None, headers=None):
        self.requested.append(url)
        return self._match(url)

    async def get(self, url, params=None, headers=None):
        self.requested.append(url)
        return self._match(url)


class _FakeSource:
    """Minimal Source-like object for orchestrator tests."""
    def __init__(self, name, kind, records, status=SourceStatus.OK, delay=0.0):
        self.name = name
        self.kind = kind
        self._records = records
        self._status = status
        self._delay = delay

    async def run(self, client, target):
        from osint.sources.base import SourceResult
        if self._delay:
            await asyncio.sleep(self._delay)
        return SourceResult(self.name, target, self._status,
                            records=[dict(r, source=self.name) for r in self._records])


class OrchestratorTest(unittest.IsolatedAsyncioTestCase):
    async def test_runs_only_matching_kind_and_merges(self):
        from osint.orchestrator import Orchestrator
        s1 = _FakeSource("a", "domain", [{"type": "subdomain", "value": "www.example.com"}])
        s2 = _FakeSource("b", "domain", [{"type": "subdomain", "value": "WWW.example.com"},
                                         {"type": "subdomain", "value": "api.example.com"}])
        s3 = _FakeSource("c", "ip", [{"type": "asn", "value": "AS1"}])  # wrong kind
        orch = Orchestrator([s1, s2, s3])
        intel = await orch.run("example.com", "domain",
                               client=object())  # sources ignore the client here
        self.assertEqual(intel.stats()["sources_run"], 2)   # s3 excluded
        # www.example.com reported by a and b (case-insensitive) -> confidence 2.
        www = [m for m in intel.merged if m.value.lower() == "www.example.com"][0]
        self.assertEqual(www.confidence, 2)
        # Highest corroboration sorts first.
        self.assertEqual(intel.merged[0].value.lower(), "www.example.com")

    async def test_per_source_timeout_becomes_error(self):
        from osint.orchestrator import Orchestrator
        slow = _FakeSource("slow", "domain", [{"type": "x", "value": "y"}], delay=0.5)
        orch = Orchestrator([slow], per_source_timeout=0.05)
        intel = await orch.run("example.com", "domain", client=object())
        self.assertEqual(intel.results[0].status, SourceStatus.ERROR)
        self.assertIn("timed out", intel.results[0].reason)

    async def test_no_matching_sources_is_empty_run(self):
        from osint.orchestrator import Orchestrator
        orch = Orchestrator([_FakeSource("a", "ip", [])])
        intel = await orch.run("example.com", "domain", client=object())
        self.assertEqual(intel.stats()["sources_run"], 0)
        self.assertEqual(intel.merged, [])


class BGPViewTest(unittest.IsolatedAsyncioTestCase):
    async def test_asn_prefixes_parsed(self):
        from osint.sources.bgpview import BGPViewASNSource
        routes = {
            "/asn/15169/prefixes": HTTPResult(ok=True, status=200, text=(
                '{"data": {"ipv4_prefixes": [{"prefix": "8.8.8.0/24"}],'
                ' "ipv6_prefixes": [{"prefix": "2001:4860::/32"}]}}')),
            "/asn/15169": HTTPResult(ok=True, status=200, text=(
                '{"data": {"name": "GOOGLE", "country_code": "US"}}')),
        }
        result = await BGPViewASNSource().run(_RoutingClient(routes), "AS15169")
        self.assertEqual(result.status, SourceStatus.OK)
        values = sorted(r["value"] for r in result.records)
        self.assertEqual(values, ["2001:4860::/32", "8.8.8.0/24"])
        self.assertEqual(result.meta.get("name"), "GOOGLE")

    async def test_ip_rejects_private(self):
        from osint.sources.bgpview import BGPViewIPSource
        result = await BGPViewIPSource().run(_RoutingClient({}), "10.0.0.1")
        self.assertEqual(result.status, SourceStatus.INVALID_TARGET)

    async def test_ip_asn_lookup(self):
        from osint.sources.bgpview import BGPViewIPSource
        routes = {"/ip/8.8.8.8": HTTPResult(ok=True, status=200, text=(
            '{"data": {"prefixes": [{"prefix": "8.8.8.0/24",'
            ' "asn": {"asn": 15169, "name": "GOOGLE"}}], "ptr_record": "dns.google"}}'))}
        result = await BGPViewIPSource().run(_RoutingClient(routes), "8.8.8.8")
        self.assertEqual(result.status, SourceStatus.OK)
        types = sorted(r["type"] for r in result.records)
        self.assertEqual(types, ["asn", "prefix"])


class ReportTest(unittest.IsolatedAsyncioTestCase):
    async def _intel(self):
        from osint.orchestrator import Orchestrator
        s1 = _FakeSource("crtsh", "domain", [{"type": "subdomain", "value": "www.example.com"}])
        s2 = _FakeSource("other", "domain", [{"type": "subdomain", "value": "www.example.com"}])
        return await Orchestrator([s1, s2]).run("example.com", "domain", client=object())

    async def test_json_report_roundtrips(self):
        import json
        from osint.reports import json_report
        intel = await self._intel()
        text = json_report.render(intel)
        data = json.loads(text)
        self.assertEqual(data["stats"]["target"], "example.com")
        self.assertEqual(data["stats"]["records_merged"], 1)

    async def test_markdown_report_has_sections(self):
        from osint.reports import markdown_report
        intel = await self._intel()
        md = markdown_report.render(intel)
        self.assertIn("# OSINT report", md)
        self.assertIn("## Sources", md)
        self.assertIn("## Findings", md)
        self.assertIn("www.example.com", md)
        self.assertIn("x2", md)   # corroboration marker (reported by 2 sources)


if __name__ == "__main__":
    unittest.main()
