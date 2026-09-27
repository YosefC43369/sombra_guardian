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


if __name__ == "__main__":
    unittest.main()
