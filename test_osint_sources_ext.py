"""
test_osint_sources_ext.py — tests for the added OSINT sources (subfinder, social).
No network: an in-memory fake HTTP client feeds canned responses per URL.
(python -m unittest test_osint_sources_ext)
"""

import json
import asyncio
import unittest

from osint.utils.async_http import HTTPResult
from osint.sources.base import SourceStatus
from osint.sources.subfinder import SubfinderSource
from osint.sources.social import SocialSource, normalize_handle


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class FakeClient:
    def __init__(self, responder):
        self._responder = responder

    async def get(self, url, *, params=None, headers=None):
        return self._responder(url, params or {})


def _ok(text, status=200, url="http://x/"):
    return HTTPResult(ok=(200 <= status < 300), status=status, url=url, text=text)


class SubfinderTest(unittest.TestCase):
    def test_aggregates_and_scopes(self):
        def responder(url, params):
            if "otx" in url:
                return _ok(json.dumps({"passive_dns": [
                    {"hostname": "api.example.com"}, {"hostname": "evil.other.com"}]}))
            if "hackertarget" in url:
                return _ok("www.example.com,1.2.3.4\nmail.example.com,5.6.7.8\n")
            if "jldc.me" in url:
                return _ok(json.dumps(["dev.example.com", "api.example.com"]))
            return _ok("", status=404)

        res = run(SubfinderSource().fetch(FakeClient(responder), "example.com"))
        self.assertEqual(res.status, SourceStatus.OK)
        subs = {r["value"] for r in res.records}
        self.assertIn("api.example.com", subs)      # de-duped across OTX+anubis
        self.assertIn("mail.example.com", subs)
        self.assertNotIn("evil.other.com", subs)    # out-of-scope name dropped

    def test_all_providers_fail(self):
        res = run(SubfinderSource().fetch(FakeClient(lambda u, p: _ok("", status=500)),
                                          "example.com"))
        self.assertEqual(res.status, SourceStatus.ERROR)


class SocialTest(unittest.TestCase):
    def test_handle_validation(self):
        self.assertEqual(normalize_handle("@johnd"), "johnd")
        self.assertIsNone(normalize_handle("a b c"))

    def test_presence_detection(self):
        def responder(url, params):
            # exists on github + reddit; 404 elsewhere
            if "github.com" in url or "reddit.com" in url:
                return _ok("{}", status=200, url=url)
            return _ok("", status=404, url=url)

        res = run(SocialSource().fetch(FakeClient(responder), "@johnd"))
        self.assertEqual(res.status, SourceStatus.OK)
        platforms = {r["platform"] for r in res.records}
        self.assertIn("GitHub", platforms)
        self.assertIn("Reddit", platforms)
        self.assertTrue(all(r["exists"] for r in res.records))

    def test_none_found(self):
        res = run(SocialSource().fetch(FakeClient(lambda u, p: _ok("", status=404, url=u)),
                                       "ghost_user"))
        self.assertEqual(res.status, SourceStatus.EMPTY)


if __name__ == "__main__":
    unittest.main()
