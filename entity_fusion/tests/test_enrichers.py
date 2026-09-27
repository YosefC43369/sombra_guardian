"""Tests for entity_fusion.enrichers.

The network stack (httpx) is not required: each enricher's ``_fetch`` is driven
with a FakeClient that returns canned responses, so the parsing/entity-emitting
logic is fully exercised offline. The degraded ``enrich`` path (no HTTP stack)
is also verified to return a clean failure rather than raising."""

import asyncio
import json as _json
import os
import pytest

from entity_fusion.entity import Entity, EntityType
from entity_fusion.enrichers.gravatar import GravatarEnricher, gravatar_hash
from entity_fusion.enrichers.github import GitHubEnricher
from entity_fusion.enrichers.dns import DNSEnricher
from entity_fusion.enrichers.whois import WhoisEnricher, _extract_org
from entity_fusion.enrichers.ipinfo import IPInfoEnricher
from entity_fusion.enrichers.urlscan import URLScanEnricher
from entity_fusion.enrichers.wayback import WaybackEnricher
from entity_fusion.enrichers.alienvault import AlienVaultEnricher
from entity_fusion.enrichers.base import Enricher


def run(coro):
    return asyncio.run(coro)


class FakeResult:
    def __init__(self, payload=None, ok=True, status=200, text=""):
        self._payload = payload
        self.ok = ok
        self.status = status
        self.url = "https://fake"
        self.reason = "" if ok else f"HTTP {status}"
        self.text = text or (_json.dumps(payload) if payload is not None else "")
        self.headers = {}

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeClient:
    """Routes get/get_json to canned FakeResults by URL substring."""

    def __init__(self, routes):
        self.routes = routes            # list of (substring, FakeResult)
        self.calls = []

    def _match(self, url, params=None):
        haystack = url + "|" + str(params or {})
        for needle, result in self.routes:
            if needle in haystack:
                return result
        return FakeResult(ok=False, status=404)

    async def get(self, url, params=None, headers=None):
        self.calls.append(url)
        return self._match(url, params)

    async def get_json(self, url, params=None, headers=None):
        self.calls.append(url)
        return self._match(url, params)


class TestDegradedPath:
    def test_enrich_returns_failure_without_http_stack(self):
        # In this environment httpx/osint HTTP is unavailable → clean failure.
        e = Entity(type=EntityType.EMAIL, value="a@b.com")
        res = run(GravatarEnricher().enrich(e, client=None))
        assert res.ok is False
        assert "unavailable" in res.reason or "not handled" in res.reason


class TestGravatar:
    def test_parses_public_profile(self):
        profile = {"entry": [{
            "preferredUsername": "johndoe",
            "displayName": "John Doe",
            "accounts": [{"username": "jd", "url": "https://x/jd", "shortname": "twitter"}],
            "urls": [{"value": "https://johndoe.dev"}],
        }]}
        gh = gravatar_hash("john@doe.com")
        client = FakeClient([(f"{gh}.json", FakeResult(profile))])
        e = Entity(type=EntityType.EMAIL, value="john@doe.com")
        res = run(GravatarEnricher()._fetch(e, client))
        assert res.derived["gravatar_username"] == "johndoe"
        types = {c.type for c in res.entities}
        assert EntityType.USERNAME in types and EntityType.WEBSITE in types

    def test_404_is_not_error(self):
        client = FakeClient([("gravatar", FakeResult(ok=False, status=404))])
        e = Entity(type=EntityType.EMAIL, value="none@x.com")
        res = run(GravatarEnricher()._fetch(e, client))
        assert res.ok is True   # no profile is a valid negative, not an error


class TestGitHub:
    def test_parses_profile_and_links(self):
        data = {"login": "johndoe", "name": "John Doe", "company": "@Acme",
                "blog": "https://johndoe.dev", "email": "john@doe.com",
                "location": "Bangkok"}
        client = FakeClient([("users/johndoe", FakeResult(data))])
        e = Entity(type=EntityType.USERNAME, value="johndoe")
        res = run(GitHubEnricher()._fetch(e, client))
        assert res.derived["display_name"] == "John Doe"
        kinds = {c.type for c in res.entities}
        assert {EntityType.ORGANIZATION, EntityType.WEBSITE, EntityType.EMAIL} <= kinds

    def test_missing_user_404(self):
        client = FakeClient([("users/", FakeResult(ok=False, status=404))])
        e = Entity(type=EntityType.USERNAME, value="ghost")
        res = run(GitHubEnricher()._fetch(e, client))
        assert res.ok is True and "no such" in res.reason


class TestDNS:
    def test_emits_global_ips_and_spf(self):
        def answer(vals):
            return {"Answer": [{"data": v} for v in vals]}
        routes = [
            ("'type': 'AAAA'", FakeResult(answer([]))),
            ("'type': 'A'", FakeResult(answer(["8.8.8.8", "10.0.0.1"]))),  # private filtered
            ("'type': 'MX'", FakeResult(answer(["10 mail.example.com"]))),
            ("'type': 'TXT'", FakeResult(answer(["v=spf1 include:_spf.example.com ~all"]))),
            ("'type': 'NS'", FakeResult(answer(["ns1.example.com"]))),
        ]
        client = FakeClient(routes)
        e = Entity(type=EntityType.DOMAIN, value="example.com")
        res = run(DNSEnricher()._fetch(e, client))
        ips = [c.value for c in res.entities if c.type == EntityType.IP]
        assert "8.8.8.8" in ips and "10.0.0.1" not in ips     # SSRF hygiene
        assert res.derived["spf"].startswith("v=spf1")


class TestWhois:
    def test_extract_org_from_vcard(self):
        entities = [{"roles": ["registrant"],
                     "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                              ["org", {}, "text", "Acme Corp"]]]}]
        assert _extract_org(entities) == "Acme Corp"

    def test_fetch_emits_org(self):
        data = {"nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
                "entities": [{"roles": ["registrant"],
                              "vcardArray": ["vcard", [["org", {}, "text", "Acme"]]]}],
                "events": [{"eventAction": "registration", "eventDate": "2020-01-01"}]}
        client = FakeClient([("rdap.org/domain/", FakeResult(data))])
        e = Entity(type=EntityType.DOMAIN, value="example.com")
        res = run(WhoisEnricher()._fetch(e, client))
        assert res.derived["registrant"] == "Acme"
        assert res.entities[0].type == EntityType.ORGANIZATION


class TestIPInfo:
    def test_parses_asn_from_org(self):
        data = {"city": "Mountain View", "country": "US",
                "org": "AS15169 Google LLC", "timezone": "America/Los_Angeles"}
        client = FakeClient([("ipinfo.io", FakeResult(data))])
        e = Entity(type=EntityType.IP, value="8.8.8.8")
        res = run(IPInfoEnricher()._fetch(e, client))
        assert res.derived["country"] == "US"
        assert res.entities and res.entities[0].type == EntityType.ASN

    def test_non_global_ip_skipped(self):
        client = FakeClient([])
        e = Entity(type=EntityType.IP, value="10.0.0.1")
        res = run(IPInfoEnricher()._fetch(e, client))
        assert res.ok is False


class TestURLScan:
    def test_emits_ips_from_results(self):
        data = {"results": [
            {"page": {"ip": "1.2.3.4", "domain": "cdn.example.com"},
             "result": "https://urlscan.io/r/1"},
            {"page": {"ip": "1.2.3.4", "domain": "example.com"}},
        ]}
        client = FakeClient([("urlscan.io/api", FakeResult(data))])
        e = Entity(type=EntityType.DOMAIN, value="example.com")
        res = run(URLScanEnricher()._fetch(e, client))
        ips = [c.value for c in res.entities if c.type == EntityType.IP]
        assert ips == ["1.2.3.4"]   # deduplicated


class TestWayback:
    def test_parses_cdx_rows(self):
        rows = [["original", "timestamp"],
                ["http://example.com/a", "20200101000000"],
                ["http://example.com/b", "20210101000000"]]
        client = FakeClient([("web.archive.org/cdx", FakeResult(rows))])
        e = Entity(type=EntityType.DOMAIN, value="example.com")
        res = run(WaybackEnricher()._fetch(e, client))
        assert len(res.derived["wayback_urls"]) == 2
        assert res.derived["wayback_first"] == "20200101000000"


class TestAlienVault:
    def test_parses_pulses_and_passive_dns(self, monkeypatch):
        monkeypatch.setenv("ALIENVAULT_OTX_API_KEY", "test-key")
        general = {"pulse_info": {"pulses": [{"name": "Bad Actor 1"},
                                             {"name": "Bad Actor 2"}]}}
        pdns = {"passive_dns": [{"address": "5.6.7.8"}]}
        client = FakeClient([("/general", FakeResult(general)),
                             ("/passive_dns", FakeResult(pdns))])
        e = Entity(type=EntityType.DOMAIN, value="evil.example.com")
        enr = AlienVaultEnricher()
        assert enr.api_key() == "test-key"
        res = run(enr._fetch(e, client))
        assert res.derived["otx_pulse_count"] == 2
        assert any(c.type == EntityType.IP for c in res.entities)

    def test_no_key_means_cannot_handle(self, monkeypatch):
        monkeypatch.delenv("ALIENVAULT_OTX_API_KEY", raising=False)
        monkeypatch.delenv("OTX_API_KEY", raising=False)
        e = Entity(type=EntityType.DOMAIN, value="x.com")
        assert AlienVaultEnricher().can_handle(e) is False


class TestCrtSh:
    def test_emits_subdomains(self):
        from entity_fusion.enrichers.crtsh import CrtShEnricher
        rows = [{"name_value": "a.example.com\n*.example.com"},
                {"name_value": "b.example.com"},
                {"name_value": "unrelated.other.com"}]
        client = FakeClient([("crt.sh", FakeResult(rows))])
        e = Entity(type=EntityType.DOMAIN, value="example.com")
        res = run(CrtShEnricher()._fetch(e, client))
        subs = sorted(c.value for c in res.entities)
        assert "a.example.com" in subs and "b.example.com" in subs
        assert all("other.com" not in s for s in subs)   # scoped to queried domain


class TestEnricherBase:
    def test_can_handle_respects_type_and_key(self):
        e_email = Entity(type=EntityType.EMAIL, value="a@b.com")
        e_domain = Entity(type=EntityType.DOMAIN, value="x.com")
        assert GravatarEnricher().can_handle(e_email) is True
        assert GravatarEnricher().can_handle(e_domain) is False   # wrong type

    def test_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "gh-123")
        assert GitHubEnricher().api_key() == "gh-123"

    def test_custom_enricher_not_handled_returns_failure(self):
        class Only(Enricher):
            name = "only"
            handles = (EntityType.IP,)
        res = run(Only().enrich(Entity(type=EntityType.EMAIL, value="a@b.com")))
        assert res.ok is False


def test_as_expander_signature():
    # the adapter must be an async callable (entity, client) -> list
    exp = GravatarEnricher().as_expander()
    assert asyncio.iscoroutinefunction(exp)
