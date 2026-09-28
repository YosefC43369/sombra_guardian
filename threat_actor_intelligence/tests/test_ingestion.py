"""Ingestion: RSS/STIX/TAXII/CISA/NVD/OTX/URLhaus/MalwareBazaar/GitHub/vendor parsers."""
from __future__ import annotations

import json
import pytest

from threat_actor_intelligence.ingestion import (
    RSSIngestor, STIXIngestor, TAXIIIngestor, CISAIngestor, NVDIngestor,
    OTXIngestor, URLhausIngestor, MalwareBazaarIngestor, GitHubIngestor,
    VendorIngestor, extract, parse_indicator_pattern, INGESTORS)


def test_extract_iocs_and_names():
    text = ("APT29 group used SUNBURST backdoor. IOC evil.example.ru, "
            "hash 44d88612fea8a8f36de82e1278abb02f, hxxp://bad[.]com/x, "
            "CVE-2021-1234, technique T1059.001.")
    ex = extract(text)
    vals = {i.value for i in ex.iocs}
    assert "evil.example.ru" in vals
    assert "44d88612fea8a8f36de82e1278abb02f" in vals
    assert "CVE-2021-1234" in ex.cve_ids
    assert "T1059.001" in ex.technique_ids
    assert "APT29" in ex.actor_names


def test_rss_parse(rss_feed):
    r = RSSIngestor(vendor="Test").parse(rss_feed)
    assert len(r.reports) == 1
    rep = r.reports[0]
    assert "APT29" in rep.actor_names
    assert "CVE-2021-1234" in rep.cve_ids
    assert any(i.value == "evil.example.ru" for i in r.iocs)


def test_stix_parse(stix_bundle):
    r = STIXIngestor(provider_name="opencti").parse(stix_bundle)
    assert len(r.actors) == 1 and r.actors[0].canonical_name == "APT29"
    assert r.actors[0].actor_type.value == "nation-state"
    assert r.actors[0].attack_group_id == "G0016"
    assert len(r.families) == 1 and r.families[0].family_name == "SUNBURST"
    assert len(r.campaigns) == 1
    assert any(i.value == "evil.example.com" for i in r.iocs)
    rel_types = {(x.src_type.value, x.rel_type.value, x.dst_type.value)
                 for x in r.relationships}
    assert ("actor", "uses", "malware") in rel_types
    assert ("campaign", "attributed_to", "actor") in rel_types


def test_stix_indicator_pattern():
    pat = ("[file:hashes.'SHA-256' = "
           "'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']")
    out = parse_indicator_pattern(pat)
    assert out and out[0][0].value == "sha256"


def test_taxii_envelope_delegates_to_stix(stix_bundle):
    env = {"objects": stix_bundle["objects"], "more": False}
    r = TAXIIIngestor(provider_name="taxii").parse(env)
    assert len(r.actors) == 1


def test_cisa_kev(cisa_kev_json):
    r = CISAIngestor().parse(cisa_kev_json)
    assert len(r.reports) == 1
    assert "CVE-2021-44228" in r.reports[0].cve_ids
    assert "ransomware" in r.reports[0].tags
    assert r.reports[0].source_class.value == "government"


def test_nvd():
    payload = json.dumps({"vulnerabilities": [{"cve": {
        "id": "CVE-2021-44228", "published": "2021-12-10T00:00:00",
        "descriptions": [{"lang": "en", "value": "Log4Shell RCE."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0,
                                                    "baseSeverity": "CRITICAL"}}]},
        "weaknesses": [{"description": [{"value": "CWE-502"}]}],
        "references": [{"url": "https://logging.apache.org"}]}}]})
    r = NVDIngestor().parse(payload)
    assert r.reports[0].cve_ids == ["CVE-2021-44228"]
    assert "CWE-502" in r.reports[0].tags


def test_otx(otx_json):
    r = OTXIngestor().parse(otx_json)
    assert len(r.campaigns) == 1
    assert r.campaigns[0].victimology.countries() == {"US": 1, "GB": 1}
    assert "APT29" in r.actor_names
    assert "T1566" in r.technique_ids
    # campaign attributed_to actor + uses malware relationships emitted
    kinds = {(x.rel_type.value, x.dst_type.value) for x in r.relationships}
    assert ("attributed_to", "actor") in kinds
    assert ("uses", "malware") in kinds


def test_urlhaus():
    payload = json.dumps({"urls": [{"url": "http://evil.com/x", "threat": "malware",
                                    "signature": "AgentTesla", "host": "evil.com",
                                    "date_added": "2023-01-01 00:00:00",
                                    "tags": ["exe"]}]})
    r = URLhausIngestor().parse(payload)
    assert any(i.ioc_type.value == "url" for i in r.iocs)
    assert "AgentTesla" in r.malware_names


def test_malwarebazaar_hash_refs_only():
    payload = json.dumps({"query_status": "ok", "data": [{
        "sha256_hash": "a" * 64, "md5_hash": "b" * 32, "signature": "Emotet",
        "first_seen": "2023-01-01 00:00:00", "tags": ["exe"]}]})
    r = MalwareBazaarIngestor().parse(payload)
    assert r.families[0].family_name == "Emotet"
    assert "a" * 64 in r.families[0].known_hashes
    # metadata only: no sample bytes anywhere in the result
    assert all("payload" not in (rep.summary or "").lower() for rep in r.reports)


def test_github_text_and_yara_refs():
    text = ("# Threat report\nAPT28 malware. rule Detects_Evil { condition: true }\n"
            "IOC: 1.2.3.4 and CVE-2020-0001.")
    r = GitHubIngestor().parse(text, repo="org/repo", path="report.md")
    assert any(i.ioc_type.value == "yara_ref" for i in r.iocs)
    assert "CVE-2020-0001" in r.cve_ids


def test_vendor_html():
    html = ("<html><head><title>APT41 report</title></head><body>"
            "<p>APT41 group used Cobalt Strike. IOC evil.example.org, "
            "CVE-2019-1234.</p></body></html>")
    r = VendorIngestor(vendor="Vendor").parse(html, url="https://v/x")
    assert r.reports[0].title == "APT41 report"
    assert "CVE-2019-1234" in r.reports[0].cve_ids


def test_registry_complete():
    for name in ("rss", "stix", "taxii", "cisa", "nvd", "otx", "urlhaus",
                 "malwarebazaar", "github", "vendor"):
        assert name in INGESTORS
