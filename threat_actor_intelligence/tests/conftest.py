"""
Shared fixtures + deterministic fixtures for the CTI test suite.

Every fixture is offline and self-contained: an isolated SQLite store under a
temp dir, a seeded ATT&CK/CAPEC knowledge base, and hand-built STIX/OTX/RSS/CISA
payloads whose extracted facts the tests assert against. A fixed base epoch keeps
confidence and timeline assertions reproducible.
"""

from __future__ import annotations

import json
import os
import time

import pytest

from threat_actor_intelligence.configuration import get_config
from threat_actor_intelligence.storage.sqlite_store import SQLiteStore
from threat_actor_intelligence.mitre.attack_engine import ATTACKEngine
from threat_actor_intelligence.mitre.capec_engine import CAPECEngine
from threat_actor_intelligence.orchestrator import Orchestrator
from threat_actor_intelligence.engine import ThreatActorIntelligenceEngine

BASE = 1609459200.0   # 2021-01-01T00:00:00Z


@pytest.fixture
def now():
    return BASE + 86400 * 30


@pytest.fixture
def config(tmp_path):
    cfg = get_config()
    cfg.db_path = str(tmp_path / "tai.db")
    cfg.cache_dir = str(tmp_path / "cache")
    return cfg


@pytest.fixture
def store(config):
    return SQLiteStore(config.db_path)


@pytest.fixture
def attack():
    return ATTACKEngine().load_seed()


@pytest.fixture
def capec():
    return CAPECEngine().load_seed()


@pytest.fixture
def orchestrator(config, store, attack, capec):
    return Orchestrator(config=config, store=store, attack=attack, capec=capec)


@pytest.fixture
def engine(config, store, attack, capec):
    return ThreatActorIntelligenceEngine(config=config, store=store,
                                         attack=attack, capec=capec)


@pytest.fixture
def stix_bundle():
    return {
        "type": "bundle",
        "objects": [
            {"type": "intrusion-set", "id": "intrusion-set--a",
             "name": "APT29", "aliases": ["Cozy Bear", "Midnight Blizzard"],
             "description": "A nation-state sponsored group.",
             "created": "2016-01-01T00:00:00Z", "modified": "2021-01-01T00:00:00Z",
             "external_references": [{"source_name": "mitre-attack",
                                      "external_id": "G0016"}]},
            {"type": "malware", "id": "malware--b", "name": "SUNBURST",
             "created": "2020-12-01T00:00:00Z",
             "external_references": [{"source_name": "mitre-attack",
                                      "external_id": "S0559"}]},
            {"type": "campaign", "id": "campaign--c", "name": "SolarWinds Compromise",
             "first_seen": "2020-03-01T00:00:00Z", "last_seen": "2020-12-13T00:00:00Z",
             "created": "2020-12-13T00:00:00Z"},
            {"type": "indicator", "id": "indicator--d",
             "pattern": "[domain-name:value = 'evil.example.com']",
             "labels": ["malicious-activity"], "created": "2020-12-13T00:00:00Z"},
            {"type": "relationship", "id": "rel--1", "relationship_type": "uses",
             "source_ref": "intrusion-set--a", "target_ref": "malware--b",
             "created": "2020-12-13T00:00:00Z"},
            {"type": "relationship", "id": "rel--2",
             "relationship_type": "attributed-to",
             "source_ref": "campaign--c", "target_ref": "intrusion-set--a",
             "created": "2020-12-13T00:00:00Z"},
        ],
    }


@pytest.fixture
def rss_feed():
    return (
        '<?xml version="1.0"?><rss version="2.0"><channel><title>Sec Feed</title>'
        '<item><title>APT29 deploys SUNBURST via spearphishing attachment</title>'
        '<link>https://example.com/report-a</link>'
        '<description>The APT29 group deployed the SUNBURST backdoor and used '
        'PowerShell (T1059.001). IOCs: evil.example.ru, '
        '44d88612fea8a8f36de82e1278abb02f, and hxxp://bad[.]com/x. '
        'Related to CVE-2021-1234.</description>'
        '<pubDate>Tue, 01 Jun 2021 12:00:00 GMT</pubDate></item></channel></rss>'
    )


@pytest.fixture
def otx_json():
    return json.dumps({"results": [{
        "id": "pulse1", "name": "SolarWinds Compromise",
        "description": "Supply chain compromise.", "adversary": "APT29",
        "created": "2020-12-13T00:00:00", "modified": "2021-01-01T00:00:00",
        "malware_families": [{"display_name": "SUNBURST"}],
        "attack_ids": [{"id": "T1566"}, {"id": "T1059.001"}],
        "targeted_countries": ["US", "GB"],
        "indicators": [{"indicator": "1.2.3.4", "type": "IPv4"},
                       {"indicator": "bad.example.com", "type": "domain"}],
    }]})


@pytest.fixture
def cisa_kev_json():
    return json.dumps({
        "catalogVersion": "2024.01.01",
        "vulnerabilities": [{
            "cveID": "CVE-2021-44228", "vendorProject": "Apache",
            "product": "Log4j", "vulnerabilityName": "Log4Shell",
            "dateAdded": "2021-12-10", "shortDescription": "RCE via JNDI.",
            "knownRansomwareCampaignUse": "Known"}]})
