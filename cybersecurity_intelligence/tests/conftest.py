"""
Shared, deterministic, offline fixtures for the CTI Analysis Engine tests.

A fixed base epoch keeps confidence/recency assertions reproducible. Every fixture
is self-contained: no network, an isolated SQLite store under a temp dir, and
hand-built article payloads whose extracted intelligence the tests assert against.
"""

from __future__ import annotations

from typing import List

import pytest

from threat_actor_intelligence.models.evidence import (
    EvidenceBundle,
    EvidenceRef,
    SourceClass,
)

from cybersecurity_intelligence.config import get_config
from cybersecurity_intelligence.engine import CTIAnalysisEngine
from cybersecurity_intelligence.models.claim import Claim, ClaimSubject, ClaimType
from cybersecurity_intelligence.storage import CTIStore

BASE = 1609459200.0            # 2021-01-01T00:00:00Z
NOW = BASE + 86400 * 340       # ~2021-12-07


@pytest.fixture
def now() -> float:
    return NOW


@pytest.fixture
def config(tmp_path):
    cfg = get_config()
    cfg.db_path = str(tmp_path / "cti.db")
    return cfg


@pytest.fixture
def store(config) -> CTIStore:
    return CTIStore(config.db_path)


@pytest.fixture
def engine(config, store) -> CTIAnalysisEngine:
    return CTIAnalysisEngine(config=config, store=store, now=NOW)


@pytest.fixture
def engine_no_store(config) -> CTIAnalysisEngine:
    return CTIAnalysisEngine(config=config, store=None, now=NOW)


def make_ref(provider: str, source_class: SourceClass, url: str = "",
             external_id: str = "", excerpt: str = "", at: float = NOW - 86400
             ) -> EvidenceRef:
    return EvidenceRef(provider=provider, source_class=source_class,
                       title=provider, source_url=url, external_id=external_id,
                       excerpt=excerpt, observed_at=at)


def make_claim(subject: ClaimSubject, statement: str, refs: List[EvidenceRef],
               claim_type: ClaimType = ClaimType.REPORTED, predicate: str = "",
               detail=None) -> Claim:
    return Claim(subject, statement, claim_type, EvidenceBundle(list(refs)),
                 predicate=predicate, observed_at=NOW - 86400,
                 detail=dict(detail or {}))


@pytest.fixture
def sample_articles():
    return [
        {
            "title": "CISA warns Log4Shell CVE-2021-44228 actively exploited",
            "summary": ("Apache Log4j CVE-2021-44228 is being exploited in the "
                        "wild in a critical ransomware campaign. IOC: "
                        "evil.example.ru and technique T1190."),
            "source": "CISA", "source_class": "government",
            "url": "https://www.cisa.gov/advisory/log4shell",
            "published_at": "2021-12-11T00:00:00Z",
        },
        {
            "title": "Unit42 analysis of Log4j exploitation",
            "summary": ("Palo Alto Unit42 confirms CVE-2021-44228 exploited in "
                        "the wild, critical severity. Same IOC evil.example.ru "
                        "observed. Attributed to APT29."),
            "source": "Unit42", "source_class": "vendor",
            "url": "https://unit42.paloaltonetworks.com/log4j",
            "published_at": "2021-12-12T00:00:00Z",
        },
        {
            "title": "Aggregator rehash of Log4j news",
            "summary": ("CVE-2021-44228 exploited. Attributed to UNC2452 "
                        "according to our sources."),
            "source": "RandomBlog", "source_class": "aggregator",
            "url": "https://randomblog.example/log4j",
            "published_at": "2021-12-13T00:00:00Z",
        },
    ]
