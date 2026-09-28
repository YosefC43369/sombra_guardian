"""
news_intelligence.tests.conftest — shared fixtures for the news-engine test suite.

Everything runs offline: no network, no external services. Fixtures build a temp
SQLite store, an engine bound to it, and a small deterministic article corpus so every
correlation/clustering/report assertion has known inputs.
"""

from __future__ import annotations

import os
import tempfile
import time

import pytest

from news_intelligence.configuration import get_config
from news_intelligence.storage.sqlite_store import SQLiteStore
from news_intelligence.engine import NewsIntelligenceEngine
from news_intelligence.models.article import Article


@pytest.fixture()
def now():
    # real "now" so the corpus falls inside the engine's real-time query windows
    # (the engine's convenience methods window against time.time()); offsets in the
    # corpus keep ordering deterministic.
    return time.time()


@pytest.fixture()
def tmp_db(tmp_path):
    return str(tmp_path / "news_test.db")


@pytest.fixture()
def config(tmp_path, tmp_db):
    cfg = get_config()
    cfg.db_path = tmp_db
    cfg.cache_dir = str(tmp_path / "cache")
    return cfg


@pytest.fixture()
def store(config):
    return SQLiteStore(config.db_path)


@pytest.fixture()
def engine(config, store):
    return NewsIntelligenceEngine(config=config, store=store)


def _article(title, summary, domain, source_class, off_hours, now):
    return Article(
        title=title, summary=summary,
        url=f"https://{domain}/{abs(hash(title)) % 99999}",
        source_name=domain, source_domain=domain, source_class=source_class,
        publication_date=now - off_hours * 3600)


@pytest.fixture()
def corpus(now):
    """A small, deterministic corpus with a duplicate, a shared IOC and a campaign."""
    return [
        _article("APT29 exploits CVE-2024-1234 with Cobalt Strike",
                 "Midnight Blizzard targeted Ukraine government with Cobalt Strike. "
                 "IOC evil[.]com and 8.8.4.4",
                 "unit42.paloaltonetworks.com", "vendor", 2, now),
        _article("Cozy Bear campaign uses CVE-2024-1234",
                 "APT29 deployed Cobalt Strike against Ukrainian targets, evil[.]com",
                 "bleepingcomputer.com", "feed", 4, now),
        # near-duplicate of the first (syndicated)
        _article("APT29 exploits CVE-2024-1234 with Cobalt Strike",
                 "Midnight Blizzard targeted Ukraine government with Cobalt Strike. "
                 "IOC evil[.]com and 8.8.4.4",
                 "msn.com", "feed", 5, now),
        _article("LockBit ransomware hits German banks",
                 "New LockBit ransomware campaign targets finance in Germany",
                 "thehackernews.com", "feed", 6, now),
        _article("Researchers track LockBit resurgence",
                 "LockBit ransomware activity rising against banks, evil[.]com noted",
                 "welivesecurity.com", "vendor", 7, now),
    ]


@pytest.fixture()
def ingested_engine(engine, corpus, now):
    engine.bootstrap_sources()
    engine.ingest_articles(corpus, now=now)
    return engine
