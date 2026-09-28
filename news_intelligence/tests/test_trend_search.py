"""Tests for the trend engine and search/filter engine."""
from news_intelligence.trend import TrendEngine
from news_intelligence.search import SearchEngine, SearchQuery, FilterEngine


def test_trend_includes_sample_and_window(ingested_engine, now):
    arts = ingested_engine.store.list_articles(limit=5000)
    trends = TrendEngine(window_days=7, min_sample=1).cve_trends(arts, now=now)
    assert trends
    t = trends[0]
    assert t.sample_size >= 1
    assert t.window_days == 7
    assert t.direction in ("emerging", "rising", "falling", "steady")


def test_search_by_text(ingested_engine):
    hits = ingested_engine.search_engine.search(SearchQuery(text="LockBit ransomware"))
    assert hits
    assert any("LockBit" in h.title for h in hits)


def test_search_by_entity(ingested_engine):
    hits = ingested_engine.search_engine.search(SearchQuery(cve="CVE-2024-1234"))
    assert hits


def test_filter_by_source_class(ingested_engine):
    vendor = ingested_engine.filters.vendor_only()
    assert all(a.source_class.value == "vendor" for a in vendor)


def test_whats_new(ingested_engine):
    nw = ingested_engine.whats_new(days=7)
    assert nw["new_articles"] >= 1
    assert isinstance(nw["new_cves"], list)
