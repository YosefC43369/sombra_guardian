"""Tests for the NewsIntelligenceEngine public API (the primary-objective questions)."""


def test_top_entities(ingested_engine):
    actors = ingested_engine.top_entities("threat_actor", days=30)
    assert any(a["value"] == "APT29" for a in actors)


def test_events(ingested_engine):
    ev = ingested_engine.events(days=30, min_sources=2)
    assert isinstance(ev, list)


def test_campaigns(ingested_engine):
    camps = ingested_engine.campaigns(days=60)
    assert isinstance(camps, list)


def test_cross_source_infrastructure(ingested_engine):
    xs = ingested_engine.cross_source_infrastructure(days=60, min_domains=2)
    assert any(x["value"] == "evil.com" for x in xs)


def test_reports_render(ingested_engine):
    assert ingested_engine.daily_brief(fmt="markdown").startswith("#")
    assert "<html" in ingested_engine.actor_report("APT29", fmt="html")
    assert ingested_engine.cve_report("CVE-2024-1234", fmt="dict")["subject"] == "CVE-2024-1234"


def test_graph_export(ingested_engine):
    import json
    g = json.loads(ingested_engine.graph(kind="news", days=60, fmt="json"))
    assert g["stats"]["nodes"] > 0


def test_search(ingested_engine):
    hits = ingested_engine.search("LockBit")
    assert hits


def test_stats(ingested_engine):
    s = ingested_engine.stats()
    assert s["store"]["articles"] >= 4
