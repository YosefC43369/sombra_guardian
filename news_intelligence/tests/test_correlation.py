"""Tests for the correlation layer: entity, article, infra, corroboration, vendor."""
from news_intelligence.correlation.entity_correlation import EntityCorrelator
from news_intelligence.correlation.article_correlation import ArticleCorrelator
from news_intelligence.correlation.infrastructure_correlation import InfrastructureCorrelator
from news_intelligence.correlation.report_correlation import ReportCorrelator
from news_intelligence.correlation.topic_correlation import TopicCorrelator


def test_entity_correlation(ingested_engine, now):
    arts = ingested_engine.store.list_articles()
    rels = EntityCorrelator(ingested_engine.store, now=now).correlate(arts)
    kinds = {r.rel_type for r in rels}
    assert "actor_uses_malware" in kinds or "actor_linked_cve" in kinds
    for r in rels:
        assert r.confidence is not None


def test_article_corroboration(ingested_engine, now):
    arts = ingested_engine.store.list_articles()
    rels = ArticleCorrelator(ingested_engine.store, now=now).correlate(arts)
    assert any(r.rel_type == "corroborates" for r in rels)


def test_cross_source_infrastructure(ingested_engine):
    arts = ingested_engine.store.list_articles()
    xs = InfrastructureCorrelator(ingested_engine.store).cross_source_iocs(
        arts, min_domains=2)
    assert any(x["value"] == "evil.com" for x in xs)


def test_report_corroboration_counts_independent(ingested_engine, now):
    arts = ingested_engine.store.list_articles()
    res = ReportCorrelator(now=now).corroboration(arts)
    d = res.to_dict()
    assert d["original"] is not None
    assert d["independent_source_count"] >= 1


def test_vendor_comparison(ingested_engine):
    arts = ingested_engine.store.list_articles()
    vc = TopicCorrelator(ingested_engine.store).vendor_comparison(arts, "CVE-2024-1234")
    assert vc["vendor_count"] >= 2
    assert vc["first_reported_by"]
