"""Tests for the ingestion pipeline: dedup, extraction, evidence, idempotency."""
from news_intelligence.pipeline import Pipeline


def test_pipeline_ingests_and_extracts(engine, corpus, now):
    res = engine.ingest_articles(corpus, now=now)
    assert res.ingested >= 4
    assert res.entities > 0
    assert engine.store.count_articles() >= 4


def test_pipeline_marks_duplicates(engine, corpus, now):
    res = engine.ingest_articles(corpus, now=now)
    # corpus has one near-duplicate pair (unit42 vs msn)
    assert res.duplicates >= 1


def test_pipeline_idempotent(engine, corpus, now):
    engine.ingest_articles(corpus, now=now)
    before = engine.store.count_articles()
    res2 = engine.ingest_articles(corpus, now=now)
    assert res2.skipped_existing >= 4
    assert engine.store.count_articles() == before


def test_pipeline_attaches_confidence(engine, corpus, now):
    engine.ingest_articles(corpus, now=now)
    art = engine.store.list_articles()[0]
    assert art.confidence is not None
    assert "score" in art.confidence


def test_pipeline_seeds_timeline(ingested_engine):
    tl = ingested_engine.timeline("APT29", kind="actor")
    assert tl["count"] >= 1
