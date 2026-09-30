"""End-to-end pipeline through the CTIAnalysisEngine facade, and reporting."""

from __future__ import annotations

import json

from cybersecurity_intelligence.constants import Priority
from cybersecurity_intelligence.models.claim import ClaimType


def test_full_pipeline_corroboration_and_contradiction(engine, sample_articles):
    result = engine.analyze_articles(sample_articles)
    assert result.claims
    assert len(result.sources) == 3
    # exactly one attribution contradiction (APT29 vs UNC2452)
    assert len(result.contradictions) == 1
    assert result.contradictions[0].contradiction_type.value == "attribution"

    by_pred = {(c.subject.key(), c.predicate): c for c in result.claims}
    ref = by_pred[("cve:cve-2021-44228", "referenced_in")]
    exploit = by_pred[("cve:cve-2021-44228", "exploitation")]
    ioc = by_pred[("domain:evil.example.ru", "indicator")]

    # the CVE reference appears in all 3 sources -> observed, high corroboration
    assert ref.claim_type is ClaimType.OBSERVED
    assert ref.detail["independence"]["independent_count"] == 3
    # exploitation reported by 2 independent primaries (+ collapsed aggregator)
    assert exploit.claim_type is ClaimType.CORROBORATED
    assert exploit.detail["independence"]["independent_count"] == 2
    # the shared IOC corroborates across the two primaries
    assert ioc.claim_type is ClaimType.CORROBORATED


def test_disputed_claims_are_capped(engine, sample_articles):
    result = engine.analyze_articles(sample_articles)
    disputed = [c for c in result.claims if c.claim_type is ClaimType.DISPUTED]
    assert disputed
    assert all(c.score <= 0.45 for c in disputed)


def test_assess_reads_persisted_claims(engine, sample_articles):
    engine.analyze_articles(sample_articles)
    a = engine.assess("cve:cve-2021-44228")
    assert a.priority is Priority.CRITICAL           # exploited + critical + ransomware
    assert a.facts and a.source_claims
    assert a.contradiction_ids                        # attribution conflict attached
    assert a.overall_confidence is not None


def test_source_grades_assigned(engine, sample_articles):
    result = engine.analyze_articles(sample_articles)
    grades = {s.name: s.reliability.grade.value for s in result.sources}
    assert grades["CISA"] == "high"
    assert grades["RandomBlog"] in ("low", "unknown")  # aggregator penalized


def test_reports_render_all_formats(engine, sample_articles):
    result = engine.analyze_articles(sample_articles)
    a = engine.assess("cve:cve-2021-44228")
    md = engine.render(a, result.contradictions, fmt="markdown")
    assert "# " in md and "Bottom Line Up Front" in md and "Contradictions" in md
    js = engine.render(a, result.contradictions, fmt="json")
    parsed = json.loads(js)
    assert parsed["assessment"]["subject_key"] == "cve:cve-2021-44228"
    tg = engine.render(a, result.contradictions, fmt="telegram")
    assert "Priority" in tg


def test_search_and_health(engine, sample_articles):
    engine.analyze_articles(sample_articles)
    assert engine.search("evil.example.ru")
    h = engine.health()
    assert h["enabled"] is True
    assert h["store"]["claims"] > 0


def test_engine_without_store_is_pure(engine_no_store, sample_articles):
    result = engine_no_store.analyze_articles(sample_articles, persist=False)
    a = engine_no_store.assess("cve:cve-2021-44228", claims=result.claims,
                               contradictions=result.contradictions, persist=False)
    assert a.subject_key == "cve:cve-2021-44228"
    assert a.statements


def test_analyze_and_assess_convenience(engine_no_store, sample_articles):
    a = engine_no_store.analyze_and_assess(sample_articles, "cve:cve-2021-44228",
                                           persist=False)
    assert a.priority is Priority.CRITICAL


def test_determinism(engine_no_store, sample_articles):
    r1 = engine_no_store.analyze_articles(sample_articles, persist=False)
    r2 = engine_no_store.analyze_articles(sample_articles, persist=False)
    s1 = sorted((c.claim_id, c.claim_type.value, round(c.score, 4)) for c in r1.claims)
    s2 = sorted((c.claim_id, c.claim_type.value, round(c.score, 4)) for c in r2.claims)
    assert s1 == s2
