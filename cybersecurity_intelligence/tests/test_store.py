"""Persistence: sources, claims, contradictions, assessments, search."""

from __future__ import annotations

from threat_actor_intelligence.models.evidence import SourceClass

from cybersecurity_intelligence.constants import ReliabilityGrade
from cybersecurity_intelligence.models.claim import ClaimSubject, ClaimType
from cybersecurity_intelligence.models.contradiction import (
    Contradiction,
    ContradictionPosition,
    ContradictionType,
)
from cybersecurity_intelligence.models.source import (
    ReliabilityAssessment,
    SourceRecord,
)

from .conftest import make_claim, make_ref


def test_store_roundtrip_source(store):
    s = SourceRecord(name="CISA", source_class=SourceClass.GOVERNMENT)
    s.reliability = ReliabilityAssessment(grade=ReliabilityGrade.HIGH, score=0.8)
    store.save_source(s)
    got = store.get_source(s.source_id)
    assert got is not None and got.name == "CISA"
    assert got.reliability.grade is ReliabilityGrade.HIGH


def test_store_claim_upsert_and_query(store):
    subj = ClaimSubject("cve", "CVE-2021-44228", "Log4Shell")
    c = make_claim(subj, "CVE-2021-44228 exploited.",
                   [make_ref("cisa", SourceClass.GOVERNMENT, "https://cisa.gov/a")],
                   claim_type=ClaimType.REPORTED, predicate="exploitation")
    store.save_claim(c)
    store.save_claim(c)  # idempotent upsert
    got = store.claims_for_subject("cve:cve-2021-44228")
    assert len(got) == 1
    assert got[0].claim_id == c.claim_id
    assert store.stats()["claims"] == 1


def test_store_iter_claims_filters(store):
    subj = ClaimSubject("cve", "CVE-1", "CVE-1")
    store.save_claim(make_claim(subj, "a", [make_ref("x", SourceClass.VENDOR, "https://x.com/1")],
                                claim_type=ClaimType.OBSERVED))
    store.save_claim(make_claim(subj, "b", [make_ref("y", SourceClass.VENDOR, "https://y.com/1")],
                                claim_type=ClaimType.REPORTED))
    observed = list(store.iter_claims(claim_type="observed"))
    assert len(observed) == 1 and observed[0].claim_type is ClaimType.OBSERVED
    cves = list(store.iter_claims(subject_type="cve"))
    assert len(cves) == 2


def test_store_search_finds_by_value(store):
    subj = ClaimSubject("domain", "evil.example.ru", "evil.example.ru")
    store.save_claim(make_claim(subj, "domain indicator evil.example.ru reported.",
                                [make_ref("cisa", SourceClass.GOVERNMENT, "https://cisa.gov/a")]))
    hits = store.search_claims("evil.example.ru")
    assert hits and hits[0].subject.ref_value == "evil.example.ru"


def test_store_contradiction_and_assessment(store):
    c = Contradiction(ContradictionType.ATTRIBUTION, "campaign:x", "conflict",
                      [ContradictionPosition("APT29", "c1", ["a"]),
                       ContradictionPosition("UNC2452", "c2", ["b"])])
    store.save_contradiction(c)
    assert store.contradictions_for_subject("campaign:x")
    assert len(list(store.iter_contradictions())) == 1
