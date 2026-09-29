"""Engine behaviour: reliability, independence/corroboration, confidence,
contradiction detection, and assessment assembly."""

from __future__ import annotations

from threat_actor_intelligence.models.evidence import SourceClass

from cybersecurity_intelligence.constants import Priority, ReliabilityGrade
from cybersecurity_intelligence.engines import (
    AssessmentEngine,
    ConfidenceEngine,
    ContradictionEngine,
    EvidenceEngine,
    SourceReliabilityEngine,
    registrable_host,
)
from cybersecurity_intelligence.models.claim import ClaimSubject, ClaimType

from .conftest import NOW, make_claim, make_ref


# --------------------------------------------------------------------------- #
# Source reliability
# --------------------------------------------------------------------------- #

def test_reliability_government_high_unknown_low():
    e = SourceReliabilityEngine(now=NOW)
    gov = e.grade_ref(make_ref("cisa", SourceClass.GOVERNMENT,
                               "https://cisa.gov/a", "CVE", "x" * 300))
    blog = e.grade_ref(make_ref("blog", SourceClass.UNKNOWN, ""))
    assert gov.grade is ReliabilityGrade.HIGH
    assert blog.grade in (ReliabilityGrade.LOW, ReliabilityGrade.UNKNOWN)
    assert gov.score > blog.score
    assert gov.reasons()  # explainable


def test_reliability_aggregator_penalized_below_primary():
    e = SourceReliabilityEngine(now=NOW)
    vendor = e.grade_ref(make_ref("v", SourceClass.VENDOR, "https://v.com/x",
                                  excerpt="y" * 300))
    agg = e.grade_ref(make_ref("a", SourceClass.AGGREGATOR, "https://a.com/x"))
    assert vendor.score > agg.score


# --------------------------------------------------------------------------- #
# Evidence engine — independence & corroboration
# --------------------------------------------------------------------------- #

def test_registrable_host():
    assert registrable_host("https://research.checkpoint.com/x") == "checkpoint.com"
    assert registrable_host("https://cisa.gov/a") == "cisa.gov"
    assert registrable_host("") == ""


def test_two_primaries_corroborate():
    ee = EvidenceEngine(min_independent=2)
    subj = ClaimSubject("cve", "CVE-1", "CVE-1")
    c1 = make_claim(subj, "CVE-1 exploited.",
                    [make_ref("cisa", SourceClass.GOVERNMENT, "https://cisa.gov/a")])
    c2 = make_claim(subj, "CVE-1 exploited.",
                    [make_ref("unit42", SourceClass.VENDOR,
                              "https://unit42.paloaltonetworks.com/b")])
    out = ee.consolidate([c1, c2])
    assert len(out) == 1
    assert out[0].claim_type is ClaimType.CORROBORATED
    assert out[0].detail["independence"]["independent_count"] == 2


def test_aggregator_reprints_do_not_manufacture_corroboration():
    ee = EvidenceEngine(min_independent=2)
    subj = ClaimSubject("cve", "CVE-1", "CVE-1")
    # one primary + three aggregator reprints => still only 2 independent groups
    claims = [
        make_claim(subj, "CVE-1 exploited.",
                   [make_ref("cisa", SourceClass.GOVERNMENT, "https://cisa.gov/a")]),
        make_claim(subj, "CVE-1 exploited.",
                   [make_ref("aggA", SourceClass.AGGREGATOR, "https://a.example/x")]),
        make_claim(subj, "CVE-1 exploited.",
                   [make_ref("aggB", SourceClass.AGGREGATOR, "https://b.example/x")]),
        make_claim(subj, "CVE-1 exploited.",
                   [make_ref("aggC", SourceClass.FEED, "https://c.example/x")]),
    ]
    out = ee.consolidate(claims)
    assert len(out) == 1
    # cisa (primary) + one collapsed secondary pool = 2 groups
    assert out[0].detail["independence"]["independent_count"] == 2


def test_same_publisher_two_urls_counts_once():
    ee = EvidenceEngine(min_independent=2)
    subj = ClaimSubject("cve", "CVE-1", "CVE-1")
    c = make_claim(subj, "CVE-1 exploited.", [
        make_ref("cisa", SourceClass.GOVERNMENT, "https://www.cisa.gov/a"),
        make_ref("cisa", SourceClass.GOVERNMENT, "https://cisa.gov/b"),
    ])
    out = ee.consolidate([c])
    assert out[0].detail["independence"]["independent_count"] == 1
    assert out[0].claim_type is ClaimType.REPORTED  # not corroborated


def test_inferred_never_promoted_by_corroboration():
    ee = EvidenceEngine(min_independent=2)
    subj = ClaimSubject("campaign", "x", "x")
    c1 = make_claim(subj, "Likely same operator.",
                    [make_ref("a", SourceClass.VENDOR, "https://a.com/x")],
                    claim_type=ClaimType.INFERRED)
    c2 = make_claim(subj, "Likely same operator.",
                    [make_ref("b", SourceClass.VENDOR, "https://b.com/x")],
                    claim_type=ClaimType.INFERRED)
    out = ee.consolidate([c1, c2])
    assert out[0].claim_type is ClaimType.INFERRED


def test_empty_evidence_becomes_unknown():
    ee = EvidenceEngine()
    subj = ClaimSubject("cve", "x", "x")
    c = make_claim(subj, "mystery", [])
    out = ee.consolidate([c])
    assert out[0].claim_type is ClaimType.UNKNOWN


# --------------------------------------------------------------------------- #
# Confidence engine — claim-type ceiling
# --------------------------------------------------------------------------- #

def test_reported_confidence_capped_by_ceiling():
    ce = ConfidenceEngine(now=NOW)
    subj = ClaimSubject("cve", "x", "x")
    # a single very-strong government source: evidence would score high, but
    # REPORTED caps it at 0.75.
    c = make_claim(subj, "x exploited.",
                   [make_ref("cisa", SourceClass.GOVERNMENT, "https://cisa.gov/a",
                             excerpt="d" * 400)],
                   claim_type=ClaimType.REPORTED)
    cm = ce.score_claim(c)
    assert cm.score <= 0.75
    assert "claim_type_ceiling" in cm.factors or cm.score < 0.75


def test_disputed_confidence_capped_low():
    ce = ConfidenceEngine(now=NOW)
    subj = ClaimSubject("campaign", "x", "x")
    c = make_claim(subj, "attributed to A.",
                   [make_ref("cisa", SourceClass.GOVERNMENT, "https://cisa.gov/a")],
                   claim_type=ClaimType.DISPUTED)
    cm = ce.score_claim(c)
    assert cm.score <= 0.45


# --------------------------------------------------------------------------- #
# Contradiction engine
# --------------------------------------------------------------------------- #

def test_contradiction_detected_on_conflicting_attribution():
    cde = ContradictionEngine()
    subj = ClaimSubject("campaign", "solarwinds", "SolarWinds")
    a = make_claim(subj, "Attributed to APT29.",
                   [make_ref("vendorA", SourceClass.VENDOR, "https://a.com/x")],
                   detail={"attribution": "APT29"})
    b = make_claim(subj, "Attributed to UNC2452.",
                   [make_ref("vendorB", SourceClass.VENDOR, "https://b.com/y")],
                   detail={"attribution": "UNC2452"})
    contras = cde.detect([a, b])
    assert len(contras) == 1
    assert contras[0].contradiction_type.value == "attribution"
    assert len(contras[0].positions) == 2
    assert cde.disputed_claim_ids(contras)


def test_no_contradiction_when_sources_agree():
    cde = ContradictionEngine()
    subj = ClaimSubject("campaign", "x", "x")
    a = make_claim(subj, "Attributed to APT29.",
                   [make_ref("vendorA", SourceClass.VENDOR, "https://a.com/x")],
                   detail={"attribution": "APT29"})
    b = make_claim(subj, "Attributed to APT29.",
                   [make_ref("vendorB", SourceClass.VENDOR, "https://b.com/y")],
                   detail={"attribution": "apt29"})  # normalized equal
    assert cde.detect([a, b]) == []


def test_contradicting_providers_for():
    cde = ContradictionEngine()
    subj = ClaimSubject("campaign", "x", "x")
    a = make_claim(subj, "Attributed to APT29.",
                   [make_ref("vendorA", SourceClass.VENDOR, "https://a.com/x")],
                   detail={"attribution": "APT29"})
    b = make_claim(subj, "Attributed to UNC2452.",
                   [make_ref("vendorB", SourceClass.VENDOR, "https://b.com/y")],
                   detail={"attribution": "UNC2452"})
    contras = cde.detect([a, b])
    provs = cde.contradicting_providers_for(a, contras)
    assert "vendorB" in provs and "vendorA" not in provs


# --------------------------------------------------------------------------- #
# Assessment engine
# --------------------------------------------------------------------------- #

def test_assessment_priority_from_defensive_signals():
    ae = AssessmentEngine(now=NOW)
    subj = ClaimSubject("cve", "cve-1", "CVE-1")
    c = make_claim(subj, "CVE-1 reported as exploited.",
                   [make_ref("cisa", SourceClass.GOVERNMENT, "https://cisa.gov/a")],
                   detail={"exploitation_status": "exploited", "severity": "critical",
                           "known_ransomware": True})
    ConfidenceEngine(now=NOW).score_claim(c)
    a = ae.build("cve:cve-1", "CVE-1", [c])
    assert a.priority is Priority.CRITICAL
    assert a.detail["priority_reason"]


def test_assessment_registers_split_by_claim_type():
    ae = AssessmentEngine(now=NOW)
    ce = ConfidenceEngine(now=NOW)
    subj = ClaimSubject("cve", "cve-1", "CVE-1")
    observed = make_claim(subj, "CVE-1 referenced.",
                          [make_ref("cisa", SourceClass.GOVERNMENT, "https://cisa.gov/a")],
                          claim_type=ClaimType.OBSERVED)
    reported = make_claim(subj, "CVE-1 exploited.",
                          [make_ref("v", SourceClass.VENDOR, "https://v.com/x")],
                          claim_type=ClaimType.REPORTED)
    inferred = make_claim(subj, "Exposure may be widespread.",
                          [make_ref("v", SourceClass.VENDOR, "https://v.com/y")],
                          claim_type=ClaimType.INFERRED)
    for c in (observed, reported, inferred):
        ce.score_claim(c)
    a = ae.build("cve:cve-1", "CVE-1", [observed, reported, inferred])
    assert len(a.facts) == 1
    assert len(a.source_claims) == 1
    assert len(a.inferences) == 1
    assert a.summary  # BLUF present
