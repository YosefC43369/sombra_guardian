"""Model invariants, round-tripping, and claim-type semantics."""

from __future__ import annotations

import pytest

from threat_actor_intelligence.models.confidence import AssertionKind
from threat_actor_intelligence.models.evidence import EvidenceBundle, SourceClass

from cybersecurity_intelligence.constants import ReliabilityGrade
from cybersecurity_intelligence.exceptions import CTIValidationError
from cybersecurity_intelligence.models.assessment import (
    Assessment,
    AssessmentStatement,
)
from cybersecurity_intelligence.models.claim import Claim, ClaimSubject, ClaimType
from cybersecurity_intelligence.models.contradiction import (
    Contradiction,
    ContradictionPosition,
    ContradictionType,
)
from cybersecurity_intelligence.models.source import (
    ReliabilityAssessment,
    ReliabilityFactor,
    SourceRecord,
)

from .conftest import make_ref


def _subj():
    return ClaimSubject("cve", "CVE-2021-44228", "Log4Shell")


def test_claim_id_is_source_independent():
    a = Claim(_subj(), "X is exploited.", ClaimType.REPORTED,
              EvidenceBundle([make_ref("cisa", SourceClass.GOVERNMENT)]))
    b = Claim(_subj(), "x   IS   Exploited.", ClaimType.REPORTED,
              EvidenceBundle([make_ref("unit42", SourceClass.VENDOR)]))
    # same subject + normalized statement => same id => they will consolidate
    assert a.claim_id == b.claim_id


def test_claim_validate_requires_evidence_for_non_unknown():
    c = Claim(_subj(), "no evidence here", ClaimType.REPORTED, EvidenceBundle())
    with pytest.raises(CTIValidationError):
        c.validate()
    # UNKNOWN claims may legitimately have no evidence
    u = Claim(_subj(), "unknown thing", ClaimType.UNKNOWN, EvidenceBundle())
    assert u.validate() is u


def test_claim_type_ceiling_and_mapping():
    assert ClaimType.REPORTED.confidence_ceiling == 0.75
    assert ClaimType.UNKNOWN.confidence_ceiling == 0.25
    assert ClaimType.CORROBORATED.to_assertion_kind() is AssertionKind.CORRELATED
    assert ClaimType.OBSERVED.to_assertion_kind() is AssertionKind.OBSERVED


def test_claim_roundtrip():
    c = Claim(_subj(), "X is exploited.", ClaimType.REPORTED,
              EvidenceBundle([make_ref("cisa", SourceClass.GOVERNMENT,
                                       "https://cisa.gov/a", "CVE-2021-44228")]),
              detail={"exploitation_status": "exploited"})
    d = c.to_dict()
    c2 = Claim.from_dict(d)
    assert c2.claim_id == c.claim_id
    assert c2.claim_type is ClaimType.REPORTED
    assert c2.detail["exploitation_status"] == "exploited"
    assert len(c2.evidence) == 1


def test_claim_merge_accumulates_evidence():
    a = Claim(_subj(), "X is exploited.", ClaimType.REPORTED,
              EvidenceBundle([make_ref("cisa", SourceClass.GOVERNMENT,
                                       "https://cisa.gov/a")]))
    b = Claim(_subj(), "X is exploited.", ClaimType.REPORTED,
              EvidenceBundle([make_ref("unit42", SourceClass.VENDOR,
                                       "https://unit42.paloaltonetworks.com/b")]))
    a.merge(b)
    assert a.evidence.distinct_count() == 2


def test_reliability_grade_from_score():
    assert ReliabilityGrade.from_score(0.9) is ReliabilityGrade.HIGH
    assert ReliabilityGrade.from_score(0.6) is ReliabilityGrade.MEDIUM
    assert ReliabilityGrade.from_score(0.35) is ReliabilityGrade.LOW
    assert ReliabilityGrade.from_score(0.1) is ReliabilityGrade.UNKNOWN


def test_source_record_roundtrip():
    s = SourceRecord(name="CISA", url="https://cisa.gov",
                     source_class=SourceClass.GOVERNMENT, article_count=5)
    s.reliability = ReliabilityAssessment(
        grade=ReliabilityGrade.HIGH, score=0.8,
        factors=[ReliabilityFactor("source_class", 0.475, "government")])
    s2 = SourceRecord.from_dict(s.to_dict())
    assert s2.source_id == s.source_id
    assert s2.reliability.grade is ReliabilityGrade.HIGH
    assert s2.reliability.reasons()  # non-empty


def test_contradiction_id_stable_regardless_of_position_order():
    p1 = ContradictionPosition("APT29", "c1", ["vendorA"])
    p2 = ContradictionPosition("UNC2452", "c2", ["vendorB"])
    a = Contradiction(ContradictionType.ATTRIBUTION, "campaign:x", "s", [p1, p2])
    b = Contradiction(ContradictionType.ATTRIBUTION, "campaign:x", "s", [p2, p1])
    assert a.contradiction_id == b.contradiction_id
    assert set(a.claim_ids) == {"c1", "c2"}


def test_assessment_register_partitioning_and_roundtrip():
    a = Assessment(
        title="t", subject_key="cve:x",
        statements=[
            AssessmentStatement("fact", "a fact"),
            AssessmentStatement("source_claim", "a claim"),
            AssessmentStatement("analytic_inference", "an inference"),
            AssessmentStatement("uncertainty", "a gap"),
        ])
    assert len(a.facts) == 1 and len(a.source_claims) == 1
    assert len(a.inferences) == 1 and len(a.uncertainties) == 1
    a2 = Assessment.from_dict(a.to_dict())
    assert a2.subject_key == "cve:x"
    assert len(a2.statements) == 4
