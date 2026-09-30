"""Model invariants: validation, round-tripping, transitions, risk math."""

from __future__ import annotations

import pytest

from group_soc.models import (
    SecurityEvent, SecuritySignal, Alert, Case, CaseNote, Incident,
    RiskDimensions, EntityRef, band_for_score, float_to_severity, severity_to_float,
)
from group_soc.models.severity import PriorityScore, clamp01


def test_event_roundtrip_and_validation():
    e = SecurityEvent(event_type="member_joined", chat_id=-100, actor_hash="h",
                      confidence=5.0, severity="bogus")
    assert e.confidence == 1.0            # clamped
    assert e.severity == "info"           # invalid → default
    e2 = SecurityEvent.from_row(e.to_row())
    assert e2.event_type == "member_joined" and e2.chat_id == -100


def test_event_invalid_type_falls_back():
    e = SecurityEvent(event_type="not_a_real_type")
    assert e.event_type == "message_created"


def test_entity_defang_and_hash_kinds():
    d = EntityRef.domain("Evil.COM")
    assert d.kind == "domain" and "[.]" in d.key
    u = EntityRef.user("hash123", "Joe")
    assert u.kind == "user" and u.key == "hash123"
    assert EntityRef.user(None) is None


def test_risk_dimensions_clamped():
    d = RiskDimensions(severity=2.0, confidence=-1.0)
    assert d.severity == 1.0 and d.confidence == 0.0
    assert RiskDimensions.from_dict(d.as_dict()).severity == 1.0


def test_severity_float_mapping_roundtrip():
    for label in ("info", "low", "medium", "high", "critical"):
        f = severity_to_float(label)
        assert 0.0 <= f <= 1.0
        assert float_to_severity(f) == label


def test_priority_band_thresholds():
    assert band_for_score(90) == "P1"
    assert band_for_score(70) == "P2"
    assert band_for_score(50) == "P3"
    assert band_for_score(25) == "P4"
    assert band_for_score(5) == "P5"


def test_alert_transition_table():
    a = Alert(chat_id=-100, status="new", signal_id="s1")
    assert a.signal_ids == ["s1"]
    assert a.can_transition_to("acknowledged")
    assert a.can_transition_to("resolved")         # a NEW alert may be dismissed as resolved
    assert not a.can_transition_to("escalated")    # ...but cannot skip straight to escalated
    closed = Alert(chat_id=-100, status="closed")
    assert not closed.can_transition_to("new")     # terminal


def test_case_and_incident_roundtrip():
    c = Case(chat_id=-100, title="t", alert_ids=["a1"])
    assert Case.from_row(c.to_row()).alert_ids == ["a1"]
    i = Incident(chat_id=-100, classification="raid", dimensions=RiskDimensions(impact=0.9))
    i2 = Incident.from_row(i.to_row())
    assert i2.classification == "raid" and i2.dimensions.impact == 0.9


def test_incident_invalid_classification_defaults():
    i = Incident(chat_id=-100, classification="nope")
    assert i.classification == "other"
