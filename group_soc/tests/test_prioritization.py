"""Prioritization: dimension combination, modifiers, noisy-OR confidence."""

from __future__ import annotations

from group_soc.models import SecuritySignal, RiskDimensions
from group_soc.prioritization import (
    PriorityEngine, combine_confidence, impact_boost, urgency_from_repeats,
)


def test_higher_dimensions_higher_score():
    weak = SecuritySignal(chat_id=-100, dimensions=RiskDimensions(severity=0.1, confidence=0.1))
    strong = SecuritySignal(chat_id=-100, dimensions=RiskDimensions(
        severity=0.9, confidence=0.9, impact=0.9, urgency=0.9))
    eng = PriorityEngine()
    assert eng.score(strong).score > eng.score(weak).score


def test_band_assignment():
    sig = SecuritySignal(chat_id=-100, dimensions=RiskDimensions(
        severity=1.0, confidence=1.0, impact=1.0, urgency=1.0, exposure=1.0, persistence=1.0))
    ps = eng_score = PriorityEngine().score(sig)
    assert ps.band == "P1" and ps.score >= 85


def test_noisy_or_confidence():
    assert combine_confidence([]) == 0.0
    assert combine_confidence([0.5]) == 0.5
    combined = combine_confidence([0.5, 0.5])
    assert 0.74 < combined < 0.76        # 1 - 0.5*0.5 = 0.75
    assert combine_confidence([0.9, 0.9, 0.9]) < 1.0


def test_impact_boost_from_metadata():
    assert impact_boost({}) == 0.0
    assert impact_boost({"distinct_actors": 5}) > 0.0
    assert impact_boost({"watchlisted": True}) >= 0.15


def test_urgency_grows_with_repeats():
    assert urgency_from_repeats(1) == 0.0
    assert urgency_from_repeats(8) > urgency_from_repeats(2) > 0.0


def test_repeats_raise_effective_urgency():
    sig = SecuritySignal(chat_id=-100, dimensions=RiskDimensions(severity=0.5, urgency=0.5))
    eng = PriorityEngine()
    assert eng.score(sig, hit_count=10).score >= eng.score(sig, hit_count=1).score
