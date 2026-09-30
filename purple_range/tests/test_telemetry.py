"""Synthetic telemetry: determinism, caps, synthetic provenance, lab-safe values."""

from __future__ import annotations

from purple_range.telemetry import TelemetrySynthesizer
from purple_range.plans import PlanRegistry


def test_deterministic_for_same_seed():
    s1 = TelemetrySynthesizer(base_seed=1337)
    s2 = TelemetrySynthesizer(base_seed=1337)
    a = [e.as_dict() for e in s1.for_technique("T1082", ["PROCESS_CREATE", "SYSTEM_QUERY"], 2)]
    b = [e.as_dict() for e in s2.for_technique("T1082", ["PROCESS_CREATE", "SYSTEM_QUERY"], 2)]
    assert a == b and len(a) == 4


def test_all_events_are_synthetic_and_lab_safe():
    events = TelemetrySynthesizer().for_technique("T1049", ["NETWORK_CONNECTION"], 3)
    for e in events:
        assert e.source == "purple_range_sim"
        blob = str(e.fields)
        assert "SIMULATED-HOST" in blob                 # fake host
        assert "192.0.2." in blob                        # RFC 5737 doc range
    # no real command is ever present
    for e in TelemetrySynthesizer().for_technique("T1059", ["PROCESS_CREATE"], 1):
        assert e.fields["command_line"].startswith("<synthetic-emulation")


def test_max_events_cap():
    events = TelemetrySynthesizer(max_events=3).for_technique(
        "T1082", ["PROCESS_CREATE", "SYSTEM_QUERY"], 10)
    assert len(events) == 3


def test_unknown_technique_yields_nothing():
    assert TelemetrySynthesizer().for_technique("not-a-tid", ["PROCESS_CREATE"]) == []


def test_for_plan_covers_all_steps():
    plan = PlanRegistry().require("discovery-baseline")
    events = TelemetrySynthesizer().for_plan(plan, per_type=1)
    assert {e.technique_id for e in events} == set(plan.technique_ids)
