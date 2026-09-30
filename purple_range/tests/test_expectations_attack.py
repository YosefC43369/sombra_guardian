"""Expectation catalog + ATT&CK adapter."""

from __future__ import annotations

from purple_range.expectations import expectation_for, merge_expectation
from purple_range.models import Expectation
from purple_range.attack import get_catalog


def test_expectation_direct_and_parent_fallback():
    assert expectation_for("T1082").expected_rules == ["BT-SIM-001"]
    # sub-technique not in map falls back to parent T1059
    assert expectation_for("T1059.999").expected_rules == ["BT-SIM-010"]


def test_expectation_generic_for_unknown():
    exp = expectation_for("T9999")
    assert exp.expected_telemetry == ["SIMULATION_EVENT"]


def test_merge_prefers_step_then_fills():
    merged = merge_expectation(Expectation(expected_telemetry=["DNS_QUERY"]), "T1082")
    assert merged.expected_telemetry == ["DNS_QUERY"]      # step wins
    assert merged.expected_rules == ["BT-SIM-001"]         # catalog fills


def test_attack_catalog_resolves_seed():
    cat = get_catalog()
    assert cat.available
    assert cat.technique_name("T1082") == "System Information Discovery"
    assert "discovery" in cat.technique_tactics("T1082")
    # unknown technique degrades to empty, never raises
    assert cat.technique_name("T9999") == ""
    assert cat.resolve("T9999")["technique_id"] == "T9999"
