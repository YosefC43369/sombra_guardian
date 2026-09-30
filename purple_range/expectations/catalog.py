"""
purple_range/expectations/catalog.py — technique → expected telemetry + detection rules.

A small curated default map, plus tactic-level fallbacks, so any technique resolves to a
reasonable expectation even when a plan step didn't spell one out. Used by the telemetry
generator and by ``/range expectations <technique>``. Pure data.
"""

from __future__ import annotations

from typing import Dict, List

from ..models import Expectation
from ..constants import TelemetryEventType as TE
from ..util import normalize_technique
from ..attack import get_catalog

# technique-specific expectations (defanged, synthetic rule ids)
_TECHNIQUE: Dict[str, Expectation] = {
    "T1082": Expectation([TE.PROCESS_CREATE.value, TE.SYSTEM_QUERY.value], ["BT-SIM-001"], ["Process"]),
    "T1016": Expectation([TE.PROCESS_CREATE.value, TE.SYSTEM_QUERY.value], ["BT-SIM-002"], ["Process"]),
    "T1049": Expectation([TE.PROCESS_CREATE.value, TE.NETWORK_CONNECTION.value], ["BT-SIM-003"], ["Network Traffic"]),
    "T1057": Expectation([TE.PROCESS_CREATE.value, TE.SYSTEM_QUERY.value], ["BT-SIM-004"], ["Process"]),
    "T1083": Expectation([TE.PROCESS_CREATE.value, TE.FILE_ACCESS.value], ["BT-SIM-005"], ["File"]),
    "T1059": Expectation([TE.PROCESS_CREATE.value], ["BT-SIM-010"], ["Process", "Command"]),
    "T1059.001": Expectation([TE.PROCESS_CREATE.value, TE.SYSTEM_QUERY.value], ["BT-SIM-011"], ["Script"]),
    "T1053.005": Expectation([TE.PROCESS_CREATE.value, TE.SCHEDULED_TASK_EVENT.value], ["BT-SIM-012"], ["Scheduled Job"]),
    "T1003": Expectation([TE.PROCESS_CREATE.value, TE.FILE_ACCESS.value, TE.SYSTEM_QUERY.value], ["BT-SIM-020"], ["Process", "File"]),
    "T1552": Expectation([TE.FILE_ACCESS.value], ["BT-SIM-021"], ["File"]),
    "T1110": Expectation([TE.AUTHENTICATION.value], ["BT-SIM-022"], ["Authentication"]),
}

# tactic-level fallback (used when a technique isn't in the map above)
_TACTIC_FALLBACK: Dict[str, Expectation] = {
    "discovery": Expectation([TE.PROCESS_CREATE.value, TE.SYSTEM_QUERY.value], ["BT-SIM-000"], ["Process"]),
    "execution": Expectation([TE.PROCESS_CREATE.value], ["BT-SIM-000"], ["Process"]),
    "credential-access": Expectation([TE.PROCESS_CREATE.value, TE.FILE_ACCESS.value], ["BT-SIM-000"], ["Process"]),
    "persistence": Expectation([TE.SCHEDULED_TASK_EVENT.value, TE.SERVICE_EVENT.value], ["BT-SIM-000"], ["Scheduled Job"]),
    "lateral-movement": Expectation([TE.AUTHENTICATION.value, TE.NETWORK_CONNECTION.value], ["BT-SIM-000"], ["Logon Session"]),
    "command-and-control": Expectation([TE.NETWORK_CONNECTION.value, TE.DNS_QUERY.value], ["BT-SIM-000"], ["Network Traffic"]),
    "exfiltration": Expectation([TE.NETWORK_CONNECTION.value], ["BT-SIM-000"], ["Network Traffic"]),
}

_GENERIC = Expectation([TE.SIMULATION_EVENT.value], ["BT-SIM-000"], [])


def expectation_for(technique_id: str) -> Expectation:
    tid = normalize_technique(technique_id)
    if not tid:
        return _GENERIC
    if tid in _TECHNIQUE:
        return _TECHNIQUE[tid]
    # try the parent technique for a sub-technique (T1059.001 -> T1059)
    if "." in tid and tid.split(".")[0] in _TECHNIQUE:
        return _TECHNIQUE[tid.split(".")[0]]
    for tactic in get_catalog().technique_tactics(tid):
        if tactic in _TACTIC_FALLBACK:
            return _TACTIC_FALLBACK[tactic]
    return _GENERIC


def merge_expectation(step_expectation: Expectation, technique_id: str) -> Expectation:
    """A plan step's explicit expectation wins; catalog fills any empty field."""
    default = expectation_for(technique_id)
    return Expectation(
        expected_telemetry=step_expectation.expected_telemetry or default.expected_telemetry,
        expected_rules=step_expectation.expected_rules or default.expected_rules,
        data_sources=step_expectation.data_sources or default.data_sources,
    )
