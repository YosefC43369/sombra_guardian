"""
purple_range/constants.py — the module vocabulary.

Dependency-free strings/enums shared across the module. Telemetry here is always
SYNTHETIC — these event types describe the *shape* of fixtures the generator emits for
detection tuning, never observations from a real host.

Detection outcomes are intentionally NOT redefined: the analyst records outcomes through
the existing ``purpleteam.DetectionOutcome`` vocabulary. This module only produces the
inputs (plans, synthetic telemetry, expectations) and the cross-exercise analytics.
"""

from __future__ import annotations

from enum import Enum


class TelemetryEventType(str, Enum):
    """Synthetic telemetry event shapes (mirror common EDR/SIEM data sources)."""
    PROCESS_CREATE = "PROCESS_CREATE"
    PROCESS_EXIT = "PROCESS_EXIT"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    DNS_QUERY = "DNS_QUERY"
    FILE_ACCESS = "FILE_ACCESS"
    REGISTRY_ACCESS = "REGISTRY_ACCESS"
    AUTHENTICATION = "AUTHENTICATION"
    SYSTEM_QUERY = "SYSTEM_QUERY"
    SERVICE_EVENT = "SERVICE_EVENT"
    SCHEDULED_TASK_EVENT = "SCHEDULED_TASK_EVENT"
    SIMULATION_EVENT = "SIMULATION_EVENT"

    def __str__(self) -> str:
        return self.value


VALID_TELEMETRY_TYPES = frozenset(t.value for t in TelemetryEventType)


class RiskLevel(str, Enum):
    """Every plan is simulation-only, so the ceiling is MEDIUM (a plan that touches
    sensitive tactics in its *narrative*); there is no HIGH/CRITICAL because nothing
    executes."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"

    def __str__(self) -> str:
        return self.value


VALID_RISK_LEVELS = frozenset(r.value for r in RiskLevel)


#: canonical MITRE ATT&CK Enterprise tactics (ordered, kill-chain-ish) — used to bucket
#: plan steps and lay out the coverage matrix even when the ATT&CK engine is unavailable.
TACTICS_ORDERED = (
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
)
VALID_TACTICS = frozenset(TACTICS_ORDERED)

#: technique id format: Txxxx or Txxxx.xxx (matches purpleteam)
TECHNIQUE_RE = r"^T\d{4}(?:\.\d{3})?$"
#: plan code format: a short slug
PLAN_CODE_RE = r"^[a-z0-9][a-z0-9_-]{1,63}$"

# bounds
MAX_NAME_LEN = 200
MAX_TEXT_LEN = 4000
MAX_STEPS_PER_PLAN = 100
DEFAULT_PAGE_LIMIT = 25
MAX_PAGE_LIMIT = 200

# audit action strings (written via security.write_audit_log)
AUDIT_PLAN_REGISTERED = "PR_PLAN_REGISTERED"
AUDIT_PLAN_INSTANTIATED = "PR_PLAN_INSTANTIATED"
AUDIT_TELEMETRY_GENERATED = "PR_TELEMETRY_GENERATED"
AUDIT_SOC_REPLAY = "PR_SOC_REPLAY"
AUDIT_COVERAGE_SNAPSHOT = "PR_COVERAGE_SNAPSHOT"

# provenance tag stamped on every synthetic artifact so it can never be mistaken for real
SYNTHETIC_SOURCE = "purple_range_sim"
