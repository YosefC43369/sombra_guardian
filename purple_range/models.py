"""
purple_range/models.py — pure value objects.

No DB, no Telegram, no network. Everything is JSON round-trippable. A Plan is an ordered
list of PlanSteps; each step names one ATT&CK technique plus its expected telemetry and
expected detection — the material an exercise and a detection-tuning cycle need.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .constants import (
    RiskLevel, VALID_RISK_LEVELS, VALID_TELEMETRY_TYPES, VALID_TACTICS,
    MAX_NAME_LEN, MAX_TEXT_LEN,
)
from .exceptions import PlanValidationError
from .util import clean, normalize_technique, valid_plan_code
from .version import PLAN_SCHEMA_VERSION


@dataclass(frozen=True)
class Expectation:
    """What a defense *should* produce for a technique, used to compare against observed."""
    expected_telemetry: List[str] = field(default_factory=list)   # TelemetryEventType values
    expected_rules: List[str] = field(default_factory=list)       # sim rule ids (BT-SIM-001 …)
    data_sources: List[str] = field(default_factory=list)

    def __post_init__(self):
        tel = [t for t in (self.expected_telemetry or []) if t in VALID_TELEMETRY_TYPES]
        object.__setattr__(self, "expected_telemetry", tel)

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Expectation":
        d = d or {}
        return cls(expected_telemetry=list(d.get("expected_telemetry") or []),
                   expected_rules=list(d.get("expected_rules") or []),
                   data_sources=list(d.get("data_sources") or []))


@dataclass(frozen=True)
class PlanStep:
    order: int
    technique_id: str
    tactic: str = ""
    name: str = ""
    description: str = ""
    expectation: Expectation = field(default_factory=Expectation)

    def __post_init__(self):
        tid = normalize_technique(self.technique_id)
        if tid is None:
            raise PlanValidationError("invalid technique id in plan step",
                                      code="PR_PLAN_INVALID", technique=self.technique_id)
        object.__setattr__(self, "technique_id", tid)
        object.__setattr__(self, "tactic", (str(self.tactic).strip().lower()
                                            if self.tactic else ""))
        object.__setattr__(self, "name", clean(self.name, MAX_NAME_LEN) or "")
        object.__setattr__(self, "description", clean(self.description, MAX_TEXT_LEN) or "")

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["expectation"] = self.expectation.as_dict()
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PlanStep":
        return cls(order=int(d.get("order", 0)), technique_id=d.get("technique_id", ""),
                   tactic=d.get("tactic", ""), name=d.get("name", ""),
                   description=d.get("description", ""),
                   expectation=Expectation.from_dict(d.get("expectation")))


@dataclass(frozen=True)
class Plan:
    code: str
    name: str
    description: str = ""
    risk_level: str = RiskLevel.LOW.value
    framework: str = "MITRE_ATTACK"
    source: str = "builtin"                 # builtin | custom
    tags: List[str] = field(default_factory=list)
    steps: List[PlanStep] = field(default_factory=list)
    schema_version: int = PLAN_SCHEMA_VERSION

    def __post_init__(self):
        if not valid_plan_code(self.code):
            raise PlanValidationError("invalid plan code (slug)", code="PR_PLAN_INVALID",
                                      plan_code=self.code)
        object.__setattr__(self, "code", str(self.code).strip().lower())
        object.__setattr__(self, "name", clean(self.name, MAX_NAME_LEN) or self.code)
        object.__setattr__(self, "description", clean(self.description, MAX_TEXT_LEN) or "")
        risk = str(self.risk_level).upper()
        object.__setattr__(self, "risk_level", risk if risk in VALID_RISK_LEVELS
                           else RiskLevel.LOW.value)
        if not self.steps:
            raise PlanValidationError("a plan needs at least one step",
                                      code="PR_PLAN_INVALID", plan_code=self.code)
        # keep steps ordered by their declared order
        object.__setattr__(self, "steps", sorted(self.steps, key=lambda s: s.order))

    @property
    def technique_ids(self) -> List[str]:
        return [s.technique_id for s in self.steps]

    @property
    def tactics(self) -> List[str]:
        seen, out = set(), []
        for s in self.steps:
            if s.tactic and s.tactic in VALID_TACTICS and s.tactic not in seen:
                out.append(s.tactic)
                seen.add(s.tactic)
        return out

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["steps"] = [s.as_dict() for s in self.steps]
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Plan":
        d = dict(d or {})
        steps = [PlanStep.from_dict(s) for s in (d.get("steps") or [])]
        return cls(code=d.get("code", ""), name=d.get("name", ""),
                   description=d.get("description", ""),
                   risk_level=d.get("risk_level", RiskLevel.LOW.value),
                   framework=d.get("framework", "MITRE_ATTACK"),
                   source=d.get("source", "builtin"),
                   tags=list(d.get("tags") or []), steps=steps,
                   schema_version=int(d.get("schema_version", PLAN_SCHEMA_VERSION)))


@dataclass(frozen=True)
class TelemetryEvent:
    """One synthetic telemetry event. Always carries the synthetic provenance tag."""
    event_type: str
    technique_id: str
    seq: int
    fields: Dict[str, Any] = field(default_factory=dict)
    source: str = "purple_range_sim"

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CoverageCell:
    technique_id: str
    tactic: str
    technique_name: str
    exercised: bool
    best_coverage: str        # purpleteam Coverage value or "NONE"
    exercise_count: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)
