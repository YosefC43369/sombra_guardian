"""Models + plan library + registry."""

from __future__ import annotations

import pytest

from purple_range.models import Plan, PlanStep, Expectation
from purple_range.plans import load_library, PlanRegistry, validate_plan_dict
from purple_range.exceptions import PlanValidationError, PlanNotFoundError


def test_plan_step_normalizes_and_sorts():
    p = Plan(code="x-y", name="X", steps=[
        PlanStep(order=2, technique_id="t1049", tactic="Discovery"),
        PlanStep(order=1, technique_id="T1082", tactic="discovery"),
    ])
    assert [s.order for s in p.steps] == [1, 2]
    assert p.steps[1].technique_id == "T1049"        # uppercased
    assert p.steps[0].tactic == "discovery"           # lowercased
    assert p.technique_ids == ["T1082", "T1049"]


def test_invalid_plans_rejected():
    with pytest.raises(PlanValidationError):
        Plan(code="BAD CODE", name="x", steps=[PlanStep(order=1, technique_id="T1001")])
    with pytest.raises(PlanValidationError):
        PlanStep(order=1, technique_id="nope")
    with pytest.raises(PlanValidationError):
        Plan(code="empty", name="x", steps=[])


def test_schema_validation_catches_duplicate_orders():
    with pytest.raises(PlanValidationError):
        validate_plan_dict({"code": "d", "name": "D", "steps": [
            {"order": 1, "technique_id": "T1082"},
            {"order": 1, "technique_id": "T1049"},
        ]})


def test_library_loads_expected_plans():
    codes = {p.code for p in load_library()}
    assert {"discovery-baseline", "execution-scripting", "credential-access-sim"} <= codes


def test_registry_builtin_and_require():
    reg = PlanRegistry()
    assert reg.is_builtin("discovery-baseline")
    p = reg.require("discovery-baseline")
    assert p.technique_ids == ["T1082", "T1016", "T1049", "T1057", "T1083"]
    with pytest.raises(PlanNotFoundError):
        reg.require("does-not-exist")


def test_plan_roundtrip():
    p = PlanRegistry().require("credential-access-sim")
    p2 = Plan.from_dict(p.as_dict())
    assert p2.code == p.code and p2.technique_ids == p.technique_ids
