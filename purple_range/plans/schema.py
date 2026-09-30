"""
purple_range/plans/schema.py — validate a raw plan dict into a Plan.

The dataclasses in models.py enforce field-level rules; this adds structural checks a
fixture/author is likely to get wrong (missing keys, too many steps, duplicate orders)
and raises a single, clear PlanValidationError.
"""

from __future__ import annotations

from typing import Any, Dict

from ..models import Plan
from ..exceptions import PlanValidationError
from ..constants import MAX_STEPS_PER_PLAN

_REQUIRED = ("code", "name", "steps")


def validate_plan_dict(data: Dict[str, Any]) -> Plan:
    if not isinstance(data, dict):
        raise PlanValidationError("plan must be an object", code="PR_PLAN_INVALID")
    for key in _REQUIRED:
        if key not in data:
            raise PlanValidationError(f"plan missing required key '{key}'",
                                      code="PR_PLAN_INVALID")
    steps = data.get("steps") or []
    if not isinstance(steps, list) or not steps:
        raise PlanValidationError("plan.steps must be a non-empty list",
                                  code="PR_PLAN_INVALID")
    if len(steps) > MAX_STEPS_PER_PLAN:
        raise PlanValidationError(f"plan has too many steps (>{MAX_STEPS_PER_PLAN})",
                                  code="PR_PLAN_INVALID")
    orders = [s.get("order") for s in steps if isinstance(s, dict)]
    if len(set(orders)) != len(orders):
        raise PlanValidationError("plan steps have duplicate 'order' values",
                                  code="PR_PLAN_INVALID")
    # Plan.from_dict performs the field-level validation (technique ids, code, etc.)
    return Plan.from_dict(data)
