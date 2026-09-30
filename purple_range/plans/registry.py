"""
purple_range/plans/registry.py — the plan catalog.

Combines the curated builtin library (from fixtures) with any custom plans an operator
has registered into the DB (via the optional store). Builtin plans are read-only; a
custom plan with the same code as a builtin cannot shadow it.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional

from ..models import Plan
from ..exceptions import PlanValidationError, PlanNotFoundError
from .loader import load_library_map


class PlanRegistry:
    def __init__(self, store=None):
        self._builtin: Dict[str, Plan] = load_library_map()
        self._store = store   # optional: object with list_plans()/get_plan()/save_plan()

    # ---- reads ----
    def get(self, code: str) -> Optional[Plan]:
        code = (code or "").strip().lower()
        if code in self._builtin:
            return self._builtin[code]
        if self._store is not None:
            return self._store.get_plan(code)
        return None

    def require(self, code: str) -> Plan:
        plan = self.get(code)
        if plan is None:
            raise PlanNotFoundError("plan not found", code="PR_PLAN_NOT_FOUND", plan_code=code)
        return plan

    def list_all(self) -> List[Plan]:
        plans = dict(self._builtin)
        if self._store is not None:
            for p in self._store.list_plans():
                if p.code not in plans:        # builtin wins
                    plans[p.code] = p
        return sorted(plans.values(), key=lambda p: p.code)

    def is_builtin(self, code: str) -> bool:
        return (code or "").strip().lower() in self._builtin

    def builtin_codes(self) -> List[str]:
        return sorted(self._builtin.keys())

    # ---- custom registration ----
    def register_custom(self, plan: Plan) -> Plan:
        if self._store is None:
            raise PlanValidationError("no store configured for custom plans",
                                      code="PR_PLAN_INVALID")
        if self.is_builtin(plan.code):
            raise PlanValidationError("cannot shadow a builtin plan code",
                                      code="PR_PLAN_INVALID", plan_code=plan.code)
        plan = dataclasses.replace(plan, source="custom")
        self._store.save_plan(plan)
        return plan
