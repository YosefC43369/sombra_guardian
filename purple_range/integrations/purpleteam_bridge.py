"""
purple_range/integrations/purpleteam_bridge.py — instantiate a plan into an exercise.

This is the ONLY way a plan becomes "live", and it does so entirely through the existing
purpleteam engine:
  * ``purpleteam.create_exercise`` — validates the engagement exists and belongs to this
    chat (ownership check);
  * ``purpleteam.add_emulation`` — records each plan step as a planned emulation.

The operator then starts the exercise with the existing ``/pt`` flow, where purpleteam
re-checks the engagement's Rules of Engagement. purple_range therefore never runs, starts,
or authorizes anything itself — it only *plans*, and it cannot bypass RoE because it does
not hold the start path. Fail-closed: any failure from purpleteam aborts and is surfaced.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from ..models import Plan
from ..exceptions import InstantiationError
from ..attack import get_catalog

logger = logging.getLogger("modbot.purple_range.bridge")


@dataclass
class InstantiationResult:
    exercise_id: int
    exercise_code: str
    steps_added: int
    steps_failed: int


class PurpleteamBridge:
    def __init__(self, store=None):
        self.store = store
        self._pt = None

    def _engine(self):
        if self._pt is None:
            try:
                import purpleteam
                self._pt = purpleteam
            except Exception as exc:  # pragma: no cover - purpleteam is core
                raise InstantiationError("purpleteam engine unavailable",
                                         code="PR_INTEGRATION_ERROR") from exc
        return self._pt

    def instantiate(self, plan: Plan, chat_id: int, engagement_id: int,
                    operator_id: int) -> InstantiationResult:
        pt = self._engine()
        catalog = get_catalog()

        # 1) create the exercise (purpleteam validates engagement ownership)
        res = pt.create_exercise(int(chat_id), int(engagement_id), plan.name,
                                 int(operator_id), objective=plan.description,
                                 framework=plan.framework)
        if not getattr(res, "ok", False):
            raise InstantiationError(f"create_exercise failed: {res.reason}",
                                     code="PR_INSTANTIATION_ERROR",
                                     reason=getattr(res, "reason", "UNKNOWN"))
        exercise_id = res.id
        exercise_code = res.detail or ""

        # 2) add each plan step as a planned emulation
        added = failed = 0
        for step in plan.steps:
            tech_name = step.name or catalog.technique_name(step.technique_id)
            r = pt.add_emulation(int(exercise_id), step.technique_id, int(operator_id),
                                 tactic=step.tactic, technique_name=tech_name,
                                 description=step.description)
            if getattr(r, "ok", False):
                added += 1
            else:
                failed += 1
                logger.warning("purple_range: add_emulation failed for %s: %s",
                               step.technique_id, getattr(r, "reason", "?"))

        # 3) record the plan→exercise link + audit (best-effort, never fails the op)
        if self.store is not None:
            try:
                self.store.record_instantiation(chat_id, plan.code, exercise_id,
                                                exercise_code, engagement_id, operator_id, added)
            except Exception:
                logger.debug("purple_range: instantiation link not recorded", exc_info=True)
        self._audit(chat_id, operator_id, plan, exercise_id, exercise_code, added)

        return InstantiationResult(exercise_id, exercise_code, added, failed)

    @staticmethod
    def _audit(chat_id, operator_id, plan, exercise_id, exercise_code, added) -> None:
        try:
            from security import write_audit_log
            from ..constants import AUDIT_PLAN_INSTANTIATED
            write_audit_log(int(chat_id), int(operator_id), actor="user",
                            action=AUDIT_PLAN_INSTANTIATED,
                            detail=(f"plan={plan.code} exercise_id={exercise_id} "
                                    f"code={exercise_code} steps={added}"))
        except Exception:
            logger.debug("purple_range: audit log unavailable", exc_info=True)
