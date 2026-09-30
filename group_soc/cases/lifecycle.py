"""group_soc/cases/lifecycle.py — validated case state transitions."""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, Tuple

from ..models.case import Case
from ..constants import CaseStatus, TERMINAL_CASE_STATUSES
from ..exceptions import SocStateError
from ..util import now


def transition(case: Case, new_status: str) -> Tuple[Case, Dict[str, Any]]:
    if new_status == case.status:
        return case, {}
    if not case.can_transition_to(new_status):
        raise SocStateError(f"illegal case transition {case.status} -> {new_status}",
                            code="SOC_STATE_ERROR", case_id=case.case_id)
    t = now()
    changes: Dict[str, Any] = {"status": new_status, "updated_at": t}
    if new_status in TERMINAL_CASE_STATUSES and not case.closed_at:
        changes["closed_at"] = t
    return dataclasses.replace(case, **changes), changes
