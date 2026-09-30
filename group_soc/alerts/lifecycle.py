"""
group_soc/alerts/lifecycle.py — validated alert state transitions.

Applies a status change to an alert, enforcing the transition table in constants.py
and stamping the right timestamps (acknowledged_at, resolved_at). An illegal
transition raises SocStateError rather than silently corrupting state.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, Tuple

from ..models.alert import Alert
from ..constants import AlertStatus, TERMINAL_ALERT_STATUSES
from ..exceptions import SocStateError
from ..util import now


def transition(alert: Alert, new_status: str) -> Tuple[Alert, Dict[str, Any]]:
    """Return (updated_alert, changes-dict). Raises SocStateError if illegal."""
    if new_status == alert.status:
        return alert, {}
    if not alert.can_transition_to(new_status):
        raise SocStateError(
            f"illegal alert transition {alert.status} -> {new_status}",
            code="SOC_STATE_ERROR", alert_id=alert.alert_id)
    t = now()
    changes: Dict[str, Any] = {"status": new_status, "updated_at": t}
    if new_status == AlertStatus.ACKNOWLEDGED.value and not alert.acknowledged_at:
        changes["acknowledged_at"] = t
    if new_status in TERMINAL_ALERT_STATUSES and not alert.resolved_at:
        changes["resolved_at"] = t
    updated = dataclasses.replace(alert, **changes)
    return updated, changes
