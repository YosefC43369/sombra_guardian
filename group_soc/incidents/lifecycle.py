"""group_soc/incidents/lifecycle.py — validated incident state transitions."""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, Tuple

from ..models.incident import Incident
from ..constants import IncidentStatus, TERMINAL_INCIDENT_STATUSES
from ..exceptions import SocStateError
from ..util import now


def transition(incident: Incident, new_status: str) -> Tuple[Incident, Dict[str, Any]]:
    if new_status == incident.status:
        return incident, {}
    if not incident.can_transition_to(new_status):
        raise SocStateError(
            f"illegal incident transition {incident.status} -> {new_status}",
            code="SOC_STATE_ERROR", incident_id=incident.incident_id)
    t = now()
    changes: Dict[str, Any] = {"status": new_status, "updated_at": t}
    if new_status in TERMINAL_INCIDENT_STATUSES and not incident.resolved_at:
        changes["resolved_at"] = t
    return dataclasses.replace(incident, **changes), changes
