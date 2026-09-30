"""
group_soc/integrations/incident.py — bridge SOC incidents to member_incident.py.

The SOC does NOT own member custody; member_incident.py does. When a SOC incident
concerns a specific member, this adapter opens (or extends) a member_incident so the
existing chain-of-custody/evidence/integrity machinery remains the single source of
truth. Fully defensive: if member_incident is unavailable or gated off, the bridge
returns None and the SOC incident simply carries no member link.
"""

from __future__ import annotations

import logging
from typing import Optional

from ..constants import IncidentClass

logger = logging.getLogger("modbot.group_soc.integrations.incident")

# SOC classification → a member_incident detection_type hint. Unknown hints become
# OTHER_SECURITY_EVENT inside member_incident (it never guesses), which is the safe default.
_CLASS_HINT = {
    IncidentClass.SPAM_CAMPAIGN.value: "spam",
    IncidentClass.RAID.value: "flooding",
    IncidentClass.MALICIOUS_LINK.value: "malicious_link",
    IncidentClass.IOC_EXPOSURE.value: "malicious_link",
    IncidentClass.IMPERSONATION.value: "impersonation",
}


class MemberIncidentAdapter:
    def __init__(self):
        self._mic = None
        try:
            import member_incident as mic
            self._mic = mic
        except Exception:
            logger.info("member_incident unavailable; SOC incident bridge is a no-op")

    @property
    def available(self) -> bool:
        return self._mic is not None

    def create_member_incident(self, chat_id: int, user_id: Optional[int],
                               classification: str, severity: str,
                               reason: str = "") -> Optional[int]:
        if self._mic is None or user_id is None:
            return None
        detection_type = _CLASS_HINT.get(classification, "other_security_event")
        try:
            result = self._mic.incident_from_detection(
                int(chat_id), int(user_id), detection_type, str(severity).upper(),
                reason=reason or f"SOC incident ({classification})")
        except Exception:
            logger.exception("member incident bridge call failed")
            return None
        # incident_from_detection returns an IncidentResult; be defensive about shape
        if getattr(result, "ok", False):
            return getattr(result, "incident_id", None)
        return None
