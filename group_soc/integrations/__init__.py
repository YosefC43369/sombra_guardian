"""
group_soc.integrations — adapters to the rest of Sombra Guardian.

Every adapter is defensive: it reuses an existing subsystem when present and degrades to
a no-op when not, so the SOC never breaks because a dependency changed.

Implemented seams:
  * event_bus   — SOC event contracts + emit binding (Platform or raw EventBus)
  * incident    — bridge SOC incidents to member_incident.py (member custody)
  * integrity   — anchor SOC incidents into integrity_ledger (tamper-evident)
  * threat_intel— optional, gated local IOC lookup (no automatic external calls)

Further seams named in the architecture (entity_fusion, behavioral, workflow) attach
here the same way when a concrete need arises; they are intentionally not stubbed.
"""

from .event_bus import bind_emit, SocAlertCreated, SocIncidentCreated
from .incident import MemberIncidentAdapter
from .integrity import IntegrityAnchor
from .threat_intel import ThreatIntelAdapter

__all__ = [
    "bind_emit", "SocAlertCreated", "SocIncidentCreated",
    "MemberIncidentAdapter", "IntegrityAnchor", "ThreatIntelAdapter",
]
