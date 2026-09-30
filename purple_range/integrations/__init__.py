"""purple_range.integrations — reuse purpleteam (instantiate) + opt-in event-bus replay."""

from .purpleteam_bridge import PurpleteamBridge, InstantiationResult
from .soc_bridge import SocBridge, BUS_EVENT_TYPE

__all__ = ["PurpleteamBridge", "InstantiationResult", "SocBridge", "BUS_EVENT_TYPE"]
