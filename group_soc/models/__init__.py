"""group_soc.models — immutable value objects for the SOC subsystem.

Pure dataclasses: no Telegram, no DB, no event-bus imports. Everything is JSON
round-trippable (``as_dict``) and, where persisted, has ``to_row``/``from_row``.
"""

from .severity import (
    RiskDimensions, PriorityScore, DEFAULT_WEIGHTS,
    clamp01, severity_to_float, float_to_severity, band_for_score,
)
from .entity import EntityRef
from .event import SecurityEvent
from .signal import SecuritySignal
from .alert import Alert
from .case import Case, CaseNote
from .incident import Incident
from .timeline import TimelineEntry, TIMELINE_KINDS
from .story import Story, StorySection

__all__ = [
    "RiskDimensions", "PriorityScore", "DEFAULT_WEIGHTS",
    "clamp01", "severity_to_float", "float_to_severity", "band_for_score",
    "EntityRef", "SecurityEvent", "SecuritySignal", "Alert",
    "Case", "CaseNote", "Incident", "TimelineEntry", "TIMELINE_KINDS",
    "Story", "StorySection",
]
