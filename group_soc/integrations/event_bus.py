"""
group_soc/integrations/event_bus.py — SOC event contracts + emit binding.

Mirrors the platform's own contract style (blueteam/platform/events.py): each SOC event
is a frozen dataclass with a schema_version and a PII-safe ``to_payload``. These are the
clean, typed interfaces future subsystems (Threat Hunting, AI Analyst, …) subscribe to
without importing SOC internals. Fields are add-only.

``bind_emit`` returns a ``callable(event_type, payload)`` bound to whatever the host
provides — a Platform (with ``.emit``) or a raw workflow EventBus — so the runtime does
not care which it got.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, Optional

from ..version import SCHEMA_VERSION
from ..constants import (
    SOC_EVENT_RECORDED, SOC_SIGNAL_CREATED, SOC_ALERT_CREATED, SOC_ALERT_ESCALATED,
    SOC_CASE_CREATED, SOC_INCIDENT_CREATED, SOC_INCIDENT_RESOLVED,
)

logger = logging.getLogger("modbot.group_soc.bus")


@dataclass(frozen=True)
class _SocEvent:
    schema_version: int = field(default=SCHEMA_VERSION, kw_only=True)
    type: str = field(default="", kw_only=True)

    def to_payload(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("type", None)
        return d


@dataclass(frozen=True)
class SocAlertCreated(_SocEvent):
    alert_id: str = ""
    chat_id: Optional[int] = None
    severity: str = "medium"
    priority_band: str = "P3"
    priority_score: float = 0.0
    correlation_id: str = ""
    type: str = field(default=SOC_ALERT_CREATED, kw_only=True)


@dataclass(frozen=True)
class SocIncidentCreated(_SocEvent):
    incident_id: str = ""
    chat_id: Optional[int] = None
    classification: str = "other"
    severity: str = "high"
    type: str = field(default=SOC_INCIDENT_CREATED, kw_only=True)


def bind_emit(host: Any) -> Optional[Callable[[str, dict], None]]:
    """Return an emit(event_type, payload) callable bound to the host, or None.

    Accepts a Platform (has ``.emit(event_type, payload)``), a raw EventBus (has
    ``.emit(Event)``), or None. Never raises; a failed emit is swallowed."""
    if host is None:
        return None
    # Platform-style emit(event_type, payload)
    emit = getattr(host, "emit", None)
    if callable(emit):
        try:
            import inspect
            params = inspect.signature(emit).parameters
        except (TypeError, ValueError):
            params = {}
        if len(params) >= 2:
            def _emit_platform(event_type: str, payload: dict) -> None:
                try:
                    host.emit(event_type, payload, source="group_soc")
                except TypeError:
                    try:
                        host.emit(event_type, payload)
                    except Exception:
                        logger.debug("soc platform emit failed", exc_info=True)
                except Exception:
                    logger.debug("soc platform emit failed", exc_info=True)
            return _emit_platform

        # raw EventBus.emit(Event)
        def _emit_bus(event_type: str, payload: dict) -> None:
            try:
                from workflows.models import Event
                host.emit(Event(type=event_type, payload=payload or {}, source="group_soc"))
            except Exception:
                logger.debug("soc bus emit failed", exc_info=True)
        return _emit_bus
    return None


__all__ = [
    "SocAlertCreated", "SocIncidentCreated", "bind_emit",
    "SOC_EVENT_RECORDED", "SOC_SIGNAL_CREATED", "SOC_ALERT_CREATED",
    "SOC_ALERT_ESCALATED", "SOC_CASE_CREATED", "SOC_INCIDENT_CREATED",
    "SOC_INCIDENT_RESOLVED",
]
