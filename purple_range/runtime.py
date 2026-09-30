"""
purple_range/runtime.py — per-DB service cache + event-bus emit binding.

Mirrors the blueteam/group_soc idiom: one service per database, cached via
``get_runtime``. The plugin binds ``emit`` to the workflow event bus so the (opt-in)
telemetry replay can publish.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from .config import PurpleRangeConfig, get_config
from .service import PurpleRangeService

logger = logging.getLogger("modbot.purple_range.runtime")


def bind_emit(bus):
    """Return emit(event_type, payload) bound to a workflow EventBus, or None."""
    if bus is None or not hasattr(bus, "emit"):
        return None

    def _emit(event_type: str, payload: dict) -> None:
        try:
            from workflows.models import Event
            bus.emit(Event(type=event_type, payload=payload or {}, source="purple_range"))
        except Exception:
            logger.debug("purple_range emit failed for %s", event_type, exc_info=True)
    return _emit


_SERVICES: Dict[str, PurpleRangeService] = {}


def get_runtime(db_path: str = "bot.db", *, config: Optional[PurpleRangeConfig] = None,
                emit=None) -> PurpleRangeService:
    svc = _SERVICES.get(db_path)
    if svc is None:
        svc = PurpleRangeService(db_path, config=config, emit=emit)
        _SERVICES[db_path] = svc
    elif emit is not None:
        svc.set_emit(emit)
    return svc


def reset_runtimes() -> None:
    _SERVICES.clear()
