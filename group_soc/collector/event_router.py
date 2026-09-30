"""
group_soc/collector/event_router.py — map a bus event type to a collector.

The router is the single place that knows which bus events the SOC ingests and how
to turn each into a RawEvent. It is intentionally table-driven so new sources are
added by registering a collector, never by editing the pipeline.

Only event types the platform actually emits are wired here. Others in the taxonomy
(admin/permission/invite changes) are NOT fabricated: when an upstream module begins
emitting them, register a collector for that type and the SOC ingests it — no other
change needed. That extension point is why the taxonomy is broader than this table.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

from ..constants import (
    BUS_MESSAGE_RECEIVED, BUS_MEMBER_JOINED, BUS_MEMBER_LEFT,
    BUS_DETECTION_TRIGGERED, BUS_RULE_MATCHED, BUS_IOC_MATCHED,
)
from ..normalization.schema import RawEvent
from .message_events import collect_message
from .member_events import collect_member_joined, collect_member_left
from .signal_events import collect_detection, collect_rule_matched, collect_ioc_matched

logger = logging.getLogger("modbot.group_soc.router")

Collector = Callable[..., Optional[RawEvent]]


class EventRouter:
    def __init__(self):
        self._routes: Dict[str, Collector] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        self.register(BUS_MESSAGE_RECEIVED, collect_message)
        self.register(BUS_MEMBER_JOINED, collect_member_joined)
        self.register(BUS_MEMBER_LEFT, collect_member_left)
        self.register(BUS_DETECTION_TRIGGERED, collect_detection)
        self.register(BUS_RULE_MATCHED, collect_rule_matched)
        self.register(BUS_IOC_MATCHED, collect_ioc_matched)

    def register(self, bus_event_type: str, collector: Collector) -> None:
        self._routes[bus_event_type] = collector

    def handles(self, bus_event_type: str) -> bool:
        return bus_event_type in self._routes

    def subscribed_types(self):
        return tuple(self._routes.keys())

    def route(self, bus_event_type: str, payload: Dict[str, Any], *,
              correlation_id: Optional[str] = None) -> Optional[RawEvent]:
        collector = self._routes.get(bus_event_type)
        if collector is None:
            return None
        try:
            return collector(payload, correlation_id=correlation_id)
        except Exception:
            logger.exception("collector failed for %s", bus_event_type)
            return None
