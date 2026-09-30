"""
purple_range/integrations/soc_bridge.py — replay synthetic telemetry onto the event bus.

Opt-in (``PURPLE_RANGE_SOC_BRIDGE_ENABLED``, default OFF). When enabled, it publishes the
generated synthetic telemetry as ``purple_range.telemetry`` events on the existing workflow
event bus, so a detection-tuning subscriber (or a future SIEM/SOC detector) can consume
them. Every payload is tagged ``source=purple_range_sim`` and carries the exercise linkage.

It does NOT inject into the group_soc alert pipeline or fabricate detections — that would
pollute real data. It only makes the synthetic stream available, clearly labelled.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from ..models import TelemetryEvent
from ..constants import SYNTHETIC_SOURCE
from ..exceptions import IntegrationError

logger = logging.getLogger("modbot.purple_range.soc_bridge")

BUS_EVENT_TYPE = "purple_range.telemetry"


class SocBridge:
    def __init__(self, config, emit=None):
        self.config = config
        self.emit = emit    # callable(event_type, payload) or None

    @property
    def enabled(self) -> bool:
        return bool(self.config.soc_bridge_enabled and self.emit is not None)

    def replay(self, chat_id: int, exercise_id: Optional[int],
               events: List[TelemetryEvent]) -> int:
        """Publish synthetic telemetry events. Returns the number emitted (0 if disabled)."""
        if not self.enabled:
            return 0
        n = 0
        for ev in events:
            payload = {
                "source": SYNTHETIC_SOURCE,
                "synthetic": True,
                "chat_id": int(chat_id),
                "exercise_id": exercise_id,
                "event_type": ev.event_type,
                "technique_id": ev.technique_id,
                "seq": ev.seq,
                "fields": ev.fields,
            }
            try:
                self.emit(BUS_EVENT_TYPE, payload)
                n += 1
            except Exception:
                logger.debug("purple_range: telemetry emit failed", exc_info=True)
        return n
