"""
group_soc/correlation/behavioral.py — per-actor multi-signal correlation.

Links an actor who is triggering *several kinds* of concerning events in a short
window (e.g. a detection hit AND a rule match AND an IOC), which together read as
riskier than any one alone. Uses bounded per-type counts on the actor index.
"""

from __future__ import annotations

from typing import Optional

from ..models.event import SecurityEvent
from ..models.signal import SecuritySignal
from ..models.entity import EntityRef
from ..models.severity import RiskDimensions
from ..constants import EventType, CorrelationKind, AnalyticState
from ..util import now
from .base import window_start


_CONCERNING = (
    EventType.DETECTION_TRIGGERED.value,
    EventType.SECURITY_RULE_TRIGGERED.value,
    EventType.IOC_MATCHED.value,
)


class BehavioralCorrelator:
    name = "behavioral"

    def correlate(self, event: SecurityEvent, storage, config) -> Optional[SecuritySignal]:
        if event.event_type not in _CONCERNING or not event.actor_hash:
            return None
        since = window_start(config)
        distinct_types = 0
        total = 0
        for et in _CONCERNING:
            c = storage.events.count_since(event.chat_id, et, since, actor_hash=event.actor_hash)
            if c > 0:
                distinct_types += 1
                total += c
        # need at least two *different* concerning signal types from the same actor
        if distinct_types < 2:
            return None
        conf = min(0.9, 0.55 + 0.1 * distinct_types)
        dims = RiskDimensions(severity=0.65, confidence=conf, impact=0.55,
                              urgency=0.6, exposure=0.4, persistence=0.6)
        return SecuritySignal(
            signal_type=CorrelationKind.BEHAVIORAL.value,
            producer="correlation:behavioral:multi_signal_actor",
            chat_id=event.chat_id,
            title="Actor triggering multiple concerning signal types",
            summary=(f"One actor produced {distinct_types} distinct concerning signal "
                     f"types ({total} events) in the correlation window."),
            dimensions=dims,
            analytic_state=AnalyticState.SUSPICIOUS.value,
            event_ids=[event.event_id],
            entities=[EntityRef.user(event.actor_hash)],
            dedup_key=f"{event.chat_id}:behavioral:{event.actor_hash}",
            metadata={"distinct_types": distinct_types, "total": total},
        )
