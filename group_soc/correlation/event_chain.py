"""
group_soc/correlation/event_chain.py — ordered-sequence correlation.

Detects the classic "fresh account drops a link" chain:

    MEMBER_JOINED  →  (within sequence window)  →  MESSAGE with URL / IOC_MATCHED

A new member posting an external link or a matched IOC shortly after joining is a
well-known scam/spam pattern. This correlates the current link/IOC event back to the
actor's recent join, tying them under one correlation for the timeline.
"""

from __future__ import annotations

from typing import Optional

from ..models.event import SecurityEvent
from ..models.signal import SecuritySignal
from ..models.entity import EntityRef
from ..models.severity import RiskDimensions
from ..constants import EventType, CorrelationKind, AnalyticState, EntityKind
from ..util import now


_LINKISH_TYPES = {EventType.MESSAGE_CREATED.value, EventType.IOC_MATCHED.value}


class SequenceCorrelator:
    name = "sequence"

    def correlate(self, event: SecurityEvent, storage, config) -> Optional[SecuritySignal]:
        if event.event_type not in _LINKISH_TYPES or not event.actor_hash:
            return None
        has_link = event.event_type == EventType.IOC_MATCHED.value or any(
            e.kind in (EntityKind.URL.value, EntityKind.DOMAIN.value) for e in event.entities)
        if not has_link:
            return None

        window = int(getattr(config, "sequence_window_s", 120))
        since = now() - window
        joined = storage.events.count_since(
            event.chat_id, EventType.MEMBER_JOINED.value, since, actor_hash=event.actor_hash)
        if joined <= 0:
            return None

        dims = RiskDimensions(severity=0.6, confidence=0.65, impact=0.5,
                              urgency=0.7, exposure=0.6, persistence=0.4)
        return SecuritySignal(
            signal_type=CorrelationKind.SEQUENCE.value,
            producer="correlation:sequence:join_then_link",
            chat_id=event.chat_id,
            title="New member posted a link/IOC shortly after joining",
            summary=(f"Actor joined then posted an external link/IOC within {window}s "
                     f"— a common scam/spam sequence."),
            dimensions=dims,
            analytic_state=AnalyticState.SUSPICIOUS.value,
            event_ids=[event.event_id],
            entities=[EntityRef.user(event.actor_hash)],
            dedup_key=f"{event.chat_id}:seq:join_link:{event.actor_hash}",
            metadata={"window_s": window},
        )
