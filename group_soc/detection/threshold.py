"""
group_soc/detection/threshold.py — rate/threshold detectors.

JoinBurstDetector       many joins in a short window → possible raid.
RepeatedContentDetector one actor posting the same content repeatedly → flood/spam.

Both are single bounded COUNT queries on migration-0006 indexes; nothing scans.
"""

from __future__ import annotations

from typing import List

from ..models.event import SecurityEvent
from ..models.signal import SecuritySignal
from ..models.entity import EntityRef
from ..models.severity import RiskDimensions
from ..constants import EventType, DetectorKind, AnalyticState
from ..util import now


class JoinBurstDetector:
    name = "join_burst"

    def detect(self, event: SecurityEvent, storage, config) -> List[SecuritySignal]:
        if event.event_type != EventType.MEMBER_JOINED.value:
            return []
        window = int(getattr(config, "join_burst_window_s", 60))
        threshold = int(getattr(config, "join_burst_threshold", 5))
        since = now() - window
        joins = storage.events.count_since(event.chat_id, EventType.MEMBER_JOINED.value, since)
        if joins < threshold:
            return []
        conf = min(0.95, 0.5 + 0.05 * (joins - threshold))
        dims = RiskDimensions(severity=0.7, confidence=conf,
                              impact=min(1.0, 0.4 + 0.05 * joins), urgency=0.85,
                              exposure=0.7, persistence=0.5)
        return [SecuritySignal(
            signal_type=DetectorKind.THRESHOLD.value,
            producer="detection:threshold:join_burst",
            chat_id=event.chat_id,
            title="Join burst (possible raid)",
            summary=f"{joins} members joined within {window}s (threshold {threshold}).",
            dimensions=dims,
            analytic_state=AnalyticState.SUSPICIOUS.value,
            event_ids=[event.event_id],
            dedup_key=f"{event.chat_id}:threshold:join_burst",
            metadata={"joins": joins, "window_s": window, "threshold": threshold},
        )]


class RepeatedContentDetector:
    name = "repeated_content"

    def detect(self, event: SecurityEvent, storage, config) -> List[SecuritySignal]:
        if event.event_type != EventType.MESSAGE_CREATED.value or not event.content_hash \
                or not event.actor_hash:
            return []
        window = int(getattr(config, "similar_message_window_s", 120))
        threshold = int(getattr(config, "similar_message_threshold", 3))
        since = now() - window
        # same content by *this* actor (flood), as opposed to campaign (many actors)
        count = storage.events.count_since(
            event.chat_id, EventType.MESSAGE_CREATED.value, since, actor_hash=event.actor_hash)
        same = storage.events.count_by_content_hash(event.chat_id, event.content_hash, since)
        # require both a personal flood and that the content is the repeated one
        if same < threshold or count < threshold:
            return []
        conf = min(0.9, 0.5 + 0.1 * (same - threshold))
        dims = RiskDimensions(severity=0.5, confidence=conf, impact=0.4,
                              urgency=0.6, exposure=0.4, persistence=0.6)
        return [SecuritySignal(
            signal_type=DetectorKind.THRESHOLD.value,
            producer="detection:threshold:repeated_content",
            chat_id=event.chat_id,
            title="Repeated identical messages from one actor",
            summary=f"An actor posted the same content {same} times within {window}s.",
            dimensions=dims,
            analytic_state=AnalyticState.SUSPICIOUS.value,
            event_ids=[event.event_id],
            entities=[EntityRef.user(event.actor_hash)],
            dedup_key=f"{event.chat_id}:threshold:repeat:{event.actor_hash}:{event.content_hash}",
            metadata={"count": same, "window_s": window},
        )]
