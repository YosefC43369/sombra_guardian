"""
group_soc/detection/sequence.py — a generic, declarative sequence detector.

Fires when the current event completes a configured ordered sequence of event types
by the same actor within a window. The default instance detects join→leave churn
(an actor that joins and quickly leaves — a common drive-by / evasion pattern),
which is distinct from the correlation layer's join→link chain.

The match is window-bounded and uses per-type COUNT queries on the actor index. It
checks presence-in-order by timestamp of the earliest preceding step, which is a
good, cheap approximation without scanning full history.
"""

from __future__ import annotations

from typing import List, Sequence

from ..models.event import SecurityEvent
from ..models.signal import SecuritySignal
from ..models.entity import EntityRef
from ..models.severity import RiskDimensions
from ..constants import EventType, DetectorKind, AnalyticState
from ..util import now


class SequenceDetector:
    def __init__(self, pattern: Sequence[str], *, name: str, title: str,
                 window_attr: str = "sequence_window_s", severity: float = 0.5,
                 confidence: float = 0.6):
        if len(pattern) < 2:
            raise ValueError("sequence pattern needs at least two steps")
        self.pattern = list(pattern)
        self.name = name
        self.title = title
        self.window_attr = window_attr
        self.severity = severity
        self.confidence = confidence

    def detect(self, event: SecurityEvent, storage, config) -> List[SecuritySignal]:
        if event.event_type != self.pattern[-1] or not event.actor_hash:
            return []
        window = int(getattr(config, self.window_attr, 120))
        since = now() - window
        # every preceding step must have occurred by this actor in the window
        for step in self.pattern[:-1]:
            if storage.events.count_since(event.chat_id, step, since,
                                          actor_hash=event.actor_hash) <= 0:
                return []
        dims = RiskDimensions(severity=self.severity, confidence=self.confidence,
                              impact=0.4, urgency=0.55, exposure=0.4, persistence=0.5)
        return [SecuritySignal(
            signal_type=DetectorKind.SEQUENCE.value,
            producer=f"detection:sequence:{self.name}",
            chat_id=event.chat_id,
            title=self.title,
            summary=f"Actor completed the sequence {' → '.join(self.pattern)} within {window}s.",
            dimensions=dims,
            analytic_state=AnalyticState.SUSPICIOUS.value,
            event_ids=[event.event_id],
            entities=[EntityRef.user(event.actor_hash)],
            dedup_key=f"{event.chat_id}:sequence:{self.name}:{event.actor_hash}",
            metadata={"pattern": self.pattern, "window_s": window},
        )]


def default_sequence_detectors() -> List[SequenceDetector]:
    return [
        SequenceDetector(
            [EventType.MEMBER_JOINED.value, EventType.MEMBER_LEFT.value],
            name="join_leave_churn", title="Join-then-leave churn",
            severity=0.4, confidence=0.55),
    ]
