"""
group_soc/correlation/clustering.py — coordinated-content (campaign) clustering.

Detects the same message content posted by several *distinct* actors inside a short
window — a strong indicator of a coordinated posting campaign (copy-paste raids,
promo spam rings). Uses the content_hash index and a DISTINCT-actor count, so it is
one bounded query, not a scan.
"""

from __future__ import annotations

from typing import Optional

from ..models.event import SecurityEvent
from ..models.signal import SecuritySignal
from ..models.entity import EntityRef
from ..models.severity import RiskDimensions
from ..constants import EventType, CorrelationKind, AnalyticState, EntityKind
from ..util import now
from .base import Correlator


class CampaignClusterer:
    name = "campaign"

    def correlate(self, event: SecurityEvent, storage, config) -> Optional[SecuritySignal]:
        if event.event_type != EventType.MESSAGE_CREATED.value or not event.content_hash:
            return None
        window = int(getattr(config, "similar_message_window_s", 120))
        since = now() - window
        distinct_actors = storage.events.distinct_actors_by_content_hash(
            event.chat_id, event.content_hash, since)
        threshold = int(getattr(config, "similar_message_threshold", 3))
        if distinct_actors < threshold:
            return None
        total = storage.events.count_by_content_hash(event.chat_id, event.content_hash, since)
        # confidence scales with how far past threshold we are (capped)
        conf = min(0.95, 0.5 + 0.1 * (distinct_actors - threshold))
        dims = RiskDimensions(
            severity=0.6, confidence=conf, impact=min(1.0, 0.3 + 0.1 * distinct_actors),
            urgency=0.7, exposure=0.5, persistence=0.5)
        return SecuritySignal(
            signal_type=CorrelationKind.CAMPAIGN.value,
            producer="correlation:campaign",
            chat_id=event.chat_id,
            title="Coordinated identical messages",
            summary=(f"{distinct_actors} distinct members posted the same content "
                     f"{total} times within {window}s."),
            dimensions=dims,
            analytic_state=AnalyticState.SUSPICIOUS.value,
            event_ids=[event.event_id],
            entities=[EntityRef(EntityKind.PATTERN.value, f"content:{event.content_hash}")],
            dedup_key=f"{event.chat_id}:campaign:{event.content_hash}",
            metadata={"distinct_actors": distinct_actors, "total": total, "window_s": window},
        )
