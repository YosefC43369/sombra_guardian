"""
group_soc/correlation/entity.py — shared-entity correlation.

Links events that share a non-user entity (a domain, URL, IP or hash) across several
actors within the window — e.g. the same domain pushed by different accounts. Scans a
bounded slice of recent events (LIMIT-capped) and counts distinct actors per shared
entity. A watchlist hit on the entity raises confidence.
"""

from __future__ import annotations

from typing import Optional

from ..models.event import SecurityEvent
from ..models.signal import SecuritySignal
from ..models.entity import EntityRef
from ..models.severity import RiskDimensions
from ..constants import CorrelationKind, AnalyticState, EntityKind
from ..util import now
from .base import window_start


_JOINABLE = {EntityKind.DOMAIN.value, EntityKind.URL.value,
             EntityKind.IP.value, EntityKind.HASH.value}


class EntityCorrelator:
    name = "entity"

    def correlate(self, event: SecurityEvent, storage, config) -> Optional[SecuritySignal]:
        targets = [e for e in event.entities if e.kind in _JOINABLE]
        if not targets:
            return None
        since = window_start(config)
        recent = storage.events.recent_in_window(
            event.chat_id, since, limit=int(getattr(config, "correlation_max_buffer", 512)))
        threshold = 2

        for target in targets:
            actors = set()
            ev_ids = []
            for ev in recent:
                if any(e.ident == target.ident for e in ev.entities):
                    ev_ids.append(ev.event_id)
                    if ev.actor_hash:
                        actors.add(ev.actor_hash)
            if len(actors) < threshold:
                continue
            watch = storage.watchlist.match(event.chat_id, target.kind, target.key) is not None
            conf = min(0.95, (0.6 if watch else 0.5) + 0.1 * (len(actors) - threshold))
            dims = RiskDimensions(
                severity=0.7 if watch else 0.5, confidence=conf,
                impact=min(1.0, 0.4 + 0.1 * len(actors)), urgency=0.6,
                exposure=0.6, persistence=0.5)
            return SecuritySignal(
                signal_type=CorrelationKind.ENTITY.value,
                producer="correlation:entity:shared_indicator",
                chat_id=event.chat_id,
                title="Same indicator shared by multiple actors",
                summary=(f"{len(actors)} actors referenced the same "
                         f"{target.kind} in the window"
                         + (" (on watchlist)" if watch else "") + "."),
                dimensions=dims,
                analytic_state=AnalyticState.SUSPICIOUS.value,
                event_ids=ev_ids[:50],
                entities=[target],
                dedup_key=f"{event.chat_id}:entity:{target.ident}",
                metadata={"distinct_actors": len(actors), "watchlisted": watch},
            )
        return None
