"""
group_soc/watchlist/matching.py — match an event's entities against the watchlist.

Complements enrichment: given a SecurityEvent, return the watchlist entries it hits.
Values are already normalized (the normalizer defangs domains/urls and hashes users;
watchlist entries are stored the same way), so matching is exact-key.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..models.event import SecurityEvent
from ..constants import EntityKind


def match_event(event: SecurityEvent, watchlist_store) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for ref in event.entities:
        m = watchlist_store.match(event.chat_id, ref.kind, ref.key)
        if m:
            hits.append(m)
    if event.actor_hash:
        m = watchlist_store.match(event.chat_id, EntityKind.USER.value, event.actor_hash)
        if m:
            hits.append(m)
    return hits
