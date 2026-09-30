"""
group_soc/normalization/enrichment.py — optional, privacy-preserving enrichment.

Enrichment tags an event with non-identifying context (e.g. "this domain is on the
group's watchlist"). External/threat-intel enrichment is gated by
``SOC_INTEL_ENRICHMENT_ENABLED`` (OFF by default) and goes through the threat_intel
adapter; nothing here calls the network directly, and member data is never sent out.
"""

from __future__ import annotations

import dataclasses
from typing import List

from ..models.event import SecurityEvent
from ..constants import EntityKind


def enrich_with_watchlist(event: SecurityEvent, watchlist_store) -> SecurityEvent:
    """Return a copy of the event with any watchlist hits recorded in context.

    A hit is NOT a verdict — it only marks that a monitored target was involved,
    which the prioritization layer may weight. Never raises."""
    if watchlist_store is None:
        return event
    hits: List[dict] = []
    try:
        for ref in event.entities:
            match = watchlist_store.match(event.chat_id, ref.kind, ref.key)
            if match:
                hits.append({"kind": ref.kind, "value": ref.key,
                             "severity": match.get("severity", "medium")})
        # actor watch (by hash)
        if event.actor_hash:
            m = watchlist_store.match(event.chat_id, EntityKind.USER.value, event.actor_hash)
            if m:
                hits.append({"kind": EntityKind.USER.value, "value": event.actor_hash,
                             "severity": m.get("severity", "medium")})
    except Exception:
        return event
    if not hits:
        return event
    context = dict(event.context)
    context["watchlist_hits"] = hits
    return dataclasses.replace(event, context=context)
