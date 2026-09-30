"""
group_soc/investigation/evidence_graph.py — pivots for an investigation.

Given a starting point (actor, entity or correlation), return the related records an
analyst would want to see next. All pivots are bounded/windowed reads on the SOC
stores; nothing scans unbounded history.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..models.event import SecurityEvent
from ..util import now


def pivot_by_actor(storage, chat_id: int, actor_hash: str,
                   window_s: int = 86400, limit: int = 50) -> List[SecurityEvent]:
    return storage.events.search(chat_id, actor_hash=actor_hash,
                                 since_ts=now() - window_s, limit=limit)


def pivot_by_entity(storage, chat_id: int, kind: str, key: str,
                    window_s: int = 86400, limit: int = 200) -> List[SecurityEvent]:
    ident = f"{kind}:{key}"
    out: List[SecurityEvent] = []
    for ev in storage.events.recent_in_window(chat_id, now() - window_s, limit=limit):
        if any(e.ident == ident for e in ev.entities):
            out.append(ev)
    return out


def pivot_by_correlation(storage, correlation_id: str) -> Dict[str, List[Any]]:
    return {
        "events": storage.events.by_correlation(correlation_id),
        "signals": storage.signals.by_correlation(correlation_id),
    }


def related_alerts(storage, chat_id: int, correlation_id: str) -> List[Any]:
    from ..models.alert import Alert
    rows = storage.alerts._get_many(
        "SELECT * FROM soc_alerts WHERE chat_id=? AND correlation_id=? "
        "ORDER BY created_at ASC LIMIT 100", (int(chat_id), correlation_id))
    return [Alert.from_row(r) for r in rows]
