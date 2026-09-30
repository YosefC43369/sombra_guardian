"""
group_soc/alerts/deduplication.py — fold a repeat signal into an existing alert.

When a signal shares an active alert's dedup_key, we do not create a second alert; we
fold it in: bump the hit counter, extend last_seen, and record the contributing signal
id. This keeps one live alert per recurring condition (rule §9 dedup).
"""

from __future__ import annotations

from typing import Any, Dict

from ..models.alert import Alert
from ..util import now


def fold_changes(alert: Alert, signal_id: str, priority_score: float,
                 priority_band: str) -> Dict[str, Any]:
    """Compute the field changes to fold a repeat signal into ``alert``."""
    signal_ids = list(alert.signal_ids)
    if signal_id and signal_id not in signal_ids:
        signal_ids.append(signal_id)
    t = now()
    return {
        "hit_count": alert.hit_count + 1,
        "last_seen_at": t,
        "updated_at": t,
        "signal_ids": signal_ids,
        # priority can only rise from a fold (repeat = more urgent), never fall
        "priority_score": max(alert.priority_score, priority_score),
        "priority_band": priority_band if priority_score >= alert.priority_score
        else alert.priority_band,
    }
