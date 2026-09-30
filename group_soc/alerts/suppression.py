"""
group_soc/alerts/suppression.py — cooldown suppression.

After an alert for a condition is resolved/closed, a fresh identical signal inside the
cooldown window should not immediately open a brand-new alert (alert fatigue). This
checks whether a terminal alert with the same dedup_key was resolved within the
cooldown. Suppression is recorded (audited), not silent.
"""

from __future__ import annotations

from typing import Optional

from ..constants import TERMINAL_ALERT_STATUSES
from ..util import now


def recently_resolved_within(store, chat_id: int, dedup_key: str,
                             cooldown_s: int) -> bool:
    """True if a terminal alert with this dedup_key was resolved/closed within
    ``cooldown_s`` — meaning a new alert should be suppressed."""
    if cooldown_s <= 0:
        return False
    placeholders = ", ".join("?" for _ in TERMINAL_ALERT_STATUSES)
    params = [int(chat_id), dedup_key] + list(TERMINAL_ALERT_STATUSES)
    row = store._get_one(
        f"SELECT resolved_at, updated_at FROM soc_alerts WHERE chat_id=? AND dedup_key=? "
        f"AND status IN ({placeholders}) ORDER BY updated_at DESC LIMIT 1", params)
    if not row:
        return False
    when = row.get("resolved_at") or row.get("updated_at") or 0
    return (now() - int(when)) < int(cooldown_s)
