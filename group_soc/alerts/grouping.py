"""
group_soc/alerts/grouping.py — group related alerts.

Alerts that fire close together (within the group window) are given a shared group_id
so an analyst sees "one situation" rather than a scatter of alerts. Grouping prefers a
shared correlation_id, falling back to time-proximity within the same chat.
"""

from __future__ import annotations

from typing import Optional

from ..util import gen_id, now


def choose_group_id(store, chat_id: int, correlation_id: Optional[str],
                    group_window_s: int) -> str:
    """Return an existing group_id to join, or a fresh one."""
    since = now() - max(1, int(group_window_s))
    # 1) same correlation id in window
    if correlation_id:
        row = store._get_one(
            "SELECT group_id FROM soc_alerts WHERE chat_id=? AND correlation_id=? "
            "AND updated_at>=? AND group_id IS NOT NULL ORDER BY updated_at DESC LIMIT 1",
            (int(chat_id), correlation_id, since))
        if row and row.get("group_id"):
            return row["group_id"]
    # 2) most recent alert in the chat within the window
    row = store._get_one(
        "SELECT group_id FROM soc_alerts WHERE chat_id=? AND updated_at>=? "
        "AND group_id IS NOT NULL ORDER BY updated_at DESC LIMIT 1",
        (int(chat_id), since))
    if row and row.get("group_id"):
        return row["group_id"]
    return gen_id("grp")
