"""group_soc/commands/reports.py — /soc report handlers."""

from __future__ import annotations

from typing import List, Optional

from ..reporting import format_executive, format_technical


def handle(rt, chat_id: int, actor_hash: Optional[str], args: List[str]) -> str:
    kind = (args[0].lower() if args else "daily")

    if kind == "daily":
        return format_executive(rt.reports.daily(chat_id))
    if kind == "weekly":
        return format_executive(rt.reports.weekly(chat_id))
    if kind == "executive":
        return format_executive(rt.reports.daily(chat_id))
    if kind == "technical":
        return format_technical(rt.reports.daily(chat_id))
    if kind == "incident" and len(args) >= 2:
        inc = rt.incidents.get(args[1])
        if inc is None:
            return f"❌ incident not found: {args[1]}"
        from ..stories import format_story
        return format_story(rt.story.for_incident(inc))

    return "ใช้งาน: /soc report [daily | weekly | executive | technical | incident <id>]"
