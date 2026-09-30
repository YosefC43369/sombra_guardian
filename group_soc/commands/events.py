"""group_soc/commands/events.py — /soc events handlers."""

from __future__ import annotations

import time
from typing import List, Optional

from .formatting import bullet_list


def _line(ev) -> str:
    when = time.strftime("%m-%d %H:%M", time.gmtime(ev.ts))
    return f"{when}  {ev.event_type}  (sev={ev.severity}, src={ev.source})"


def handle(rt, chat_id: int, actor_hash: Optional[str], args: List[str]) -> str:
    sub = (args[0].lower() if args else "recent")

    if sub in ("recent", "list", ""):
        evs = rt.storage.events.recent(chat_id, limit=20)
        return bullet_list(f"📥 Recent events ({len(evs)})",
                           [_line(e) for e in evs], empty="No events recorded.")

    if sub == "search" and len(args) >= 2:
        etype = args[1]
        evs = rt.storage.events.search(chat_id, event_type=etype, limit=20)
        return bullet_list(f"🔎 Events of type '{etype}' ({len(evs)})",
                           [_line(e) for e in evs], empty="No matching events.")

    if sub == "timeline" and len(args) >= 2:
        from ..timeline import render_timeline
        entries = rt.timeline.build_for_correlation(args[1])
        return render_timeline(entries, header=f"TIMELINE corr={args[1]}")

    # treat as event id
    ev = rt.storage.events.get(args[0])
    if ev is None:
        return "ใช้งาน: /soc events [recent | search <type> | timeline <correlation_id> | <event_id>]"
    return "\n".join([
        f"Event {ev.event_id}",
        f"  type:   {ev.event_type}",
        f"  chat:   {ev.chat_id}",
        f"  source: {ev.source}",
        f"  sev:    {ev.severity}  conf={ev.confidence}",
        f"  state:  {ev.analytic_state}",
        f"  corr:   {ev.correlation_id}",
        f"  entities: {', '.join(e.ident for e in ev.entities) or '(none)'}",
    ])
