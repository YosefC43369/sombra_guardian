"""
group_soc/timeline/renderer.py — render a timeline to plain text.

Plain text only (no markup, defanged content) so it is safe to send straight into a
Telegram chat. Times render as HH:MM:SS UTC; each entry is one line with a kind icon.
"""

from __future__ import annotations

import time
from typing import List

from ..models.timeline import TimelineEntry

_ICON = {"event": "•", "signal": "◆", "alert": "▲", "case": "■",
         "incident": "★", "note": "✎", "action": "⚙"}


def _hms(ts: int) -> str:
    return time.strftime("%H:%M:%S", time.gmtime(int(ts)))


def render_timeline(entries: List[TimelineEntry], *, header: str = "SECURITY TIMELINE",
                    limit: int = 60) -> str:
    if not entries:
        return f"{header}\n(no entries)"
    lines = [header]
    for e in entries[:limit]:
        icon = _ICON.get(e.kind, "•")
        extra = ""
        if e.kind == "alert" and e.metadata.get("priority"):
            extra = f" [{e.metadata['priority']}]"
        elif e.kind == "event" and e.metadata.get("severity"):
            sev = e.metadata["severity"]
            if sev not in ("info", "low"):
                extra = f" ({sev})"
        lines.append(f"{_hms(e.ts)} {icon} {e.summary}{extra}")
    if len(entries) > limit:
        lines.append(f"… (+{len(entries) - limit} more)")
    return "\n".join(lines)
