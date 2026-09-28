"""
news_intelligence.telegram.callbacks — inline-callback dispatch for /news navigation.

Parses ``news:<type>:<tab>:<subject>`` callback data and renders the requested tab of a
profile using the pure ``NewsCommandService``/engine. The ``dispatch`` function is pure
(returns text) and unit-testable; ``make_handler`` wraps it for python-telegram-bot.
"""

from __future__ import annotations

import logging
from typing import Optional

from .commands import NewsCommandService, _svc

logger = logging.getLogger("modbot.news.telegram.callbacks")

try:
    from telegram.ext import CallbackQueryHandler
    HAVE_PTB = True
except Exception:  # pragma: no cover
    CallbackQueryHandler = None
    HAVE_PTB = False


def dispatch(data: str, *, service: Optional[NewsCommandService] = None) -> str:
    """Render the text for a callback data string. Pure."""
    svc = service or _svc()
    parts = (data or "").split(":")
    if not parts or parts[0] != "news":
        return ""
    kind = parts[1] if len(parts) > 1 else ""
    tab = parts[2] if len(parts) > 2 else "overview"
    subject = ":".join(parts[3:]) if len(parts) > 3 else ""

    if kind == "brief":
        return svc.cmd_news_brief([tab])
    if kind == "fmt" and tab == "graph":
        rest = subject.split(":", 1)
        st = rest[0] if rest else "news"
        subj = rest[1] if len(rest) > 1 else ""
        return svc.cmd_news_graph([f"kind={st}", subj])

    # profile tabs
    eng = svc.engine
    try:
        if kind == "actor":
            d = eng.actor_report(subject, fmt="dict")
        elif kind == "malware":
            d = eng.malware_report(subject, fmt="dict")
        elif kind == "cve":
            d = eng.cve_report(subject, fmt="dict")
        elif kind == "campaign":
            d = eng.campaign_report(subject, fmt="dict")
        else:
            return svc.cmd_news([])
    except Exception as exc:  # pragma: no cover
        return f"Error: {exc}"

    if tab == "timeline":
        tl = eng.timeline(subject, kind=kind)
        lines = [f"🕘 Timeline — {subject} ({tl.get('count', 0)} entries)"]
        for e in tl.get("entries", [])[-15:]:
            lines.append(f"• {e.get('iso','')}: {e.get('title','')[:70]}")
        return "\n".join(lines)
    if tab == "evidence":
        for sec in d.get("sections", []):
            if "Evidence" in sec.get("title", "") or "Source" in sec.get("title", ""):
                ev = sec.get("evidence", [])[:12]
                return "📎 Evidence:\n" + "\n".join(
                    f"• {x.get('title','') or x.get('provider','')}" for x in ev)
        return "No evidence section."
    # default: render the matching section or the whole profile
    return svc._render_profile(d, "📄")


def make_handler(service: Optional[NewsCommandService] = None):
    if not HAVE_PTB:  # pragma: no cover
        return None

    async def handler(update, context):  # pragma: no cover - needs bot
        query = getattr(update, "callback_query", None)
        if query is None:
            return
        await query.answer()
        text = dispatch(query.data or "", service=service)
        if text:
            try:
                await query.edit_message_text(text, parse_mode="Markdown",
                                              disable_web_page_preview=True)
            except Exception:
                await query.message.reply_text(text, parse_mode="Markdown",
                                               disable_web_page_preview=True)

    return CallbackQueryHandler(handler, pattern=r"^news:")


__all__ = ["dispatch", "make_handler", "HAVE_PTB"]
