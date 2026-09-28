"""
threat_actor_intelligence.telegram.callbacks — inline-button callback handling.

Decodes ``tai:<action>:<id>`` callback data and dispatches to the command
service to render the pivot view (timeline, graph, malware list, campaigns,
report). ``dispatch`` is pure (returns the reply text) and unit-tested; the async
``make_handler`` wraps it for python-telegram-bot.
"""

from __future__ import annotations

import logging
from typing import Optional

from ..engine import ThreatActorIntelligenceEngine
from .keyboards import decode
from .commands import TAICommandService, _svc

logger = logging.getLogger("modbot.tai.telegram.callbacks")

try:
    from telegram.ext import CallbackQueryHandler
    HAVE_PTB = True
except Exception:  # pragma: no cover
    CallbackQueryHandler = None
    HAVE_PTB = False


def dispatch(action: str, obj_id: str, *,
             service: Optional[TAICommandService] = None) -> str:
    svc = service or _svc()
    eng = svc.engine
    if action == "timeline":
        return svc.cmd_timeline([obj_id])
    if action == "ctimeline":
        return svc.cmd_timeline([obj_id])
    if action == "graph":
        g = eng.actor_graph(obj_id, fmt="dot")
        return g or "no graph"
    if action == "cgraph":
        g = eng.campaign_graph(obj_id, fmt="dot")
        return g or "no graph"
    if action == "malware":
        actor = eng.resolve_actor(obj_id)
        if not actor:
            return "actor not found"
        fams = [eng.store.get_family(m) for m in actor.malware_families]
        names = [f.family_name for f in fams if f]
        return "🦠 Malware: " + (", ".join(names) or "none documented")
    if action == "campaigns":
        actor = eng.resolve_actor(obj_id)
        if not actor:
            return "actor not found"
        camps = [eng.store.get_campaign(c) for c in actor.campaigns]
        names = [c.campaign_name for c in camps if c]
        return "📁 Campaigns: " + (", ".join(names) or "none documented")
    if action in ("report", "creport", "mreport"):
        builder = {"report": eng.actor_report, "creport": eng.campaign_report,
                   "mreport": eng.malware_report}[action]
        out = builder(obj_id, fmt="markdown")
        return out or "not found"
    if action == "iocs":
        return svc.cmd_ioc_report([obj_id])
    if action in ("mactors", "mcampaigns"):
        fam = eng.resolve_family(obj_id)
        if not fam:
            return "family not found"
        if action == "mactors":
            names = [a.canonical_name for a in
                     (eng.store.get_actor(x) for x in fam.actors) if a]
            return "🎯 Actors: " + (", ".join(names) or "none documented")
        names = [c.campaign_name for c in
                 (eng.store.get_campaign(x) for x in fam.campaigns) if c]
        return "📁 Campaigns: " + (", ".join(names) or "none documented")
    return "unknown action"


def make_handler(service: Optional[TAICommandService] = None):  # pragma: no cover
    if not HAVE_PTB:
        return None

    async def handler(update, context):
        query = update.callback_query
        if query is None:
            return
        await query.answer()
        decoded = decode(query.data)
        if decoded is None:
            return
        action, obj_id = decoded
        try:
            text = dispatch(action, obj_id, service=service)
        except Exception as exc:
            logger.exception("tai callback failed")
            text = f"Failed: {exc}"
        await query.message.reply_text(text[:3900], parse_mode="Markdown",
                                       disable_web_page_preview=True)

    return CallbackQueryHandler(handler, pattern=r"^tai:")


__all__ = ["dispatch", "make_handler", "HAVE_PTB"]
