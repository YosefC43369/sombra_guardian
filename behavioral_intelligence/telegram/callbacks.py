"""
behavioral_intelligence.telegram.callbacks — inline-button callback handling.

Handles taps on the section / format keyboards: decodes the callback data, runs
the matching service method (re-authorizing every time — a button press is not a
standing grant), and edits the message with the result. ``python-telegram-bot``
is imported defensively; the dispatch logic is a plain function that can be unit
tested with a stub service.
"""

from __future__ import annotations

import logging
from typing import Optional

from .keyboards import decode
from .commands import BehaviorCommandService

logger = logging.getLogger("modbot.behavioral.telegram.cb")

try:
    from telegram.ext import CallbackQueryHandler
    HAVE_PTB = True
except Exception:  # pragma: no cover
    CallbackQueryHandler = None
    HAVE_PTB = False

_SECTION_ACTIONS = {"activity", "heatmap", "timeline", "languages", "topics",
                    "hashtags", "domains", "interactions", "anomalies",
                    "changes", "baseline"}


def dispatch(service: BehaviorCommandService, data: str, actor: str = "") -> str:
    """Pure dispatch: map callback data to rendered text. Testable offline."""
    action, target, program = decode(data)
    if not action:
        return "Unrecognised action."
    if action in _SECTION_ACTIONS:
        return service._section(target, program, actor, action)
    if action == "report":
        return service.behavior_report(target, program, actor)
    if action.startswith("fmt_"):
        return service.behavior_report(target, program, actor,
                                       fmt=action[len("fmt_"):])
    return "Unrecognised action."


def make_handler(service: Optional[BehaviorCommandService] = None):
    """Build a CallbackQueryHandler for behavioural inline buttons, or None when
    PTB is unavailable."""
    if not HAVE_PTB or CallbackQueryHandler is None:
        return None
    svc = service or BehaviorCommandService()

    async def _cb(update, context):
        query = update.callback_query
        await query.answer()
        actor = ""
        try:
            actor = str(update.effective_user.id)
        except Exception:
            pass
        text = dispatch(svc, query.data or "", actor)
        try:
            await query.edit_message_text(text[:4096], disable_web_page_preview=True)
        except Exception:
            await query.message.reply_text(text[:4096])

    from .keyboards import CALLBACK_PREFIX
    return CallbackQueryHandler(_cb, pattern=f"^{CALLBACK_PREFIX}\\|")
