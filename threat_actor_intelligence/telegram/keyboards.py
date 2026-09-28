"""
threat_actor_intelligence.telegram.keyboards — inline keyboards for CTI results.

Small builders for the inline keyboards attached to actor/campaign/malware
replies: pivot buttons (view timeline, graph, malware, campaigns) encoded as
``tai:<action>:<id>`` callback data the callback handler decodes. Imported
defensively so the module works without python-telegram-bot.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

try:
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    HAVE_PTB = True
except Exception:  # pragma: no cover
    InlineKeyboardButton = None
    InlineKeyboardMarkup = None
    HAVE_PTB = False

CALLBACK_PREFIX = "tai"


def encode(action: str, obj_id: str) -> str:
    # Telegram callback_data is limited to 64 bytes; ids are short slugs/hashes.
    return f"{CALLBACK_PREFIX}:{action}:{obj_id}"[:64]


def decode(data: str) -> Optional[Tuple[str, str]]:
    parts = (data or "").split(":", 2)
    if len(parts) != 3 or parts[0] != CALLBACK_PREFIX:
        return None
    return parts[1], parts[2]


def _rows_to_markup(rows: List[List[Tuple[str, str]]]):
    if not HAVE_PTB:  # pragma: no cover
        return rows
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton(text, callback_data=cb) for text, cb in row]
         for row in rows])


def actor_keyboard(actor_id: str):
    return _rows_to_markup([
        [("🕒 Timeline", encode("timeline", actor_id)),
         ("🕸 Graph", encode("graph", actor_id))],
        [("🦠 Malware", encode("malware", actor_id)),
         ("📁 Campaigns", encode("campaigns", actor_id))],
        [("📄 Full report", encode("report", actor_id))],
    ])


def campaign_keyboard(campaign_id: str):
    return _rows_to_markup([
        [("🕒 Timeline", encode("ctimeline", campaign_id)),
         ("🕸 Graph", encode("cgraph", campaign_id))],
        [("🔎 IOCs", encode("iocs", campaign_id)),
         ("📄 Report", encode("creport", campaign_id))],
    ])


def malware_keyboard(family_id: str):
    return _rows_to_markup([
        [("🎯 Actors", encode("mactors", family_id)),
         ("📁 Campaigns", encode("mcampaigns", family_id))],
        [("📄 Report", encode("mreport", family_id))],
    ])


__all__ = ["encode", "decode", "actor_keyboard", "campaign_keyboard",
           "malware_keyboard", "CALLBACK_PREFIX", "HAVE_PTB"]
