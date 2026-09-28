"""
geo_osint.telegram.keyboards — inline keyboards for the Geo-OSINT commands (spec §45).

Pure builders returning ``InlineKeyboardMarkup`` (or a plain button spec when
python-telegram-bot is absent, for testing). The callbacks module consumes the
``callback_data`` these produce.
"""

from __future__ import annotations

from typing import Any, List, Tuple

try:
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    HAVE_PTB = True
except Exception:  # pragma: no cover
    InlineKeyboardButton = None
    InlineKeyboardMarkup = None
    HAVE_PTB = False


def _markup(rows: List[List[Tuple[str, str]]]) -> Any:
    """rows of (label, callback_data) -> InlineKeyboardMarkup, or the raw spec."""
    if not HAVE_PTB:
        return rows
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton(label, callback_data=data) for label, data in row]
         for row in rows])


def geo_actions(entity: str) -> Any:
    """Follow-up actions for a /geo result."""
    e = entity[:48]
    return _markup([
        [("🗺 Map", f"geo:map:{e}"), ("📡 Nearby", f"geo:nearby:{e}")],
        [("📄 Report", f"geo:report:{e}"), ("🧭 Reverse", f"geo:reverse:{e}")],
    ])


def report_formats(entity: str) -> Any:
    e = entity[:48]
    return _markup([
        [("Markdown", f"geo:fmt:md:{e}"), ("JSON", f"geo:fmt:json:{e}")],
        [("HTML", f"geo:fmt:html:{e}"), ("CSV", f"geo:fmt:csv:{e}")],
    ])
