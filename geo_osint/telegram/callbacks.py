"""
geo_osint.telegram.callbacks — inline-button callback handling (spec §45).

Parses the ``callback_data`` emitted by :mod:`geo_osint.telegram.keyboards`
(``geo:<action>:<...>:<entity>``) and dispatches to :class:`GeoCommandService`. The
parser is pure/testable; the async handler is a thin PTB adapter.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from .commands import GeoCommandService, _svc

logger = logging.getLogger("modbot.geo_osint.telegram.cb")

try:
    from telegram.ext import CallbackQueryHandler
    HAVE_PTB = True
except Exception:  # pragma: no cover
    CallbackQueryHandler = None
    HAVE_PTB = False


@dataclass
class Callback:
    action: str
    entity: str
    fmt: str = ""


def parse_callback(data: str) -> Optional[Callback]:
    if not data or not data.startswith("geo:"):
        return None
    parts = data.split(":", 3)
    if len(parts) < 3:
        return None
    action = parts[1]
    if action == "fmt" and len(parts) == 4:
        return Callback(action="report", entity=parts[3], fmt=parts[2])
    return Callback(action=action, entity=parts[-1])


async def dispatch(cb: Callback, service: Optional[GeoCommandService] = None) -> str:
    svc = service or _svc()
    if cb.action == "map":
        return await svc.map(cb.entity)
    if cb.action == "nearby":
        return await svc.nearby(cb.entity)
    if cb.action == "reverse":
        return await svc.reversegeo(cb.entity)
    if cb.action == "report":
        return await svc.geo_report(cb.entity)
    return await svc.geo(cb.entity)


async def on_callback(update, context) -> None:  # pragma: no cover - needs bot
    query = update.callback_query
    await query.answer()
    cb = parse_callback(query.data or "")
    if cb is None:
        return
    text = await dispatch(cb)
    await query.message.reply_text(text, parse_mode="Markdown",
                                   disable_web_page_preview=True)


def build_handler():
    if not HAVE_PTB:
        raise RuntimeError("python-telegram-bot is required")
    return CallbackQueryHandler(on_callback, pattern=r"^geo:")
