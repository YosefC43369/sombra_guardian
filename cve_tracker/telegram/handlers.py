"""
cve_tracker.telegram.handlers — thin python-telegram-bot adapters.

Each handler extracts args from the ``(update, context)`` pair, calls the
decoupled :class:`CVECommandService`, and replies (splitting long output with the
project's ``gemini.split_telegram_message``). Admin-only commands go through the
:class:`PermissionChecker`. Telegram/gemini are imported at call time so this
module imports cleanly in a test environment with neither installed.

The handlers are registered by ``plugins/builtin/cve_tracker_suite.py`` through
the platform's ``ctx.register_command`` — this module never imports app.py.
"""

from __future__ import annotations

import logging
from typing import List

from .commands import CVECommandService
from .permissions import PermissionChecker
from . import pagination

logger = logging.getLogger("modbot.cve.handlers")


def _split(text: str) -> List[str]:
    try:
        from gemini import split_telegram_message
        return split_telegram_message(text)
    except Exception:
        # bounded local fallback
        return [text[i:i + 4000] for i in range(0, len(text), 4000)] or [text]


class CVEHandlers:
    def __init__(self, service: CVECommandService, *, permissions: PermissionChecker = None):
        self.service = service
        self.perms = permissions or PermissionChecker()

    # ---------------- reply helpers ----------------

    async def _reply(self, update, text: str, *, keyboard=None):
        msg = getattr(update, "effective_message", None) or getattr(update, "message", None)
        if msg is None:
            return
        chunks = _split(text)
        for i, chunk in enumerate(chunks):
            await msg.reply_text(
                chunk, parse_mode="HTML", disable_web_page_preview=True,
                reply_markup=keyboard if i == len(chunks) - 1 else None)

    @staticmethod
    def _args(context) -> List[str]:
        return list(getattr(context, "args", None) or [])

    @staticmethod
    def _chat_topic(update):
        chat = update.effective_chat
        msg = getattr(update, "effective_message", None)
        topic = getattr(msg, "message_thread_id", None) if msg else None
        return (chat.id if chat else 0), (topic or 0)

    # ---------------- public read commands ----------------

    async def cve(self, update, context):
        args = self._args(context)
        if not args:
            await self._reply(update, self.service.cmd_help())
            return
        await self._reply(update, self.service.cmd_info(args[0]))

    async def cve_info(self, update, context):
        args = self._args(context)
        if not args:
            await self._reply(update, "ระบุ CVE ID เช่น /cve_info CVE-2026-93740")
            return
        await self._reply(update, self.service.cmd_info(args[0]))

    async def cve_search(self, update, context):
        query = " ".join(self._args(context))
        text, token = self.service.cmd_search(query)
        keyboard = None
        if token:
            result = self.service.search.search(query, page=1)
            keyboard = pagination.build_keyboard(result, token)
        await self._reply(update, text, keyboard=keyboard)

    async def cve_ask(self, update, context):
        query = " ".join(self._args(context))
        await self._reply(update, await self.service.cmd_ask(query))

    async def cve_recent(self, update, context):
        await self._reply(update, self.service.cmd_recent())

    async def cve_latest(self, update, context):
        await self._reply(update, self.service.cmd_latest())

    async def cve_history(self, update, context):
        args = self._args(context)
        if not args:
            await self._reply(update, "ระบุ CVE ID เช่น /cve_history CVE-2026-93740")
            return
        await self._reply(update, self.service.cmd_history(args[0]))

    async def cve_kev(self, update, context):
        await self._reply(update, self.service.cmd_kev())

    async def cve_affected(self, update, context):
        await self._reply(update, self.service.cmd_affected(self._args(context)))

    async def cve_digest(self, update, context):
        args = self._args(context)
        window = 7 if (args and args[0].lower() in ("week", "weekly", "7", "สัปดาห์")) else 1
        await self._reply(update, self.service.cmd_digest(window_days=window))

    async def cve_stats(self, update, context):
        await self._reply(update, self.service.cmd_stats())

    async def cve_report(self, update, context):
        args = self._args(context)
        window = 30 if (args and args[0].lower() in ("month", "30", "เดือน")) else 7
        await self._reply(update, self.service.cmd_report(window_days=window))

    # ---------------- subscription commands ----------------

    async def cve_subscribe(self, update, context):
        chat_id, topic = self._chat_topic(update)
        await self._reply(update, self.service.cmd_subscribe(chat_id, topic, self._args(context)))

    async def cve_unsubscribe(self, update, context):
        chat_id, topic = self._chat_topic(update)
        await self._reply(update, self.service.cmd_unsubscribe(chat_id, topic))

    async def cve_preferences(self, update, context):
        chat_id, topic = self._chat_topic(update)
        await self._reply(update, self.service.cmd_preferences(chat_id, topic))

    # ---------------- admin commands ----------------

    async def cve_status(self, update, context):
        await self._reply(update, self.service.cmd_status())

    async def cve_sources(self, update, context):
        await self._reply(update, self.service.cmd_sources())

    async def cve_sync(self, update, context):
        if not await self.perms.is_admin(update, context):
            await self._reply(update, "คำสั่งนี้สำหรับผู้ดูแลระบบเท่านั้น")
            return
        source = (self._args(context) or [""])[0]
        await self._reply(update, await self.service.cmd_sync(source=source))

    async def cve_test(self, update, context):
        if not await self.perms.is_admin(update, context):
            await self._reply(update, "คำสั่งนี้สำหรับผู้ดูแลระบบเท่านั้น")
            return
        await self._reply(update, await self.service.cmd_test())

    # ---------------- pagination callback ----------------

    async def on_callback(self, update, context):
        query = getattr(update, "callback_query", None)
        if query is None:
            return
        parsed = pagination.parse_callback(query.data or "")
        if parsed is None:
            return
        page, token = parsed
        text, result, _ = self.service.cmd_search_page(token, page)
        try:
            await query.answer()
        except Exception:
            pass
        if text is None:
            return
        keyboard = pagination.build_keyboard(result, token) if result else None
        try:
            await query.edit_message_text(
                text, parse_mode="HTML", disable_web_page_preview=True,
                reply_markup=keyboard)
        except Exception:
            logger.debug("CVE pagination edit failed", exc_info=True)
