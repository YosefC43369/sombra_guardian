"""
plugins.builtin.purple_range_suite — registers the Purple Range into the platform.

Thin adapter (connect via Plugins; no logic in app.py). It builds the shared
``purple_range`` service for this DB, binds its (opt-in) telemetry replay to the event
bus, and registers the admin ``/range`` command. python-telegram-bot is imported only
inside the handler, so this module imports fine with no telegram installed.

Dormant unless ``PURPLE_RANGE_ENABLED=true``. The suite only *plans* exercises (through
purpleteam) and generates synthetic telemetry — it never starts, authorizes, or executes
anything, and cannot bypass RoE.
"""

import logging

from plugins.base import BasePlugin, PluginContext, HealthStatus, PermissionLevel

logger = logging.getLogger("modbot.plugins.purple_range")


class PurpleRangePlugin(BasePlugin):
    name = "purple-range"
    version = "0.1.0"
    description = "Purple-team ATT&CK emulation plans, synthetic telemetry, coverage analytics (on purpleteam)."
    author = "sombra_guardian"
    permission = PermissionLevel.ADMIN

    def __init__(self):
        self._svc = None
        self._cmd = None
        self._config = None

    def setup(self, ctx: PluginContext) -> None:
        from purple_range.config import get_config
        from purple_range.runtime import get_runtime, bind_emit
        from purple_range.commands import RangeCommandService

        self._config = get_config()
        if not self._config.enabled:
            ctx.logger.info("purple_range: master switch off (PURPLE_RANGE_ENABLED); dormant")
            return

        db_path = ctx.db_path or "bot.db"
        emit = bind_emit(ctx.event_bus)
        self._svc = get_runtime(db_path, config=self._config, emit=emit)
        self._cmd = RangeCommandService(self._svc)

        ctx.register_command("range", self._range_handler, permission="ADMIN",
                             description="Purple Range (ATT&CK emulation plans + coverage)")
        ctx.logger.info("purple_range: registered /range")

    async def _range_handler(self, update, context):
        chat = update.effective_chat
        if chat is None or chat.type not in ("group", "supergroup"):
            return await update.message.reply_text("คำสั่งนี้ใช้ในกลุ่มเท่านั้น")
        user = update.effective_user
        args = context.args or []
        text = self._cmd.dispatch(chat.id, user.id if user else None, args)
        return await update.message.reply_text(text, disable_web_page_preview=True)

    def healthcheck(self) -> HealthStatus:
        if self._config is not None and not self._config.enabled:
            return HealthStatus.ok("dormant (PURPLE_RANGE_ENABLED off)")
        if self._svc is None:
            return HealthStatus.unhealthy("service not initialised")
        try:
            h = self._svc.health()
            return HealthStatus.ok(f"plans={h['builtin_plans']} attack={h['attack_catalog']}")
        except Exception as exc:
            return HealthStatus.unhealthy(f"health error: {exc}")
