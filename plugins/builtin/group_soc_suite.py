"""
plugins.builtin.group_soc_suite — registers the Group SOC into the platform.

Thin adapter (กติกาข้อ 4: no big logic in app.py; connect via Event Bus + Plugins). It:

  * builds the shared :class:`~group_soc.runtime.SocRuntime` for this DB and binds its
    ``emit`` to the event bus;
  * subscribes the runtime's ``on_event`` to the bus event types the SOC ingests
    (message.received / member.joined / member.left / detection.triggered /
    rule.matched / intel.ioc_matched — all emitted additively by app.py / blueteam);
  * registers the admin ``/soc`` command (gated by the platform's existing is_admin via
    its PermissionLevel);
  * reports health.

python-telegram-bot is imported only inside the handler (call time), so this module
imports fine in the test environment with no telegram installed. The suite is dormant
unless ``SOC_ENABLED=true`` AND an admin runs ``/soc on`` in the group — the safe default
is inactive (rule §17 privacy-by-default).
"""

import logging

from plugins.base import BasePlugin, PluginContext, HealthStatus, PermissionLevel

logger = logging.getLogger("modbot.plugins.group_soc")


class GroupSocPlugin(BasePlugin):
    name = "group-soc"
    version = "0.1.0"
    description = "Group Security Operations Center: correlate→detect→alert→case/incident→story (defensive)."
    author = "sombra_guardian"
    permission = PermissionLevel.ADMIN

    def __init__(self):
        self._runtime = None
        self._cmd = None
        self._config = None

    def setup(self, ctx: PluginContext) -> None:
        from group_soc.config import get_config
        from group_soc.runtime import get_runtime
        from group_soc.commands import SocCommandService
        from group_soc.integrations.event_bus import bind_emit
        from group_soc.constants import CONSUMED_BUS_EVENTS

        self._config = get_config()
        if not self._config.enabled:
            ctx.logger.info("group_soc: master kill switch off (SOC_ENABLED); suite dormant")
            return

        db_path = ctx.db_path or "bot.db"
        emit = bind_emit(ctx.event_bus)
        self._runtime = get_runtime(db_path, emit=emit, config=self._config)
        self._cmd = SocCommandService(self._runtime)

        # subscribe the SOC to every bus event type it ingests
        for bus_type in CONSUMED_BUS_EVENTS:
            ctx.subscribe_event(self._runtime.on_event, bus_type)

        # admin command surface — gated by the platform's is_admin via PermissionLevel
        ctx.register_command("soc", self._soc_handler, permission="ADMIN",
                             description="Security Operations Center")
        ctx.logger.info("group_soc: registered /soc + %d event subscription(s)",
                        len(CONSUMED_BUS_EVENTS))

    async def _soc_handler(self, update, context):
        """The /soc Telegram handler. Telegram objects are only touched at call time."""
        chat = update.effective_chat
        if chat is None or chat.type not in ("group", "supergroup"):
            return await update.message.reply_text("คำสั่งนี้ใช้ในกลุ่มเท่านั้น")
        user = update.effective_user
        args = context.args or []
        text = self._cmd.dispatch(chat.id, user.id if user else None, args)
        # SOC output is plain text with indicators already defanged
        return await update.message.reply_text(text, disable_web_page_preview=True)

    def healthcheck(self) -> HealthStatus:
        if self._config is not None and not self._config.enabled:
            return HealthStatus.ok("dormant (SOC_ENABLED off)")
        if self._runtime is None:
            return HealthStatus.unhealthy("runtime not initialised")
        try:
            h = self._runtime.health()
            perf = h["performance"]
            return HealthStatus.ok(
                f"worker={'up' if h['worker_started'] else 'idle'} "
                f"depth={perf.get('queue_depth', 0)} processed={perf.get('processed', 0)}")
        except Exception as exc:
            return HealthStatus.unhealthy(f"health error: {exc}")

    def shutdown(self) -> None:
        # best-effort worker stop; the loop may already be closing
        if self._runtime is not None:
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self._runtime.stop())
            except Exception:
                pass
