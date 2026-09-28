"""
plugins.builtin.blueteam_suite — registers the Blue Team Suite into the platform.

Thin adapter (กติกาข้อ 4: no big logic in app.py, connect via Event Bus + Workflow
Engine + Plugins). It:

  * builds the shared :class:`~blueteam.runtime.BlueTeamRuntime` for this DB and
    gives it an ``emit`` bound to the event bus;
  * subscribes the runtime's handlers to ``message.received`` / ``member.joined`` /
    ``member.left`` (emitted additively by app.py);
  * registers the admin/member commands (``/linkguard`` etc.) — admin ones inherit
    the platform's existing ``is_admin`` gate via their PermissionLevel;
  * registers a workflow action so playbooks can annotate Blue Team events;
  * reports health.

python-telegram-bot is imported only inside handlers (call time), so this module
imports fine in the test environment with no telegram installed. Per-module feature
flags (config) plus per-group policy mean the suite is inert until an admin turns a
module on — the safe default.
"""

import logging

from plugins.base import BasePlugin, PluginContext, HealthStatus, PermissionLevel

logger = logging.getLogger("modbot.plugins.blueteam")


class _BlueTeamNoteAction:
    """A workflow action playbooks can call to log a structured Blue Team note."""
    name = "bt_note"

    async def execute(self, context):
        from workflows.models import ActionResult
        event = context["event"]
        context["logger"].info("BLUETEAM workflow note | %s corr=%s",
                               event.type, context.get("correlation_id"))
        return ActionResult.success(self.name, f"noted {event.type}")


class BlueTeamPlugin(BasePlugin):
    name = "blueteam-suite"
    version = "0.7.0"
    description = "Link Guard + Scam/Impersonation + Join Guard/Anti-Raid (passive, defensive)."
    author = "sombra_guardian"
    permission = PermissionLevel.ADMIN

    def __init__(self):
        self._runtime = None
        self._cmd = None
        self._config = None

    def setup(self, ctx: PluginContext) -> None:
        from blueteam.config import get_config
        from blueteam.runtime import get_runtime
        from blueteam.commands import CommandService

        self._config = get_config()
        if not self._config.enabled:
            ctx.logger.info("blueteam: master kill switch off; suite dormant")
            return

        # emit bound to the shared event bus (Event has no telegram dependency)
        from workflows.models import Event

        def _emit(event_type: str, payload: dict) -> None:
            try:
                ctx.event_bus.emit(Event(type=event_type, payload=payload or {},
                                         source="blueteam"))
            except Exception:
                ctx.logger.debug("blueteam emit failed for %s", event_type, exc_info=True)

        db_path = ctx.db_path or "bot.db"
        self._runtime = get_runtime(db_path, emit=_emit)
        self._cmd = CommandService(self._runtime)

        # event subscriptions (analysis runs off the message-handler path)
        ctx.subscribe_event(self._runtime.on_message, "message.received")
        ctx.subscribe_event(self._runtime.on_member_joined, "member.joined")
        ctx.subscribe_event(self._runtime.on_member_left, "member.left")

        # workflow action for playbooks
        ctx.register_workflow_action(_BlueTeamNoteAction())

        # commands — admin ones gated by the platform's is_admin via PermissionLevel
        ctx.register_command("linkguard", self._make(self._cmd.linkguard),
                             permission="ADMIN", description="จัดการ Link Guard")
        ctx.register_command("scamguard", self._make(self._cmd.scamguard),
                             permission="ADMIN", description="จัดการ Scam Guard")
        ctx.register_command("joinguard", self._make(self._cmd.joinguard),
                             permission="ADMIN", description="จัดการ Join Guard")
        ctx.register_command("blueteam", self._make(self._cmd.blueteam),
                             permission="ADMIN", description="แดชบอร์ด Blue Team")
        ctx.register_command("linkcheck", self._linkcheck,
                             permission="PUBLIC", description="ตรวจสอบลิงก์ (สมาชิก)")
        ctx.logger.info("blueteam: registered commands + subscriptions")

    # -- command adapters (telegram objects only at call time) -------------
    def _make(self, service_method):
        async def handler(update, context):
            chat = update.effective_chat
            if chat is None or chat.type not in ("group", "supergroup"):
                from blueteam.messages_th import msg
                return await update.message.reply_text(msg("not_in_group"))
            actor = update.effective_user.id if update.effective_user else None
            args = context.args or []
            text = service_method(chat.id, args, actor)
            return await update.message.reply_text(text, disable_web_page_preview=True)
        return handler

    async def _linkcheck(self, update, context):
        chat = update.effective_chat
        user = update.effective_user
        args = context.args or []
        url = args[0] if args else ""
        text = await self._cmd.linkcheck(chat.id if chat else 0,
                                         user.id if user else 0, url, is_admin=False)
        # reply privately when possible; fall back to a chat reply
        try:
            if user is not None:
                await context.bot.send_message(chat_id=user.id, text=text,
                                               disable_web_page_preview=True)
                return await update.message.reply_text("📩 ส่งผลตรวจให้ทางแชทส่วนตัวแล้ว")
        except Exception:
            pass
        return await update.message.reply_text(text, disable_web_page_preview=True)

    def healthcheck(self) -> HealthStatus:
        if self._config is not None and not self._config.enabled:
            return HealthStatus.ok("dormant (kill switch off)")
        if self._runtime is None:
            return HealthStatus.unhealthy("runtime not initialised")
        try:
            st = self._runtime.registry.status()
            return HealthStatus.ok(
                f"rules ok={st['checksums_ok']} th={st['scam_th']} en={st['scam_en']}")
        except Exception as exc:
            return HealthStatus.unhealthy(f"registry error: {exc}")
