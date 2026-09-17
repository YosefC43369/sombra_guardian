"""
sg_platform.py — the integration seam between app.py and the three new
subsystems (migrations, workflows, plugins).

app.py stays almost untouched: it calls three functions from here —
``init_platform`` (once, in main(), after the legacy *_db_init calls),
``register_handlers`` (once, in the handler-registration block), and
``configure_telegram_services`` (once, in post_init when the bot exists) —
plus a fire-and-forget ``emit`` in a couple of event-producing spots.

Design guarantees
-----------------
* Migrations are the only fatal step: a real migration failure raises and
  main() must not swallow it (a half-migrated DB is worse than a clear stop).
* Everything else (loading workflows, discovering plugins, wiring services) is
  wrapped so a bug there degrades the platform to a no-op but NEVER stops the
  bot from booting or serving its existing commands.
* Authentication is NOT reinvented: admin-gated platform commands reuse the
  ``is_admin`` callable app.py already uses for every other admin command.

This module imports Telegram (for the admin command handlers) but does so
lazily inside functions where possible, so importing sg_platform in a test
does not require a running bot.
"""

import os
import logging
from typing import Callable, List, Optional

import migrations
from workflows import (
    Event, EventBus, WorkflowEngine, Services, build_default_registry, load_dir,
)
from plugins import PluginManager, PermissionLevel

logger = logging.getLogger("modbot.platform")

# Anchored to this file, not the process cwd: the bot may be started from a
# different working directory (and the startup test chdirs to a temp dir), but
# the shipped definitions always live next to the code.
_HERE = os.path.dirname(os.path.abspath(__file__))
WORKFLOW_DEFINITIONS_DIR = os.path.join(_HERE, "workflows", "definitions")


class Platform:
    """Holds the live subsystem objects and the small glue app.py needs."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.action_registry = build_default_registry()
        self.services = Services()
        self.event_bus = EventBus()
        self.engine = WorkflowEngine(self.action_registry, self.services,
                                     db_path=db_path)
        self.plugins = PluginManager(
            db_path=db_path, engine=self.engine,
            action_registry=self.action_registry, event_bus=self.event_bus,
        )
        self.migration_status: dict = {}
        # is_admin is injected at register_handlers time so we never duplicate auth.
        self._is_admin: Optional[Callable] = None

    # ---- event production (called by app.py) ----

    def emit(self, event_type: str, payload: dict, correlation_id: str = None,
             depth: int = 0, source: str = "app") -> None:
        """Fire-and-forget: publish an event onto the bus. Never raises into
        the caller — a workflow problem must not break message handling."""
        try:
            event = Event(type=event_type, payload=payload or {}, depth=depth,
                          source=source)
            if correlation_id:
                event.correlation_id = correlation_id
            self.event_bus.emit(event)
        except Exception:
            logger.exception("PLATFORM emit failed for %s", event_type)

    # ---- reporting helpers for the admin commands ----

    def migration_runner(self):
        return migrations.MigrationRunner(self.db_path)


# ---------------- Boot ----------------

def init_platform(db_path: str) -> Platform:
    """Run migrations, build the platform, load workflows + plugins, and wire
    the event bus to the engine. Returns a Platform.

    Raises only if a migration genuinely fails — the caller (main()) must let
    that propagate rather than start on a half-migrated database.
    """
    # 1) Migrations — the fatal step. Creates the wf_* / plugin_state tables.
    status = migrations.apply_startup_migrations(db_path)

    platform = Platform(db_path)
    platform.migration_status = status

    # 2) Wire the engine to the bus so published events drive workflows.
    async def _drive(event: Event):
        return await platform.engine.dispatch(event)
    platform.event_bus.subscribe(_drive)

    # 3) Load workflow definitions (isolated: a bad file never stops boot).
    try:
        definitions = load_dir(WORKFLOW_DEFINITIONS_DIR)
        platform.engine.register_many(definitions)
        logger.info("PLATFORM | %d workflow(s) loaded", len(definitions))
    except Exception:
        logger.exception("PLATFORM | workflow loading failed; continuing with none")

    # 4) Discover + load plugins (each plugin's failure already isolated).
    try:
        platform.plugins.discover()
        platform.plugins.load_all()
        summary = platform.plugins.summary()
        logger.info("PLATFORM | plugins: %s", summary)
        if summary.get("failed"):
            logger.warning("PLATFORM | failed plugins (bot unaffected): %s",
                           summary["failed"])
    except Exception:
        logger.exception("PLATFORM | plugin loading failed; continuing without plugins")

    return platform


def configure_telegram_services(platform: Platform, bot,
                                is_admin: Optional[Callable] = None) -> None:
    """Called from post_init once app.bot exists. Wires the Services the
    built-in workflow actions use to actually talk to Telegram and the
    feature modules. Everything here is optional — a service left unset just
    keeps its action a logged stub."""

    async def _send_message(chat_id, text):
        if chat_id is None:
            return None
        return await bot.send_message(chat_id=chat_id, text=text)

    async def _send_admin_alert(chat_id, text):
        # No dedicated admin channel exists; the group's own admins see the
        # group. Sending the alert into the chat is the least-surprising,
        # non-invasive default and mirrors how existing incidents surface.
        if chat_id is None:
            return None
        return await bot.send_message(chat_id=chat_id, text=text)

    platform.services.set("send_message", _send_message)
    platform.services.set("send_admin_alert", _send_admin_alert)

    # Feature-module services: imported lazily and wrapped so a signature or
    # availability change degrades to a stub rather than crashing a workflow.
    _wire_incident_services(platform)
    logger.info("PLATFORM | telegram services configured")


def _wire_incident_services(platform: Platform) -> None:
    try:
        import member_incident as mic
    except Exception:
        logger.info("PLATFORM | member_incident unavailable; incident actions stay stubs")
        return

    def _create_incident(chat_id, user_id, category, severity, reason, meta):
        result = mic.incident_from_detection(
            chat_id, user_id, category, severity, reason=reason,
            username=(meta or {}).get("username"),
            display_name=(meta or {}).get("display_name"),
        )
        return {"incident_id": getattr(result, "incident_id", None),
                "ok": getattr(result, "ok", False)}

    def _update_incident(incident_id, status, actor, reason):
        if incident_id is None:
            return {"ok": False}
        result = mic.update_incident_status(incident_id, status,
                                            actor_user_id=actor or 0, reason=reason)
        return {"ok": getattr(result, "ok", False)}

    platform.services.set("create_incident", _create_incident)
    platform.services.set("update_incident", _update_incident)


# ---------------- Handler registration ----------------

def register_handlers(app, platform: Platform, is_admin: Callable) -> List[str]:
    """Register the platform admin commands (/plugins, /workflow, /migration)
    and every command a plugin contributed, each behind the injected
    ``is_admin`` gate when its permission requires it. Returns the list of
    command names registered (handy for logging/tests).

    Only ``app.add_handler`` is used, so this works with the real
    python-telegram-bot Application and with the test's FakeApp alike.
    """
    from telegram.ext import CommandHandler

    platform._is_admin = is_admin
    registered: List[str] = []

    def add(name: str, handler: Callable):
        app.add_handler(CommandHandler(name, handler))
        registered.append(name)

    # Built-in platform admin commands.
    add("plugins", _make_admin_command(platform, is_admin, _cmd_plugins))
    add("workflow", _make_admin_command(platform, is_admin, _cmd_workflow))
    add("migration", _make_admin_command(platform, is_admin, _cmd_migration))

    # Plugin-contributed commands, gated per their declared permission.
    for spec in platform.plugins.iter_command_specs():
        if spec.permission >= PermissionLevel.ADMIN:
            handler = _wrap_permission(spec.handler, is_admin)
        else:
            handler = spec.handler
        try:
            add(spec.name, handler)
        except Exception:
            logger.exception("PLATFORM | could not register plugin command /%s",
                             spec.name)

    logger.info("PLATFORM HANDLERS | %s", ", ".join("/" + c for c in registered))
    return registered


def _wrap_permission(handler: Callable, is_admin: Callable) -> Callable:
    async def wrapped(update, context):
        if not await is_admin(update, context):
            return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
        return await handler(update, context)
    return wrapped


def _make_admin_command(platform: Platform, is_admin: Callable, impl: Callable):
    async def command(update, context):
        if not await is_admin(update, context):
            return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
        try:
            return await impl(platform, update, context)
        except Exception:
            logger.exception("PLATFORM | admin command failed")
            return await update.message.reply_text("⚠️ คำสั่งแพลตฟอร์มผิดพลาด (ดู log)")
    return command


# ---------------- Admin command implementations ----------------

async def _cmd_plugins(platform: Platform, update, context):
    args = context.args or []
    sub = (args[0].lower() if args else "list")

    if sub in ("list", ""):
        rows = platform.plugins.metadata()
        if not rows:
            return await update.message.reply_text("ไม่มีปลั๊กอินที่โหลด")
        lines = ["🧩 Plugins"]
        for r in rows:
            icon = {"ENABLED": "🟢", "DISABLED": "⚪", "FAILED": "🔴"}.get(r["state"], "▫️")
            lines.append(f"{icon} {r['name']} v{r['version']} — {r['state']}")
        return await update.message.reply_text("\n".join(lines))

    if sub == "status":
        return await update.message.reply_text(_format_kv(platform.plugins.summary()))

    if sub == "health":
        health = platform.plugins.healthcheck_all()
        lines = ["🩺 Plugin health"]
        for name, status in health.items():
            icon = "🟢" if status and status.healthy else "🔴"
            lines.append(f"{icon} {name}: {status.detail if status else 'unknown'}")
        return await update.message.reply_text("\n".join(lines))

    if sub == "info" and len(args) >= 2:
        record = platform.plugins.registry.get(args[1])
        if record is None:
            return await update.message.reply_text(f"ไม่พบปลั๊กอิน: {args[1]}")
        return await update.message.reply_text(_format_kv(record.as_dict()))

    if sub in ("enable", "disable") and len(args) >= 2:
        actor = update.effective_user.id if update.effective_user else None
        ok = (platform.plugins.enable(args[1], actor) if sub == "enable"
              else platform.plugins.disable(args[1], actor))
        verb = "เปิด" if sub == "enable" else "ปิด"
        return await update.message.reply_text(
            f"{'✅' if ok else '❌'} {verb}ปลั๊กอิน {args[1]}"
            + ("" if ok else " (ไม่พบ)"))

    return await update.message.reply_text(
        "ใช้งาน: /plugins [list|status|health|info <name>|enable <name>|disable <name>]")


async def _cmd_workflow(platform: Platform, update, context):
    args = context.args or []
    sub = (args[0].lower() if args else "list")
    engine = platform.engine

    if sub in ("list", ""):
        workflows = engine.list()
        if not workflows:
            return await update.message.reply_text("ยังไม่มี workflow")
        lines = ["⚙️ Workflows"]
        for w in workflows:
            icon = "🟢" if w.enabled else "⚪"
            lines.append(f"{icon} {w.name} ← {w.trigger}")
        return await update.message.reply_text("\n".join(lines))

    if sub == "status":
        return await update.message.reply_text(_format_kv(engine.stats()))

    if sub == "show" and len(args) >= 2:
        wf = engine.get(args[1])
        if wf is None:
            return await update.message.reply_text(f"ไม่พบ workflow: {args[1]}")
        return await update.message.reply_text(_format_kv(wf.as_dict()))

    if sub == "history":
        name = args[1] if len(args) >= 2 else None
        rows = engine.history(name, limit=10)
        if not rows:
            return await update.message.reply_text("ยังไม่มีประวัติการรัน")
        lines = ["📜 Workflow history"]
        for r in rows:
            lines.append(f"• {r['workflow_name']} [{r['state']}] {r['event_type']}")
        return await update.message.reply_text("\n".join(lines))

    if sub in ("enable", "disable") and len(args) >= 2:
        actor = update.effective_user.id if update.effective_user else None
        ok = engine.set_enabled(args[1], sub == "enable", actor)
        verb = "เปิด" if sub == "enable" else "ปิด"
        return await update.message.reply_text(
            f"{'✅' if ok else '❌'} {verb} workflow {args[1]}"
            + ("" if ok else " (ไม่พบ)"))

    return await update.message.reply_text(
        "ใช้งาน: /workflow [list|status|show <name>|history [name]|"
        "enable <name>|disable <name>]")


async def _cmd_migration(platform: Platform, update, context):
    args = context.args or []
    sub = (args[0].lower() if args else "status")
    runner = platform.migration_runner()

    if sub in ("status", ""):
        return await update.message.reply_text(_format_migration_status(runner.status()))

    if sub == "current":
        return await update.message.reply_text(f"เวอร์ชันปัจจุบัน: {runner.current() or '(baseline)'}")

    if sub == "pending":
        pending = runner.pending()
        if not pending:
            return await update.message.reply_text("ไม่มี migration ค้าง ✅")
        lines = ["⏳ Pending migrations"]
        for m in pending:
            flag = " ⚠️destructive" if m.destructive else ""
            lines.append(f"• {m.version} {m.description}{flag}")
        return await update.message.reply_text("\n".join(lines))

    if sub == "verify":
        problems = runner.verify()
        if not problems:
            return await update.message.reply_text("✅ schema สอดคล้อง (ไม่พบปัญหา)")
        return await update.message.reply_text("⚠️ พบปัญหา:\n" + "\n".join(problems))

    if sub == "up":
        # Destructive migrations require an explicit --confirm from an admin.
        confirm = "--confirm" in args or "confirm" in args
        try:
            applied = runner.migrate_up(allow_destructive=confirm,
                                        stop_before_destructive=not confirm)
        except migrations.MigrationError as exc:
            return await update.message.reply_text(f"❌ migration ล้มเหลว: {exc}")
        if not applied:
            return await update.message.reply_text(
                "ไม่มีอะไรให้ทำ (หรือมี destructive ที่ต้องยืนยันด้วย /migration up --confirm)")
        return await update.message.reply_text("✅ applied: " + ", ".join(applied))

    return await update.message.reply_text(
        "ใช้งาน: /migration [status|current|pending|verify|up [--confirm]]")


# ---------------- Formatting helpers ----------------

def _format_kv(data: dict) -> str:
    lines = []
    for key, value in data.items():
        lines.append(f"{key}: {value}")
    return "\n".join(lines) if lines else "(ว่าง)"


def _format_migration_status(status: dict) -> str:
    lines = [
        "🗄️ Migration status",
        f"current: {status.get('current') or '(baseline)'}",
        f"applied: {status.get('applied_count')}/{status.get('total')}",
        f"pending: {status.get('pending_count')}",
    ]
    if status.get("problems"):
        lines.append("⚠️ problems:")
        lines.extend(f"  - {p}" for p in status["problems"])
    return "\n".join(lines)
