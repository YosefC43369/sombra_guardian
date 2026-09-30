"""
plugins.builtin.cve_tracker_suite — register the CVE Intelligence subsystem.

Thin adapter (same rule as group_soc_suite: no big logic in app.py; connect via
the plugin layer). It:

  * gets the process-wide :class:`cve_tracker.engine.CVETracker` singleton so its
    commands share state with the background loop app.py starts in post_init;
  * binds the subsystem's domain events to the platform event bus (so other
    modules can subscribe to cve.discovered / cve.kev_added / …);
  * registers the ``/cve*`` command surface, admin commands (sync/test) at
    ADMIN so the platform gates them with the bot's existing is_admin;
  * reports health.

python-telegram-bot is imported only inside the handlers (call time), so this
module imports fine in the test environment with no telegram installed. The
whole subsystem is dormant unless ``CVE_TRACKER_ENABLED=true`` — the safe default
is inactive, and even enabled it broadcasts nothing until a chat subscribes.
"""

from __future__ import annotations

import logging

from plugins.base import BasePlugin, PluginContext, HealthStatus, PermissionLevel

logger = logging.getLogger("modbot.plugins.cve_tracker")


class CVETrackerPlugin(BasePlugin):
    name = "cve-tracker"
    version = "1.0.0"
    description = "CVE Intelligence & Tracking: monitor public CVE sources → enrich → Thai AI summary → Telegram (defensive)."
    author = "sombra_guardian"
    permission = PermissionLevel.ADMIN

    def __init__(self):
        self._tracker = None
        self._handlers = None
        self._config = None

    def setup(self, ctx: PluginContext) -> None:
        from cve_tracker.config import get_config
        from cve_tracker.engine import get_tracker
        from cve_tracker.telegram.handlers import CVEHandlers
        from cve_tracker.telegram.permissions import PermissionChecker

        self._config = get_config()

        # Bind domain events to the platform bus (best-effort). The tracker's
        # AuditLogger uses this emit to publish cve.* events additively.
        emit = self._make_emit(ctx.event_bus)
        self._tracker = get_tracker(emit=emit)

        # Ensure schema exists even if the platform migration hasn't been run
        # (defensive; the migration is the primary path).
        try:
            self._tracker.init_storage()
        except Exception:
            ctx.logger.exception("cve-tracker: schema init failed (continuing)")

        # Admin commands are registered at ADMIN so the platform wraps them with
        # the bot's real is_admin; the handler's own checker is permissive since
        # that gate has already run before the handler is reached.
        self._handlers = CVEHandlers(
            self._tracker.command_service,
            permissions=PermissionChecker(is_admin=lambda *a, **k: True),
        )

        public = [
            ("cve", self._handlers.cve, "ดู/ค้นหา CVE"),
            ("cve_info", self._handlers.cve_info, "รายละเอียด CVE แบบเต็ม"),
            ("cve_search", self._handlers.cve_search, "ค้นหา CVE"),
            ("cve_ask", self._handlers.cve_ask, "ถามหา CVE เป็นภาษาธรรมชาติ"),
            ("cve_recent", self._handlers.cve_recent, "CVE ล่าสุด"),
            ("cve_latest", self._handlers.cve_latest, "CVE ล่าสุด 1 รายการ"),
            ("cve_history", self._handlers.cve_history, "ประวัติ/ไทม์ไลน์ของ CVE"),
            ("cve_kev", self._handlers.cve_kev, "CVE ใน CISA KEV"),
            ("cve_affected", self._handlers.cve_affected, "CVE ที่กระทบผลิตภัณฑ์/เวอร์ชัน"),
            ("cve_digest", self._handlers.cve_digest, "สรุป CVE ประจำวัน/สัปดาห์"),
            ("cve_stats", self._handlers.cve_stats, "สถิติ CVE"),
            ("cve_report", self._handlers.cve_report, "รายงาน CVE (แนวโน้ม/แหล่ง/AI)"),
            ("cve_subscribe", self._handlers.cve_subscribe, "ตั้งค่าการแจ้งเตือน CVE"),
            ("cve_unsubscribe", self._handlers.cve_unsubscribe, "ปิดการแจ้งเตือน CVE"),
            ("cve_preferences", self._handlers.cve_preferences, "ดูการตั้งค่าการแจ้งเตือน"),
            ("cve_sources", self._handlers.cve_sources, "สถานะแหล่งข้อมูล CVE"),
        ]
        for name, handler, desc in public:
            ctx.register_command(name, handler, permission="PUBLIC", description=desc)

        admin = [
            ("cve_status", self._handlers.cve_status, "สถานะ CVE Tracker"),
            ("cve_sync", self._handlers.cve_sync, "ซิงค์ CVE ด้วยตนเอง"),
            ("cve_test", self._handlers.cve_test, "ทดสอบรูปแบบการแจ้งเตือน"),
        ]
        for name, handler, desc in admin:
            ctx.register_command(name, handler, permission="ADMIN", description=desc)

        ctx.logger.info(
            "cve-tracker: registered %d commands (enabled=%s, sources=%s)",
            len(public) + len(admin), self._config.enabled,
            [s.name for s in self._config.enabled_sources()])

    def _make_emit(self, event_bus):
        """Return an emit(event_type, payload) that publishes onto the platform
        bus if one is present, else a no-op. Never raises."""
        if event_bus is None:
            return None

        def _emit(event_type: str, payload: dict) -> None:
            try:
                publish = getattr(event_bus, "publish", None) or getattr(event_bus, "emit", None)
                if publish is None:
                    return
                result = publish(event_type, payload)
                # some buses return a coroutine; schedule it if a loop is running
                if hasattr(result, "__await__"):
                    import asyncio
                    try:
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            loop.create_task(result)
                    except Exception:
                        pass
            except Exception:
                pass

        return _emit

    def healthcheck(self) -> HealthStatus:
        if self._config is not None and not self._config.enabled:
            return HealthStatus.ok("dormant (CVE_TRACKER_ENABLED off)")
        if self._tracker is None:
            return HealthStatus.unhealthy("tracker not initialised")
        try:
            h = self._tracker.health()
            hh = h.get("health", {})
            return HealthStatus.ok(
                f"records={h.get('record_count', 0)} "
                f"sources={hh.get('healthy_sources', 0)}/{hh.get('total_sources', 0)} "
                f"overall={hh.get('overall', '?')}")
        except Exception as exc:
            return HealthStatus.unhealthy(f"health error: {exc}")

    def shutdown(self) -> None:
        if self._tracker is not None:
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self._tracker.stop())
            except Exception:
                pass
