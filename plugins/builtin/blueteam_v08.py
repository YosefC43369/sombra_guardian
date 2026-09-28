"""
plugins.builtin.blueteam_v08 — wires the v0.8 Blue Team Intelligence & Governance
suite (Threat Intel, Detection-as-Code, Posture) into the platform.

Additive and self-contained (กติกา: connect at the seam, no refactor of app.py):
  * assembles the DI container — sqlite adapters + services for intel/dac/posture,
    a shared metrics registry, an ``emit`` bound to the event bus, and a ``sealer``
    bound to the Merkle integrity ledger;
  * registers ``/intel`` ``/rule`` ``/posture`` (OWNER = a chat admin within their
    own single-group tenant; reads gated at ADMIN);
  * subscribes a fail-open analysis pass to ``message.received`` — DaC rule
    evaluation + Threat-Intel URL lookup, emitting defanged events only;
  * drives feed sync + posture snapshots **opportunistically** (throttled, in an
    executor) since the platform exposes no background-task hook — every unit is
    unit-tested offline; this module only glues them.

python-telegram-bot is imported only inside handlers. The suite is inert unless
``BLUETEAM_V08_ENABLED`` is set and a module is on (safe default: off).
"""

from __future__ import annotations

import asyncio
import json
import os
import time

from plugins.base import BasePlugin, PluginContext, HealthStatus, PermissionLevel

_REF = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                    "reference_data", "blueteam")


class BlueTeamV08Plugin(BasePlugin):
    name = "blueteam-v08"
    version = "0.8.0"
    description = "Threat Intel/IOC + Detection-as-Code + Security Posture (passive, defensive)."
    author = "sombra_guardian"
    permission = PermissionLevel.ADMIN

    def __init__(self):
        self._cfg = None
        self._intel = self._dac = self._posture = None
        self._intel_cmd = self._rule_cmd = self._posture_cmd = None
        self._container = None
        self._last = {"feed": 0.0, "posture": 0.0}
        self._pack = []

    # ---------------- setup ----------------
    def setup(self, ctx: PluginContext) -> None:
        from blueteam.platform.config import get_v08_config
        self._cfg = get_v08_config()
        if self._cfg.kill_switch:
            ctx.logger.info("blueteam-v08: kill switch on; dormant")
            return
        db_path = ctx.db_path or "bot.db"
        try:
            self._assemble(ctx, db_path)
        except Exception as exc:              # fail-closed on wiring, but never crash startup
            ctx.logger.warning("blueteam-v08: setup skipped (%s)", exc)
            return

        # commands
        if self._cfg.module_enabled("intel"):
            ctx.register_command("intel", self._make(lambda c, a, actor, role:
                                 self._intel_cmd.handle(a, actor=actor, role=role)),
                                 permission="ADMIN", description="Threat Intel / IOC")
        if self._cfg.module_enabled("dac"):
            ctx.register_command("rule", self._make_rule(),
                                 permission="ADMIN", description="Detection-as-Code rules")
        if self._cfg.module_enabled("posture"):
            ctx.register_command("posture", self._make(lambda c, a, actor, role:
                                 self._posture_cmd.handle(c, a, actor=actor, role=role)),
                                 permission="ADMIN", description="Security Posture & report")

        # analysis on messages (fail-open)
        ctx.subscribe_event(self._on_message, "message.received")
        ctx.logger.info("blueteam-v08: wired intel=%s dac=%s posture=%s",
                        self._cfg.module_enabled("intel"), self._cfg.module_enabled("dac"),
                        self._cfg.module_enabled("posture"))

    def _assemble(self, ctx: PluginContext, db_path: str) -> None:
        from blueteam.platform.metrics import get_metrics
        from blueteam.platform.container import BlueTeamContainer
        from blueteam.platform.tenancy import tenant_id_for_chat
        from workflows.models import Event

        metrics = get_metrics()

        def emit(event) -> None:
            try:
                ctx.event_bus.emit(Event(type=getattr(event, "type", "blueteam.event"),
                                         payload=event.to_payload() if hasattr(event, "to_payload") else {},
                                         source="blueteam-v08"))
            except Exception:
                ctx.logger.debug("blueteam-v08 emit failed", exc_info=True)

        seal_state = {"ok": True}

        def sealer(kind: str, payload: dict) -> str:
            if not seal_state["ok"]:
                return ""                       # ledger unavailable; stop retrying (best-effort)
            try:
                import integrity_ledger
                chat_id = int(payload.get("chat_id", 0) or 0)
                integrity_ledger.record_event(chat_id, f"blueteam.{kind}", payload)
            except Exception:
                seal_state["ok"] = False
                ctx.logger.debug("blueteam-v08 seal disabled (ledger unavailable)", exc_info=True)
            return ""

        tenant_of = tenant_id_for_chat

        # ---- Intel ----
        if self._cfg.module_enabled("intel"):
            from blueteam.intel.adapters import SqliteIntelRepository
            from blueteam.intel.service import IntelService
            from blueteam.intel.commands import IntelCommandService
            from blueteam.intel.feeds import FeedFetcher, load_feed_defs
            from blueteam.netprobe import screen_host
            feeds = load_feed_defs(os.path.join(_REF, "intel", "feeds.json"))
            fetcher = FeedFetcher(screen_host=screen_host,
                                  max_decompress_ratio=self._cfg.intel.max_decompress_ratio)
            self._intel = IntelService(
                SqliteIntelRepository(db_path), feeds=feeds, fetcher=fetcher,
                metrics=metrics, emit=emit,
                growth_quarantine_ratio=self._cfg.intel.growth_quarantine_ratio,
                auto_action_min_confidence=self._cfg.intel.auto_action_min_confidence)
            self._intel_cmd = IntelCommandService(self._intel)

        # ---- DaC ----
        if self._cfg.module_enabled("dac"):
            from blueteam.dac.adapters import SqliteRuleRepository
            from blueteam.dac.service import DacService
            from blueteam.dac.commands import RuleCommandService
            self._dac = DacService(SqliteRuleRepository(db_path), metrics=metrics, emit=emit,
                                   sealer=sealer, max_ast_nodes=self._cfg.dac.max_ast_nodes,
                                   per_rule_budget_us=self._cfg.dac.per_rule_budget_us)
            try:
                with open(os.path.join(_REF, "dac", "rules", "starter_pack.json"),
                          encoding="utf-8") as fh:
                    self._pack = json.load(fh).get("rules", [])
            except OSError:
                self._pack = []
            self._rule_cmd = RuleCommandService(self._dac, pack=self._pack)

        # ---- Posture ----
        if self._cfg.module_enabled("posture"):
            from blueteam.posture.adapters import SqlitePostureRepository
            from blueteam.posture.service import PostureService
            from blueteam.posture.commands import PostureCommandService
            from blueteam.posture.domain import load_catalog
            with open(os.path.join(_REF, "posture", "controls.json"), encoding="utf-8") as fh:
                catalog = load_catalog(json.load(fh)["controls"])
            self._posture = PostureService(
                SqlitePostureRepository(db_path), catalog=catalog,
                signals=_RuntimeSignals(db_path, self._intel, self._dac),
                metrics=metrics, emit=emit, sealer=sealer, tenant_of=tenant_of)
            self._posture_cmd = PostureCommandService(self._posture)

        self._container = BlueTeamContainer(db_path=db_path, config=self._cfg, metrics=metrics,
                                            emit=emit, intel=self._intel, dac=self._dac,
                                            posture=self._posture)

    # ---------------- command adapters ----------------
    @staticmethod
    def _role_for(update):
        # single group = its own tenant; a chat admin is OWNER of that tenant.
        from blueteam.platform.tenancy import Role
        return Role.OWNER

    def _make(self, call):
        async def handler(update, context):
            chat = update.effective_chat
            if chat is None or chat.type not in ("group", "supergroup"):
                return await update.message.reply_text("ใช้ได้เฉพาะในกลุ่มเท่านั้น")
            if not await _is_admin(update, context):
                return await update.message.reply_text("⛔ เฉพาะผู้ดูแลกลุ่ม")
            actor = update.effective_user.id if update.effective_user else None
            args = context.args or []
            role = self._role_for(update)
            try:
                text = call(chat.id, args, actor, role)
            except Exception:
                text = "เกิดข้อผิดพลาดภายใน โปรดลองใหม่"
            return await update.message.reply_text(text, disable_web_page_preview=True)
        return handler

    def _make_rule(self):
        async def handler(update, context):
            chat = update.effective_chat
            if chat is None or chat.type not in ("group", "supergroup"):
                return await update.message.reply_text("ใช้ได้เฉพาะในกลุ่มเท่านั้น")
            if not await _is_admin(update, context):
                return await update.message.reply_text("⛔ เฉพาะผู้ดูแลกลุ่ม")
            actor = update.effective_user.id if update.effective_user else None
            args = context.args or []
            raw = update.message.text or ""
            role = self._role_for(update)
            try:
                text = self._rule_cmd.handle(args, raw=raw, actor=actor, role=role)
            except Exception:
                text = "เกิดข้อผิดพลาดภายใน โปรดลองใหม่"
            return await update.message.reply_text(text, disable_web_page_preview=True)
        return handler

    # ---------------- message analysis (fail-open) ----------------
    async def _on_message(self, event) -> None:
        try:
            p = event.payload if hasattr(event, "payload") else event
            await self._analyze(p or {})
        except Exception:
            pass  # detection is fail-open: never break the message path

    async def _analyze(self, p: dict) -> None:
        chat_id = p.get("chat_id")
        text = p.get("text") or ""
        # DaC evaluation
        if self._dac is not None:
            from blueteam.dac.records import build_record
            from blueteam.urlkit import extract_urls
            urls = [u.url for u in extract_urls(text)] if text else []
            rec = build_record(text=text, urls=urls, user_id=p.get("user_id"),
                               chat_id=chat_id, is_new_member=bool(p.get("is_first_message")),
                               has_username=bool(p.get("username")),
                               entities={"mention": int(p.get("mention_count", 0) or 0)})
            for hit in self._dac.evaluate(rec, chat_id=chat_id):
                self._container.emit(_rule_event(hit, chat_id, p.get("user_id")))
        # Intel URL lookup
        if self._intel is not None and text:
            from blueteam.urlkit import extract_urls
            for u in (extract_urls(text) or [])[:10]:
                from blueteam.intel.domain import IOCType
                mr = self._intel.lookup(u.url, IOCType.URL, chat_id=chat_id,
                                        user_id=p.get("user_id"), record=True)
                if mr is not None:
                    self._container.emit(_ioc_event(mr, chat_id, p.get("user_id")))

        # opportunistic scheduling (throttled, off-loop)
        await self._tick(chat_id)

    async def _tick(self, chat_id) -> None:
        now = time.time()
        loop = asyncio.get_running_loop()
        if (self._intel is not None
                and now - self._last["feed"] > self._cfg.intel.sync_interval_s):
            self._last["feed"] = now
            loop.run_in_executor(None, self._safe, lambda: self._intel.sync_all(only_enabled=True))
        if (self._posture is not None and chat_id is not None
                and now - self._last["posture"] > self._cfg.posture.snapshot_interval_s):
            self._last["posture"] = now
            loop.run_in_executor(None, self._safe, lambda: self._posture.record_snapshot(chat_id))

    @staticmethod
    def _safe(fn):
        try:
            fn()
        except Exception:
            pass

    # ---------------- health ----------------
    def healthcheck(self) -> HealthStatus:
        if self._cfg is not None and self._cfg.kill_switch:
            return HealthStatus.ok("dormant (kill switch)")
        if self._container is None:
            return HealthStatus.ok("dormant (all modules off)")
        try:
            bits = []
            if self._intel is not None:
                bits.append(f"intel={self._intel.engine.size}")
            if self._dac is not None:
                bits.append(f"rules={self._dac.engine.active_count()}")
            if self._posture is not None:
                bits.append("posture=on")
            return HealthStatus.ok(", ".join(bits) or "idle")
        except Exception as exc:
            return HealthStatus.unhealthy(f"v08 error: {exc}")


# ---------------- posture signals bridge ----------------

class _RuntimeSignals:
    """Derives posture control statuses from real bot state (per-chat policy +
    intel/dac service state). Only observable facts (กติกา)."""

    def __init__(self, db_path, intel, dac):
        self._db_path = db_path
        self._intel = intel
        self._dac = dac

    def assess(self, chat_id: int):
        status = {}
        try:
            from blueteam.store import BlueTeamStore
            store = BlueTeamStore(self._db_path)
            for module, control in (("linkguard", "link_guard"), ("scamguard", "scam_guard"),
                                    ("joinguard", "join_guard")):
                pol = store.get_policy(chat_id, module) or {}
                status[control] = "pass" if pol.get("enabled") else "fail"
            store.close()
        except Exception:
            pass
        if self._intel is not None:
            try:
                status["intel_feeds"] = "pass" if self._intel.engine.size > 0 else "weak"
            except Exception:
                status["intel_feeds"] = "unknown"
        if self._dac is not None:
            try:
                status["detection_rules"] = "pass" if self._dac.engine.active_count() > 0 else "weak"
            except Exception:
                status["detection_rules"] = "unknown"
        try:
            import integrity_ledger
            status["integrity_ledger"] = "pass" if integrity_ledger.entry_count(chat_id) > 0 else "partial"
        except Exception:
            status["integrity_ledger"] = "unknown"
        return status


async def _is_admin(update, context) -> bool:
    try:
        chat = update.effective_chat
        user = update.effective_user
        if chat is None or user is None:
            return False
        member = await context.bot.get_chat_member(chat.id, user.id)
        return getattr(member, "status", "") in ("administrator", "creator")
    except Exception:
        return False


def _rule_event(hit, chat_id, user_id):
    from blueteam.platform.events import RuleMatched
    import hashlib
    subj = hashlib.sha256(f"{chat_id}|{user_id}".encode()).hexdigest()[:16]
    return RuleMatched(chat_id=chat_id, user_id=user_id, rule_id=hit.rule_id,
                       rule_title=hit.title, level=hit.level, attack=hit.attack,
                       mode=hit.mode, subject=subj)


def _ioc_event(mr, chat_id, user_id):
    from blueteam.platform.events import IocMatched
    from blueteam.urlkit import defang
    return IocMatched(chat_id=chat_id, user_id=user_id, ioc_type=mr.ioc_type.value,
                      value_defanged=defang(mr.matched_value), confidence=mr.confidence,
                      severity=mr.severity, feeds=",".join(mr.sources), subject=mr.ioc_id[:16])
