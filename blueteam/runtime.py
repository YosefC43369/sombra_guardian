"""
blueteam/runtime.py — the orchestration seam between the plugins/event bus and the
Blue Team modules.

Keeps the plugins thin: they subscribe events and register commands, all of which
delegate here. Responsibilities:

  * build and own the store, rule registry, the three guards, the correlator and
    the dashboard (one runtime per database, shared via :func:`get_runtime`);
  * resolve the effective per-group policy (global feature flag AND per-group
    ``bt_group_policy``) and apply it (MONITOR/WARN/DELETE/DELETE_RESTRICT);
  * run analysis on ``message.received`` / ``member.joined`` events and perform the
    Telegram side-effects through a :class:`TelegramActions` container (each call
    optional; a missing one degrades to a logged no-op, so the runtime is fully
    testable offline and a wiring gap never crashes anything);
  * emit ``link.flagged`` / ``scam.detected`` / ``raid.detected`` /
    ``blueteam.correlated`` events for the SOAR playbooks;
  * implement the admin command surfaces as pure string-returning services.

FAILURE ISOLATION: every event handler is wrapped so an error here can never break
the legacy moderation flow (กติกาข้อ 10). User content is only ever sent back as
plain text with URLs defanged (กติกาข้อ 7).
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from .config import get_config
from .correlator import Correlator
from .dashboard import Dashboard, PRESETS
from .impersonation import ImpersonationDetector, Target
from .joinguard import JoinGuard, JoinGuardParams, RaidState
from .linkguard import LinkGuard
from .messages_th import msg
from .models import Assessment, PolicyAction, Verdict
from .rules import get_registry
from .scamguard import CampaignTracker, ScamGuard
from .store import BlueTeamStore
from .urlkit import defang

logger = logging.getLogger("modbot.blueteam.runtime")

_MODULES = ("linkguard", "scamguard", "joinguard")


class TelegramActions:
    """Optional Telegram side-effect callables; a missing one is a logged no-op.

    Async callables (all optional), set by sg_platform when the bot exists:
      send_message(chat_id, text, reply_markup=None)
      delete_message(chat_id, message_id)
      restrict_user(chat_id, user_id, permissions, until=None)
      ban_user(chat_id, user_id) / unban_user(chat_id, user_id)
      get_chat_administrators(chat_id) -> [ {user_id, username, display_name} ]
      set_chat_permissions(chat_id, permissions) / get_chat_permissions(chat_id)
    """

    def __init__(self, **callables: Optional[Callable]):
        self._c: Dict[str, Optional[Callable]] = dict(callables)

    def set(self, name: str, fn: Optional[Callable]) -> None:
        self._c[name] = fn

    def get(self, name: str) -> Optional[Callable]:
        return self._c.get(name)

    def has(self, name: str) -> bool:
        return callable(self._c.get(name))

    async def call(self, name: str, *args, **kwargs):
        fn = self._c.get(name)
        if not callable(fn):
            logger.info("BLUETEAM ACTION (stub) | %s", name)
            return None
        import inspect
        result = fn(*args, **kwargs)
        if inspect.isawaitable(result):
            result = await result
        return result


class BlueTeamRuntime:
    def __init__(self, db_path: str = "bot.db",
                 emit: Optional[Callable[[str, dict], None]] = None,
                 logger_obj: Optional[logging.Logger] = None):
        self.config = get_config()
        self.store = BlueTeamStore(db_path)
        self.registry = get_registry()
        self.campaign = CampaignTracker(buffer=self.config.campaign_buffer)
        self.linkguard = LinkGuard(self.store, self.registry)
        self.scamguard = ScamGuard(self.store, self.registry, self.campaign)
        self.impersonation = ImpersonationDetector(self.store)
        self.joinguard = JoinGuard(self.store, JoinGuardParams(
            buffer=self.config.join_buffer))
        self.correlator = Correlator()
        self.dashboard = Dashboard(self.store)
        self.actions = TelegramActions()
        self._emit = emit or (lambda et, p: None)
        self.log = logger_obj or logger
        self._hmac_secret = (self.config.hmac_secret_env
                             or self.store.get_or_create_secret())

    # ---- policy resolution ------------------------------------------------
    def is_active(self, chat_id: int, module: str) -> bool:
        if not self.config.module_enabled(module):
            return False
        pol = self.store.get_policy(chat_id, module)
        return bool(pol and pol["enabled"] and pol["mode"] != "OFF")

    def policy(self, chat_id: int, module: str) -> Dict[str, Any]:
        pol = self.store.get_policy(chat_id, module) or {}
        return {
            "enabled": bool(pol.get("enabled")),
            "mode": PolicyAction.parse(pol.get("mode", "MONITOR")),
            "threshold": int(pol.get("threshold", 45)),
            "sensitivity": pol.get("sensitivity", "balanced"),
            "settings": pol.get("settings", {}),
        }

    # ---- event: message.received -----------------------------------------
    async def on_message(self, event) -> None:
        try:
            await self._on_message(event.payload if hasattr(event, "payload") else event)
        except Exception:
            self.log.exception("BLUETEAM | on_message failed (moderation unaffected)")

    async def _on_message(self, p: dict) -> None:
        chat_id = p.get("chat_id")
        user_id = p.get("user_id")
        if chat_id is None:
            return
        text = p.get("text") or ""
        entities = p.get("entities") or []
        is_admin = bool(p.get("is_admin"))
        link_score = 0

        # --- Link Guard ---
        if self.is_active(chat_id, "linkguard") and not is_admin:
            results = self.linkguard.analyze_message(chat_id, text, entities)
            worst = self.linkguard.worst(results)
            if worst is not None:
                eu, a = worst
                link_score = a.score
                await self._handle_link(chat_id, user_id, p, eu, a)

        # --- Scam Guard ---
        if self.is_active(chat_id, "scamguard") and not is_admin:
            pol = self.policy(chat_id, "scamguard")
            ctx = {
                "is_first_message": bool(p.get("is_first_message")),
                "has_link_or_contact": bool(entities) or "@" in text or "http" in text.lower(),
                "mention_count": int(p.get("mention_count", 0) or 0),
                "post_rate_z": float(p.get("post_rate_z", 0) or 0),
                "link_score": link_score,
                "is_admin": is_admin,
                "is_trusted": bool(p.get("is_trusted")),
            }
            a = self.scamguard.analyze(chat_id, text, user_id=user_id,
                                       sensitivity=pol["sensitivity"], context=ctx)
            if a.score >= pol["threshold"]:
                await self._handle_scam(chat_id, user_id, p, a)

    async def _handle_link(self, chat_id, user_id, p, eu, a: Assessment) -> None:
        pol = self.policy(chat_id, "linkguard")
        if a.score < pol["threshold"]:
            return
        action = pol["mode"]
        self.store.log_event(chat_id, "linkguard", user_id=user_id, subject=a.subject,
                             score=a.score, verdict=a.verdict.name,
                             action=action.name, attack=",".join(a.attack_tags))
        # correlate with a recent join
        corr = self.correlator.note_flag(chat_id, user_id, "link", a.score)
        if corr is not None:
            self._emit("blueteam.correlated", corr.to_event_payload(
                {"message": corr.detail}))
        # SOAR trail
        if a.verdict >= Verdict.HIGH:
            self._emit("link.flagged", {
                "chat_id": chat_id, "user_id": user_id, "subject": a.subject,
                "verdict": a.verdict.name, "score": a.score,
                "reason": self._reasons_text(a), "category": "MALICIOUS_LINK",
                "detection_type": "malicious_link", "severity": "high",
                "username": p.get("username"), "display_name": p.get("display_name")})
        await self._apply_action(chat_id, user_id, p, action, a, module="linkguard",
                                 note=msg("lg_deleted", verdict=a.verdict.label_th))

    async def _handle_scam(self, chat_id, user_id, p, a: Assessment) -> None:
        pol = self.policy(chat_id, "scamguard")
        action = pol["mode"]
        self.store.log_event(chat_id, "scamguard", user_id=user_id, subject=a.subject,
                             score=a.score, verdict=a.verdict.name,
                             action=action.name, attack=",".join(a.attack_tags))
        corr = self.correlator.note_flag(chat_id, user_id, "scam", a.score)
        if corr is not None:
            self._emit("blueteam.correlated", corr.to_event_payload(
                {"message": corr.detail}))
        if a.verdict >= Verdict.HIGH:
            self._emit("scam.detected", {
                "chat_id": chat_id, "user_id": user_id, "subject": a.subject,
                "verdict": a.verdict.name, "score": a.score,
                "reason": self._reasons_text(a),
                "category": "SCAM", "detection_type": "scam", "severity": "high",
                "username": p.get("username"), "display_name": p.get("display_name")})
        # scams always enqueue for admin review (human-in-the-loop) unless auto mode
        self.store.add_review(chat_id, "scamguard", user_id, a.subject, a.score,
                              a.verdict.name, [s.to_dict() for s in a.top_reasons()])
        await self._apply_action(chat_id, user_id, p, action, a, module="scamguard")

    async def _apply_action(self, chat_id, user_id, p, action: PolicyAction,
                            a: Assessment, *, module: str, note: str = "") -> None:
        """Apply MONITOR/WARN/DELETE/DELETE_RESTRICT via wired actions. Bans are
        NEVER automatic here — DELETE_RESTRICT restricts (mutes) only; a permanent
        ban stays human-confirmed unless the group set auto mode explicitly."""
        if action <= PolicyAction.MONITOR:
            return
        message_id = p.get("message_id")
        if action >= PolicyAction.WARN:
            warn = msg("lg_warn_group", verdict=a.verdict.label_th,
                       url=defang(a.meta.get("url", ""))) if module == "linkguard" \
                else msg("sg_result", emoji=a.verdict.emoji, verdict=a.verdict.label_th,
                         score=a.score, categories=", ".join(a.meta.get("categories", [])),
                         reasons=self._reasons_text(a), limitation=msg("limitation"))
            # plain text only; never parse_mode with user content
            await self.actions.call("send_message", chat_id, warn)
        if action >= PolicyAction.DELETE and message_id is not None:
            await self.actions.call("delete_message", chat_id, message_id)
        if action >= PolicyAction.DELETE_RESTRICT and user_id is not None:
            await self.actions.call("restrict_user", chat_id, user_id, None)

    # ---- event: member.joined / member.left ------------------------------
    async def on_member_joined(self, event) -> None:
        try:
            await self._on_member_joined(event.payload if hasattr(event, "payload") else event)
        except Exception:
            self.log.exception("BLUETEAM | on_member_joined failed (moderation unaffected)")

    async def _on_member_joined(self, p: dict) -> None:
        chat_id = p.get("chat_id")
        user_id = p.get("user_id")
        if chat_id is None or user_id is None:
            return
        self.correlator.note_join(chat_id, user_id)

        # impersonation of admins/VIPs at join time
        if self.is_active(chat_id, "scamguard"):
            admins = await self._fetch_admin_targets(chat_id)
            imp = self.impersonation.check(chat_id, user_id, p.get("display_name", ""),
                                           p.get("username", ""), admins=admins,
                                           moment="join")
            if imp.score > 0:
                self.store.log_event(chat_id, "impersonation", user_id=user_id,
                                     subject=imp.subject, score=imp.score,
                                     verdict=imp.verdict.name, action="REVIEW",
                                     attack=",".join(imp.attack_tags))
                self.store.add_review(chat_id, "impersonation", user_id, imp.subject,
                                      imp.score, imp.verdict.name,
                                      [s.to_dict() for s in imp.top_reasons()])

        if not self.is_active(chat_id, "joinguard"):
            return
        decision = self.joinguard.observe_join(
            chat_id, display_name=p.get("display_name", ""),
            username=p.get("username", ""), invite=p.get("invite", ""))
        self.store.log_event(chat_id, "joinguard", user_id=user_id,
                             subject=str(chat_id), score=decision.assessment.score,
                             verdict=decision.state.value,
                             action=decision.state.value,
                             attack=",".join(decision.assessment.attack_tags))
        if decision.changed and decision.state == RaidState.RAID:
            raid_id = f"raid-{chat_id}-{int(decision.metrics.get('rate', 0))}"
            self._emit("raid.detected", {
                "chat_id": chat_id, "raid_id": raid_id,
                "reason": "join-rate/name-cluster anomaly", "severity": "high",
                "category": "RAID", "detection_type": "raid"})
            await self._enter_lockdown(chat_id, decision)
        # challenge new joiners while elevated/raid
        if decision.challenge_required:
            await self._issue_challenge(chat_id, user_id, p)

    async def on_member_left(self, event) -> None:
        try:
            p = event.payload if hasattr(event, "payload") else event
            if p.get("chat_id") is not None:
                self.joinguard.record_leave(p["chat_id"])
        except Exception:
            self.log.exception("BLUETEAM | on_member_left failed")

    async def _fetch_admin_targets(self, chat_id: int) -> List[Target]:
        out: List[Target] = []
        try:
            admins = await self.actions.call("get_chat_administrators", chat_id)
            for a in (admins or []):
                out.append(Target(user_id=a.get("user_id"), display_name=a.get("display_name", ""),
                                  username=a.get("username", ""), role="admin"))
        except Exception:
            pass
        return out

    async def _issue_challenge(self, chat_id, user_id, p) -> None:
        from . import challenge as ch
        c = ch.build_challenge(ttl_seconds=120)
        self.store.create_challenge(chat_id, user_id, c.nonce, c.answer, c.ttl_seconds)
        buttons = c.buttons(self._hmac_secret, chat_id, user_id)
        await self.actions.call("restrict_user", chat_id, user_id, None)  # mute until verified
        await self.actions.call("send_challenge", chat_id, user_id,
                                msg("jg_challenge", timeout=c.ttl_seconds),
                                c.prompt_emoji, buttons)

    async def _enter_lockdown(self, chat_id, decision) -> None:
        import time
        # snapshot current permissions, then restrict new members
        current = await self.actions.call("get_chat_permissions", chat_id)
        until = int(time.time()) + 3600     # dead-man switch: auto-lift after 1h
        self.store.save_perm_snapshot(chat_id, current or {}, lockdown_until=until)
        self.store.set_raid_state(chat_id, "RAID", meta={"lockdown": True})
        await self.actions.call("set_chat_permissions", chat_id,
                                {"can_send_messages": False})
        await self.actions.call("send_message", chat_id,
                                msg("jg_lockdown_on", minutes=60))

    async def lift_lockdown(self, chat_id: int) -> bool:
        snap = self.store.get_perm_snapshot(chat_id)
        if not snap:
            return False
        await self.actions.call("set_chat_permissions", chat_id, snap["permissions"])
        self.store.clear_perm_snapshot(chat_id)
        self.store.set_raid_state(chat_id, "NORMAL")
        await self.actions.call("send_message", chat_id, msg("jg_lockdown_off"))
        return True

    async def restore_lockdowns_on_startup(self) -> int:
        """Dead-man switch: lift any lockdown whose max time elapsed (called at boot)."""
        import time
        now = int(time.time())
        restored = 0
        for snap in self.store.active_lockdowns():
            if snap.get("lockdown_until") and snap["lockdown_until"] <= now:
                if await self.lift_lockdown(snap["chat_id"]):
                    restored += 1
        return restored

    # ---- challenge callback ----------------------------------------------
    async def handle_challenge_callback(self, chat_id: int, presser_id: int,
                                        callback_data: str) -> str:
        from . import challenge as ch
        valid, choice, nonce = ch.verify_callback(self._hmac_secret, chat_id,
                                                  presser_id, callback_data)
        if not valid:
            return msg("jg_not_your_challenge")
        row = self.store.get_challenge(chat_id, presser_id)
        if not row or row["status"] != "PENDING":
            return msg("jg_challenge_expired")
        import time
        if row["expires_at"] < time.time():
            self.store.set_challenge_status(chat_id, presser_id, "EXPIRED")
            return msg("jg_challenge_expired")
        if choice == row["answer"] and nonce == row["nonce"]:
            self.store.set_challenge_status(chat_id, presser_id, "PASSED")
            await self.actions.call("restrict_user", chat_id, presser_id,
                                    {"can_send_messages": True}, )
            return msg("jg_passed")
        attempts = self.store.bump_challenge_attempt(chat_id, presser_id)
        if attempts >= 3:
            self.store.set_challenge_status(chat_id, presser_id, "FAILED")
            await self.actions.call("ban_user", chat_id, presser_id)
            await self.actions.call("unban_user", chat_id, presser_id)  # kick, not perma-ban
            return msg("jg_failed")
        return msg("jg_failed")

    # ---- helpers ----------------------------------------------------------
    @staticmethod
    def _reasons_text(a: Assessment, n: int = 3) -> str:
        return "\n".join(f"• {s.fact}" for s in a.top_reasons(n))


# ---- process-wide runtime registry (shared by plugins + sg_platform) -----
_runtimes: Dict[str, BlueTeamRuntime] = {}


def get_runtime(db_path: str = "bot.db",
                emit: Optional[Callable[[str, dict], None]] = None) -> BlueTeamRuntime:
    rt = _runtimes.get(db_path)
    if rt is None:
        rt = BlueTeamRuntime(db_path, emit=emit)
        _runtimes[db_path] = rt
    elif emit is not None:
        rt._emit = emit
    return rt


def attach_bot(db_path: str, actions: TelegramActions) -> None:
    """Called by sg_platform when the bot exists, to wire Telegram side-effects."""
    rt = _runtimes.get(db_path)
    if rt is not None:
        rt.actions = actions
