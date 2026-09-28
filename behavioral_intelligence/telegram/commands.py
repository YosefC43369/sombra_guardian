"""
behavioral_intelligence.telegram.commands — Telegram command surface (spec §39,40).

Commands: /behavior /activity /heatmap /timeline /languages /topics /hashtags
/domains /interactions /anomalies /changes /baseline /behavior_report.

Design: the analytical logic lives in ``BehaviorCommandService`` (pure, returns
rendered strings — fully testable without a running bot). The ``async def cmd_*``
handlers are thin adapters that parse arguments, call the service, and reply.
``python-telegram-bot`` is imported defensively so this module imports in the
pure test environment; the handlers require it at call time.

AUTHORIZATION: these commands operate on account/person-level behaviour, which is
fail-closed. A command must carry an authorized ``program_id`` (parsed from a
``program=`` argument) AND the deployment must have set person scope for it;
otherwise the gate DENIES and the user is told exactly why. Telegram admin is
NEVER sufficient on its own — the same rule the entity_fusion gate enforces.
"""

from __future__ import annotations

import logging
from typing import Optional

from ..configuration import BehavioralConfig, get_config
from ..authorization import (BehaviorGate, AuthorizationContext, Subject,
                             GateDecision)
from ..engine import BehavioralEngine
from ..models.observation import ObservationBatch
from ..storage.observation_store import ObservationStore
from ..reports import BehavioralReportBuilder

logger = logging.getLogger("modbot.behavioral.telegram")

try:  # python-telegram-bot is a project dependency; import defensively for tests
    from telegram import Update
    from telegram.ext import ContextTypes, CommandHandler
    HAVE_PTB = True
except Exception:  # pragma: no cover
    Update = object
    ContextTypes = None
    CommandHandler = None
    HAVE_PTB = False

_TELEGRAM_LIMIT = 3900     # keep replies under Telegram's 4096-char message cap


class BehaviorCommandService:
    """Pure command implementations returning rendered text. Reused by tests and
    by the thin async handlers."""

    def __init__(self, *, config: Optional[BehavioralConfig] = None,
                 store: Optional[ObservationStore] = None,
                 gate: Optional[BehaviorGate] = None):
        self.config = config or get_config()
        self.store = store or ObservationStore(db_path=self.config.db_path)
        self.gate = gate or BehaviorGate()
        self.engine = BehavioralEngine(config=self.config, gate=self.gate,
                                       store=self.store.store)
        self.reports = BehavioralReportBuilder(self.config)

    # -- argument parsing -------------------------------------------------- #

    @staticmethod
    def parse_args(args) -> "tuple[str, Optional[int], dict]":
        """Return (target, program_id, options) from raw command args. Supports
        ``program=<id>`` and ``tz=<hours>``; the first bare token is the target."""
        target = ""
        program_id: Optional[int] = None
        opts: dict = {}
        for a in (args or []):
            if a.startswith("program="):
                try:
                    program_id = int(a.split("=", 1)[1])
                except ValueError:
                    pass
            elif a.startswith("tz="):
                try:
                    opts["tz"] = float(a.split("=", 1)[1])
                except ValueError:
                    pass
            elif not target:
                target = a
        return target, program_id, opts

    def _context(self, program_id: Optional[int], actor: str) -> AuthorizationContext:
        return AuthorizationContext(program_id=program_id,
                                    allow_person_scope=program_id is not None,
                                    actor=actor)

    def _load(self, target: str) -> ObservationBatch:
        return self.store.load_batch(target)

    def _authorize_or_message(self, ctx: AuthorizationContext, target: str
                              ) -> Optional[str]:
        d: GateDecision = self.gate.authorize(ctx, Subject.ACCOUNT, target)
        if d.allowed:
            return None
        return (f"⛔ Not authorized to analyse `{target}`.\n"
                f"Reason: {d.reason} — {d.detail}\n"
                f"Account/person behavioural analysis requires an authorized "
                f"scope_policy program (pass `program=<id>`) covering this subject. "
                f"Telegram admin alone is not sufficient.")

    # -- command implementations (return text) ---------------------------- #

    def behavior(self, target: str, program_id: Optional[int], actor: str = "") -> str:
        if not target:
            return "Usage: /behavior <entity_id|account> program=<id>"
        ctx = self._context(program_id, actor)
        denied = self._authorize_or_message(ctx, target)
        if denied:
            return denied
        batch = self._load(target)
        if not len(batch):
            return f"No stored observations for `{target}`. Collect first."
        profile = self.engine.analyze_entity(batch, ctx)
        return self._telegram_summary(profile)

    def _section(self, target, program_id, actor, fn_name: str) -> str:
        if not target:
            return f"Usage: /{fn_name} <entity_id> program=<id>"
        ctx = self._context(program_id, actor)
        denied = self._authorize_or_message(ctx, target)
        if denied:
            return denied
        batch = self._load(target)
        if not len(batch):
            return f"No stored observations for `{target}`."
        return getattr(self, f"_render_{fn_name}")(batch, ctx)

    def _render_activity(self, batch, ctx) -> str:
        p = self.engine.analyze_entity(batch, ctx)
        a = p.activity
        lo = f"{a.posts_per_day:.2f}/day over {a.period_days:.0f}d, " \
             f"{a.active_days} active days" if a else "n/a"
        peak = p.peak_windows[0].label() if p.peak_windows else "n/a"
        return (f"📊 Activity — {batch.entity_id}\n"
                f"{a.sample_size if a else 0} observations · {lo}\n"
                f"Peak window: {peak}\n"
                f"Bursts: {len(p.bursts)} · Inactivity gaps: {len(p.inactivity)}")

    def _render_heatmap(self, batch, ctx) -> str:
        p = self.engine.analyze_entity(batch, ctx)
        hm = p.heatmap
        if not hm:
            return "No hourly data."
        r, c, v = hm.hottest()
        return (f"🗓 Heatmap (UTC hour × weekday) — {batch.entity_id}\n"
                f"Hottest cell: {r} {c}:00 with {v} observations.\n"
                f"(Full grid available in the HTML report.)")

    def _render_timeline(self, batch, ctx) -> str:
        t = self.engine.build_timeline(batch, ctx)
        lines = [f"🧭 Timeline — {batch.entity_id} ({len(t.events)} events)"]
        for e in t.sorted_events()[:12]:
            from datetime import datetime, timezone
            d = datetime.fromtimestamp(e.at, tz=timezone.utc).strftime("%Y-%m-%d")
            lines.append(f"• {d}: {e.label or e.kind}")
        return "\n".join(lines)

    def _render_languages(self, batch, ctx) -> str:
        res = self.engine.analyze_languages(batch, ctx)
        dist = res["distribution"]["shares"]
        top = sorted(dist.items(), key=lambda kv: kv[1], reverse=True)[:6]
        body = "\n".join(f"  {lang}: {share*100:.0f}%" for lang, share in top)
        return (f"🗣 Languages — {batch.entity_id}\n{body}\n"
                f"Switching freq: {res['switching_frequency']:.1f}/100 posts\n"
                f"_Language use is observed; nationality is NOT inferred._")

    def _render_topics(self, batch, ctx) -> str:
        res = self.engine.analyze_topics(batch, ctx)
        kws = ", ".join(k["term"] for k in res["keywords"][:10])
        return f"🔖 Topics — {batch.entity_id}\nTop terms: {kws or 'n/a'}"

    def _render_hashtags(self, batch, ctx) -> str:
        res = self.engine.analyze_topics(batch, ctx)
        tags = res["hashtags"][:12]
        body = " ".join(f"#{h['tag']}({h['frequency']})" for h in tags)
        return f"#️⃣ Hashtags — {batch.entity_id}\n{body or 'none'}"

    def _render_domains(self, batch, ctx) -> str:
        p = self.engine.analyze_entity(batch, ctx)
        body = "\n".join(f"  {d.domain} ×{d.frequency}" for d in p.domains[:12])
        return f"🌐 Domains — {batch.entity_id}\n{body or 'none'}"

    def _render_interactions(self, batch, ctx) -> str:
        res = self.engine.analyze_interactions(batch, ctx)
        net = res["network"]
        lines = [f"🕸 Interactions — {batch.entity_id}",
                 f"{len(net['edges'])} edges · reciprocity {net['reciprocity']:.2f}"]
        for e in net["edges"][:8]:
            lines.append(f"  {e['source']} → {e['target']} ×{e['count']}")
        lines.append("_Observed public acts; no private relationship inferred._")
        return "\n".join(lines)

    def _render_anomalies(self, batch, ctx) -> str:
        score, anomalies, _ = self.engine.detect_anomalies(batch, ctx)
        lines = [f"⚠️ Anomalies — {batch.entity_id}",
                 f"Deviation score: {score.score:.0f}/100 ({score.band}) "
                 f"— relative to own baseline, not a threat score."]
        for a in anomalies[:6]:
            lines.append(f"• [{a.severity}] {a.description}")
        return "\n".join(lines)

    def _render_changes(self, batch, ctx) -> str:
        t = self.engine.build_timeline(batch, ctx)
        cps = [e for e in t.sorted_events()
               if "change" in e.kind or "migration" in e.kind]
        lines = [f"🔀 Changes — {batch.entity_id} ({len(cps)})"]
        for e in cps[:12]:
            from datetime import datetime, timezone
            d = datetime.fromtimestamp(e.at, tz=timezone.utc).strftime("%Y-%m-%d")
            lines.append(f"• {d}: {e.label or e.kind}")
        return "\n".join(lines)

    def _render_baseline(self, batch, ctx) -> str:
        b = self.engine.build_baseline(batch, ctx, window_days=30)
        return (f"📐 Baseline (30d) — {batch.entity_id}\n"
                f"{b.posts_per_day:.2f} posts/day · sample {b.sample_size}\n"
                f"Top languages: " +
                ", ".join(f"{k} {v*100:.0f}%" for k, v in
                          sorted(b.language_distribution.items(),
                                 key=lambda kv: -kv[1])[:4]))

    def behavior_report(self, target: str, program_id: Optional[int],
                        actor: str = "", fmt: str = "markdown") -> str:
        if not target:
            return "Usage: /behavior_report <entity_id> program=<id>"
        ctx = self._context(program_id, actor)
        denied = self._authorize_or_message(ctx, target)
        if denied:
            return denied
        batch = self._load(target)
        if not len(batch):
            return f"No stored observations for `{target}`."
        profile = self.engine.analyze_entity(batch, ctx)
        md = self.reports.markdown(profile)
        return md[:_TELEGRAM_LIMIT] + ("\n… (truncated; full report via HTML export)"
                                       if len(md) > _TELEGRAM_LIMIT else "")

    def _telegram_summary(self, profile) -> str:
        """The compact multi-section summary of spec §40."""
        from datetime import datetime, timezone
        p = profile
        def d(x):
            return datetime.fromtimestamp(x, tz=timezone.utc).strftime("%Y-%m-%d") \
                if x else "—"
        langs = ""
        if p.languages and p.languages.shares:
            top = sorted(p.languages.shares.items(), key=lambda kv: kv[1],
                         reverse=True)[:3]
            langs = " · ".join(f"{k} {v*100:.0f}%" for k, v in top)
        peak = p.peak_windows[0].label() if p.peak_windows else "—"
        topics = ", ".join(k.term for k in p.keywords[:5]) or "—"
        anomaly = (f"{p.anomaly_score.score:.0f}/100 ({p.anomaly_score.band})"
                   if p.anomaly_score else "—")
        scored = [a for a in p.assertions if a.confidence]
        conf = (sum(a.score for a in scored) / len(scored)) if scored else 0.0
        srcs = len({o for o in (s.get("provider") for s in p.provider_status)
                    if o}) or len({e.provider for a in scored for e in a.evidence
                                   if e.provider})
        lines = [
            "🔍 *Behavioral Intelligence*",
            f"Entity: {p.label or p.entity_id}",
            f"Observation period: {d(p.period_start)} → {d(p.period_end)}",
            f"Public observations: {p.sample_size:,}",
            f"Platforms: {len(p.platforms)}",
            f"Languages: {langs or '—'}",
            f"Peak activity: {peak}",
            f"Top topics: {topics}",
            f"Anomaly: {anomaly} (deviation from baseline, not a threat score)",
            f"Confidence: {conf:.2f}",
            f"Evidence: {srcs} independent public source(s)",
            "Limitations: reflects only publicly observed data; describes activity "
            "patterns, not the person.",
        ]
        return "\n".join(lines)


# -- thin async handlers ---------------------------------------------------- #

_service: Optional[BehaviorCommandService] = None


def _svc() -> BehaviorCommandService:
    global _service
    if _service is None:
        _service = BehaviorCommandService()
    return _service


async def _reply(update, text: str) -> None:
    if update and getattr(update, "message", None):
        await update.message.reply_text(text[:4096], disable_web_page_preview=True)


def _actor(update) -> str:
    try:
        return str(update.effective_user.id)
    except Exception:
        return ""


async def cmd_behavior(update, context) -> None:
    target, program, _ = _svc().parse_args(getattr(context, "args", []))
    await _reply(update, _svc().behavior(target, program, _actor(update)))


async def cmd_activity(update, context) -> None:
    target, program, _ = _svc().parse_args(getattr(context, "args", []))
    await _reply(update, _svc()._section(target, program, _actor(update), "activity"))


async def cmd_heatmap(update, context) -> None:
    target, program, _ = _svc().parse_args(getattr(context, "args", []))
    await _reply(update, _svc()._section(target, program, _actor(update), "heatmap"))


async def cmd_timeline(update, context) -> None:
    target, program, _ = _svc().parse_args(getattr(context, "args", []))
    await _reply(update, _svc()._section(target, program, _actor(update), "timeline"))


async def cmd_languages(update, context) -> None:
    target, program, _ = _svc().parse_args(getattr(context, "args", []))
    await _reply(update, _svc()._section(target, program, _actor(update), "languages"))


async def cmd_topics(update, context) -> None:
    target, program, _ = _svc().parse_args(getattr(context, "args", []))
    await _reply(update, _svc()._section(target, program, _actor(update), "topics"))


async def cmd_hashtags(update, context) -> None:
    target, program, _ = _svc().parse_args(getattr(context, "args", []))
    await _reply(update, _svc()._section(target, program, _actor(update), "hashtags"))


async def cmd_domains(update, context) -> None:
    target, program, _ = _svc().parse_args(getattr(context, "args", []))
    await _reply(update, _svc()._section(target, program, _actor(update), "domains"))


async def cmd_interactions(update, context) -> None:
    target, program, _ = _svc().parse_args(getattr(context, "args", []))
    await _reply(update, _svc()._section(target, program, _actor(update), "interactions"))


async def cmd_anomalies(update, context) -> None:
    target, program, _ = _svc().parse_args(getattr(context, "args", []))
    await _reply(update, _svc()._section(target, program, _actor(update), "anomalies"))


async def cmd_changes(update, context) -> None:
    target, program, _ = _svc().parse_args(getattr(context, "args", []))
    await _reply(update, _svc()._section(target, program, _actor(update), "changes"))


async def cmd_baseline(update, context) -> None:
    target, program, _ = _svc().parse_args(getattr(context, "args", []))
    await _reply(update, _svc()._section(target, program, _actor(update), "baseline"))


async def cmd_behavior_report(update, context) -> None:
    target, program, _ = _svc().parse_args(getattr(context, "args", []))
    await _reply(update, _svc().behavior_report(target, program, _actor(update)))


COMMANDS = {
    "behavior": cmd_behavior, "activity": cmd_activity, "heatmap": cmd_heatmap,
    "timeline": cmd_timeline, "languages": cmd_languages, "topics": cmd_topics,
    "hashtags": cmd_hashtags, "domains": cmd_domains,
    "interactions": cmd_interactions, "anomalies": cmd_anomalies,
    "changes": cmd_changes, "baseline": cmd_baseline,
    "behavior_report": cmd_behavior_report,
}


def _existing_commands(application) -> set:
    """Command strings already registered on the Application, so we never shadow
    an existing command (e.g. the member-incident /timeline)."""
    found: set = set()
    try:
        for group in getattr(application, "handlers", {}).values():
            for h in group:
                cmds = getattr(h, "commands", None)
                if cmds:
                    found |= {str(c) for c in cmds}
    except Exception:  # pragma: no cover - defensive
        pass
    return found


def register(application, *, service: Optional[BehaviorCommandService] = None,
             prefix: str = "") -> int:
    """Register the behavioural commands on a python-telegram-bot Application.

    Collision-safe: a command whose name is already registered is skipped (with a
    warning) rather than shadowing the existing handler. Pass ``prefix`` (e.g.
    ``"bi_"``) to register under a namespace instead of skipping. Returns the
    number of handlers added; no-op (0) if PTB is absent."""
    global _service
    if service is not None:
        _service = service
    if not HAVE_PTB or CommandHandler is None:
        logger.warning("python-telegram-bot unavailable; behavioural commands "
                       "not registered")
        return 0
    existing = _existing_commands(application)
    added = 0
    for name, handler in COMMANDS.items():
        cmd = f"{prefix}{name}"
        if cmd in existing:
            logger.warning("behavioural command /%s already registered; skipping "
                           "(use prefix= to namespace)", cmd)
            continue
        application.add_handler(CommandHandler(cmd, handler))
        added += 1
    logger.info("registered %d behavioural intelligence commands (prefix=%r)",
                added, prefix)
    return added
