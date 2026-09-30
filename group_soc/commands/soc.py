"""
group_soc/commands/soc.py — the /soc command dispatcher.

A single dispatcher turns ``/soc <sub> <args…>`` into a call to the matching area
handler. Every handler is a pure function returning text; the plugin wraps this service
with a Telegram adapter and the platform's is_admin gate, so nothing here imports
Telegram. ``dispatch`` never raises — an unexpected error becomes a clean message.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from ..util import hash_id
from ..metrics import performance_snapshot
from . import events as events_cmd
from . import alerts as alerts_cmd
from . import cases as cases_cmd
from . import incidents as incidents_cmd
from . import timeline as timeline_cmd
from . import investigation as investigation_cmd
from . import watchlist as watchlist_cmd
from . import reports as reports_cmd

logger = logging.getLogger("modbot.group_soc.commands")

_HELP = (
    "🛡 SOMBRA SOC — commands\n"
    "/soc overview | status | health | metrics\n"
    "/soc on | off              (activate/deactivate this group)\n"
    "/soc events [recent|search <type>|timeline <corr>|<id>]\n"
    "/soc alerts [list|<id>|ack <id>|suppress <id>|escalate <id>|assign <id>]\n"
    "/soc cases [list|<id>|create <title>|assign <id>|note <id> <text>|close <id>]\n"
    "/soc incident [list|<id>|create <class> <title>|resolve <id>|timeline <id>|story <id>]\n"
    "/soc investigate [list|open <title>|hypothesis <id> <text>|evidence <id> <kind> <ref>]\n"
    "/soc pivot [actor <hash>|entity <kind> <key>|related <corr>]\n"
    "/soc watch <kind> <value> | /soc unwatch <kind> <value> | /soc watchlist\n"
    "/soc report [daily|weekly|executive|technical|incident <id>]"
)


class SocCommandService:
    def __init__(self, runtime):
        self.rt = runtime

    def dispatch(self, chat_id: int, actor_id: Optional[int], args: List[str]) -> str:
        actor_hash = hash_id(actor_id)
        sub = (args[0].lower() if args else "overview")
        rest = args[1:]
        try:
            return self._route(sub, chat_id, actor_hash, actor_id, rest)
        except Exception:
            logger.exception("SOC command failed: %s", sub)
            return "⚠️ SOC command error (see logs)."

    def _route(self, sub, chat_id, actor_hash, actor_id, rest) -> str:
        if sub in ("overview", ""):
            return self._overview(chat_id)
        if sub == "status":
            return self._status(chat_id)
        if sub == "health":
            return self._health(chat_id)
        if sub == "metrics":
            return self._metrics(chat_id)
        if sub in ("on", "enable"):
            self.rt.storage.set_policy(chat_id, enabled=True, mode="alert", updated_by=actor_id)
            self.rt.storage.audit(chat_id, "soc.activated", actor_hash=actor_hash)
            return "✅ SOC activated for this group (mode=alert)."
        if sub in ("off", "disable"):
            self.rt.storage.set_policy(chat_id, enabled=False, updated_by=actor_id)
            self.rt.storage.audit(chat_id, "soc.deactivated", actor_hash=actor_hash)
            return "✅ SOC deactivated for this group."
        if sub in ("events", "event"):
            return events_cmd.handle(self.rt, chat_id, actor_hash, rest)
        if sub in ("alerts", "alert"):
            return alerts_cmd.handle(self.rt, chat_id, actor_hash, rest)
        if sub in ("cases", "case"):
            return cases_cmd.handle(self.rt, chat_id, actor_hash, rest)
        if sub in ("incidents", "incident"):
            return incidents_cmd.handle(self.rt, chat_id, actor_hash, rest)
        if sub == "timeline":
            return timeline_cmd.handle(self.rt, chat_id, actor_hash, rest)
        if sub in ("investigate", "investigation"):
            return investigation_cmd.handle(self.rt, chat_id, actor_hash, rest)
        if sub == "pivot":
            return investigation_cmd.handle_pivot(self.rt, chat_id, actor_hash, rest)
        if sub == "watch":
            return watchlist_cmd.handle_watch(self.rt, chat_id, actor_hash, rest)
        if sub == "unwatch":
            return watchlist_cmd.handle_unwatch(self.rt, chat_id, actor_hash, rest)
        if sub == "watchlist":
            return watchlist_cmd.handle_list(self.rt, chat_id, actor_hash, rest)
        if sub in ("report", "reports"):
            return reports_cmd.handle(self.rt, chat_id, actor_hash, rest)
        return _HELP

    # ---- overview / status / health / metrics ----
    def _overview(self, chat_id: int) -> str:
        ov = self.rt.metrics.overview(chat_id)
        active = self.rt.storage.is_group_active(chat_id)
        return "\n".join([
            "🛡 SOMBRA SOC — overview",
            f"group active: {'yes' if active else 'no'}   master: {'on' if self.rt.config.enabled else 'off'}",
            f"events:    {ov['events']}",
            f"signals:   {ov['signals']}",
            f"alerts:    open {ov['alerts_open']}  " +
            " ".join(f"{k}={v}" for k, v in sorted(ov['alerts_by_status'].items())),
            f"cases:     " + (" ".join(f"{k}={v}" for k, v in sorted(ov['cases_by_status'].items())) or "none"),
            f"incidents: " + (" ".join(f"{k}={v}" for k, v in sorted(ov['incidents_by_status'].items())) or "none"),
            "",
            "Tip: /soc on to activate, /soc help for commands.",
        ])

    def _status(self, chat_id: int) -> str:
        cfg = self.rt.config
        policy = self.rt.storage.get_policy(chat_id)
        caps = ["ingest", "correlation", "detection", "alerting", "intel_enrichment", "emit_events"]
        cap_lines = [f"  {c}: {'on' if cfg.capability_enabled(c) else 'off'}" for c in caps]
        return "\n".join([
            "🛡 SOC status",
            f"master enabled: {cfg.enabled}",
            f"group policy:   enabled={bool(policy['enabled'])} mode={policy['mode']}",
            "capabilities:",
            *cap_lines,
            f"worker: {'running' if self.rt._started else 'idle'}  depth={self.rt.worker.depth()}",
        ])

    def _health(self, chat_id: int) -> str:
        h = self.rt.health()
        perf = h["performance"]
        integ = h["integrations"]
        return "\n".join([
            "🩺 SOC health",
            f"master enabled: {h['enabled']}   worker: {h['worker_started']}",
            f"queue depth {perf.get('queue_depth')}/{perf.get('queue_maxsize')}  "
            f"processed={perf.get('processed')}  dropped={perf.get('dropped_overflow')}",
            "integrations: " + ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in integ.items()),
        ])

    def _metrics(self, chat_id: int) -> str:
        ov = self.rt.metrics.overview(chat_id, window_s=86400)
        det = self.rt.detection_metrics.signal_breakdown(chat_id, window_s=86400)

        def _fmt_s(v):
            return "—" if v is None else (f"{v:.0f}s" if v < 90 else f"{v/60:.1f}m")

        lines = [
            "📊 SOC metrics (24h)",
            f"events={ov['events']} signals={ov['signals']} alerts_open={ov['alerts_open']}",
            f"MTTA={_fmt_s(ov['mtta_s'])}  MTTR={_fmt_s(ov['mttr_s'])}",
            "top producers:",
        ]
        for producer, n in list(det["by_producer"].items())[:8]:
            lines.append(f"  {n:>3}  {producer}")
        if not det["by_producer"]:
            lines.append("  (none)")
        return "\n".join(lines)
