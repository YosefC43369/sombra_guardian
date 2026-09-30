"""
purple_range/commands/range.py — the /range command dispatcher.

Pure text service (Telegram-free). The plugin wraps it with the platform's is_admin gate.
`dispatch` never raises — an unexpected error becomes a clean message. Governance note:
`instantiate` only *plans* an exercise via purpleteam; starting it (and the RoE re-check)
stays with the existing /pt flow, so this surface cannot bypass authorization.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from ..exceptions import PurpleRangeError
from ..attack import get_catalog
from . import formatting as fmt

logger = logging.getLogger("modbot.purple_range.commands")

_HELP = (
    "🛡 PURPLE RANGE — commands\n"
    "/range plans                         list emulation plans\n"
    "/range plan <code>                   plan detail (steps, expectations)\n"
    "/range instantiate <code> <eng_id>   plan → purpleteam exercise (admin)\n"
    "/range telemetry <technique> [n]     synthetic telemetry sample\n"
    "/range expectations <technique>      expected telemetry + rules\n"
    "/range coverage                      program-wide ATT&CK coverage\n"
    "/range snapshot                      save a coverage snapshot\n"
    "/range instantiations                recent plan→exercise links\n"
    "/range status                        module status/health\n"
    "\nEmulation-only: no agents, no execution. Start an exercise via /pt (RoE re-checked there)."
)


class RangeCommandService:
    def __init__(self, service):
        self.svc = service

    def dispatch(self, chat_id: int, actor_id: Optional[int], args: List[str]) -> str:
        sub = (args[0].lower() if args else "help")
        rest = args[1:]
        try:
            return self._route(sub, chat_id, actor_id, rest)
        except PurpleRangeError as exc:
            return f"❌ {exc.message}"
        except Exception:
            logger.exception("range command failed: %s", sub)
            return "⚠️ Purple Range command error (see logs)."

    def _route(self, sub, chat_id, actor_id, rest) -> str:
        if sub in ("help", ""):
            return _HELP
        if sub == "status":
            h = self.svc.health()
            return ("🛡 Purple Range\n"
                    f"enabled: {h['enabled']}   soc_bridge: {h['soc_bridge_enabled']}\n"
                    f"builtin plans: {h['builtin_plans']}   ATT&CK catalog: {h['attack_catalog']}")
        if sub == "plans":
            plans = self.svc.list_plans()
            if not plans:
                return "No plans."
            return "📚 Emulation plans:\n" + "\n".join("• " + fmt.plan_line(p) for p in plans)
        if sub == "plan" and rest:
            return fmt.plan_detail(self.svc.get_plan(rest[0]))
        if sub == "instantiate" and len(rest) >= 2:
            try:
                eng_id = int(rest[1])
            except ValueError:
                return "❌ engagement_id must be a number"
            res = self.svc.instantiate_plan(rest[0], chat_id, eng_id, actor_id or 0)
            return (f"✅ Instantiated '{rest[0]}' → exercise {res.exercise_code} "
                    f"(id={res.exercise_id}, {res.steps_added} emulations planned).\n"
                    f"Start it with /pt start {res.exercise_id} — RoE is re-checked there.")
        if sub == "telemetry" and rest:
            count = 1
            if len(rest) >= 2:
                try:
                    count = max(1, min(5, int(rest[1])))
                except ValueError:
                    count = 1
            events = self.svc.generate_telemetry(rest[0], per_type=count)
            return fmt.telemetry_sample(events)
        if sub == "expectations" and rest:
            exp = self.svc.expectations(rest[0])
            return fmt.expectation_detail(rest[0], exp, get_catalog().technique_name(rest[0]))
        if sub == "coverage":
            cells, summary = self.svc.coverage_matrix(chat_id)
            return fmt.coverage_report(cells, summary)
        if sub == "snapshot":
            out = self.svc.coverage_snapshot(chat_id, actor_id)
            s = out["summary"]
            return (f"📸 Coverage snapshot saved.\n"
                    f"techniques={s['total_techniques']} detection={s['detection']} "
                    f"({s['detection_pct']}%)")
        if sub == "instantiations":
            rows = self.svc.list_instantiations(chat_id)
            if not rows:
                return "No plan instantiations yet."
            return "🔗 Plan → exercise:\n" + "\n".join(
                f"• {r['plan_code']} → ex {r['exercise_code'] or r['exercise_id']} "
                f"({r['step_count']} steps)" for r in rows[:20])
        return _HELP
