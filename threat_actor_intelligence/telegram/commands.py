"""
threat_actor_intelligence.telegram.commands — the CTI command surface.

Commands (spec TELEGRAM COMMANDS):
  /actor /campaign /malware /ioc /attack /capec /report /timeline
  /actor_graph /campaign_graph /ioc_report

Design mirrors ``behavioral_intelligence.telegram``: the analytical logic lives
in ``TAICommandService`` (pure, returns rendered strings — fully testable without
a running bot); the ``async def cmd_*`` handlers are thin adapters that parse
args, call the service and reply. ``python-telegram-bot`` is imported defensively
so this module imports in the pure test environment.

These commands are read-only CTI queries over public data; they carry no
destructive action and expose no secrets.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from ..configuration import TAIConfig, get_config
from ..engine import ThreatActorIntelligenceEngine

logger = logging.getLogger("modbot.tai.telegram")

try:
    from telegram import Update
    from telegram.ext import ContextTypes, CommandHandler
    HAVE_PTB = True
except Exception:  # pragma: no cover
    Update = object
    ContextTypes = None
    CommandHandler = None
    HAVE_PTB = False

_TELEGRAM_LIMIT = 3900

COMMANDS = ["actor", "campaign", "malware", "ioc", "attack", "capec", "report",
            "timeline", "actor_graph", "campaign_graph", "ioc_report"]


def _truncate(text: str, limit: int = _TELEGRAM_LIMIT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit - 40].rstrip() + "\n… (truncated; use /report for full)"


class TAICommandService:
    """Pure command implementations returning rendered text."""

    def __init__(self, *, config: Optional[TAIConfig] = None,
                 engine: Optional[ThreatActorIntelligenceEngine] = None):
        self.config = config or get_config()
        self.engine = engine or ThreatActorIntelligenceEngine(config=self.config)

    # -- helpers ----------------------------------------------------------- #

    @staticmethod
    def _arg(args, default: str = "") -> str:
        return " ".join(a for a in (args or []) if "=" not in a).strip() or default

    @staticmethod
    def _opt(args, key: str, default: str = "") -> str:
        for a in (args or []):
            if a.startswith(key + "="):
                return a.split("=", 1)[1]
        return default

    # -- commands ---------------------------------------------------------- #

    def cmd_actor(self, args) -> str:
        name = self._arg(args)
        if not name:
            return "Usage: /actor <name|alias> — e.g. /actor APT29"
        d = self.engine.actor_report(name, fmt="dict")
        if d is None:
            hits = self.engine.actors_for_alias(name)
            if hits:
                return ("No exact match. Candidates by alias:\n" +
                        "\n".join(f"• {a.canonical_name} (`{a.actor_id}`)" for a in hits))
            return f"No actor found for '{name}'. Try /actor <alias> or ingest more data."
        ident = d["identity"]
        conf = d.get("confidence") or {}
        lines = [f"🎯 *{ident['canonical_name']}* ({ident['actor_type']})",
                 d["executive_summary"], ""]
        if d["aliases"]:
            lines.append("*Aliases:* " + ", ".join(a["name"] for a in d["aliases"]))
        if d["malware_relationships"]:
            lines.append("*Malware:* " + ", ".join(
                m["name"] for m in d["malware_relationships"]))
        if d["campaigns"]:
            lines.append("*Campaigns:* " + ", ".join(c["name"] for c in d["campaigns"]))
        cov = d["attack_coverage"]
        lines.append(f"*ATT&CK:* {cov['tactics_covered']}/{cov['tactics_total']} "
                     f"tactics, {cov['techniques']} techniques")
        vic = d["victimology"]
        if vic.get("countries"):
            lines.append("*Targeted countries:* " + ", ".join(vic["countries"]))
        if vic.get("sectors"):
            lines.append("*Targeted sectors:* " + ", ".join(vic["sectors"]))
        lines.append(f"*Confidence:* {conf.get('band', 'n/a')} "
                     f"({conf.get('score_100', 0)}/100)")
        lines.append("_Public-source CTI; aliases are not identity; no attribution "
                     "beyond cited sources._")
        return _truncate("\n".join(lines))

    def cmd_campaign(self, args) -> str:
        name = self._arg(args)
        if not name:
            return "Usage: /campaign <name> — e.g. /campaign SolarWinds Compromise"
        d = self.engine.campaign_report(name, fmt="dict")
        if d is None:
            return f"No campaign found for '{name}'."
        ident = d["identity"]
        conf = d.get("confidence") or {}
        lines = [f"📁 *{ident['campaign_name']}*", d["executive_summary"], ""]
        if d["attributed_actors"]:
            lines.append("*Actors:* " + ", ".join(
                a["name"] for a in d["attributed_actors"]))
        if d["malware_relationships"]:
            lines.append("*Malware:* " + ", ".join(
                m["name"] for m in d["malware_relationships"]))
        lines.append(f"*IOCs:* {len(d['iocs'])} · *Duration:* "
                     f"{ident.get('duration_days', 0)}d")
        lines.append(f"*Confidence:* {conf.get('band', 'n/a')} "
                     f"({conf.get('score_100', 0)}/100)")
        return _truncate("\n".join(lines))

    def cmd_malware(self, args) -> str:
        name = self._arg(args)
        if not name:
            return "Usage: /malware <family> — e.g. /malware SUNBURST"
        d = self.engine.malware_report(name, fmt="dict")
        if d is None:
            return f"No malware family found for '{name}'."
        ident = d["identity"]
        conf = d.get("confidence") or {}
        lines = [f"🦠 *{ident['name']}* ({ident.get('category', 'n/a')})",
                 d["executive_summary"], ""]
        if d["aliases"]:
            lines.append("*Aliases:* " + ", ".join(a["name"] for a in d["aliases"]))
        if ident.get("platforms"):
            lines.append("*Platforms:* " + ", ".join(ident["platforms"]))
        kh = d["known_hashes"]
        lines.append(f"*Known public sample refs:* {kh['count']}")
        lines.append(f"*Confidence:* {conf.get('band', 'n/a')} "
                     f"({conf.get('score_100', 0)}/100)")
        return _truncate("\n".join(lines))

    def cmd_ioc(self, args) -> str:
        value = self._arg(args)
        if not value:
            return "Usage: /ioc <indicator> — e.g. /ioc evil.example.com"
        r = self.engine.lookup_ioc(value)
        if r is None:
            return f"No stored IOC matching '{value}'."
        ioc = r["ioc"]
        lines = [f"🔎 *IOC* `{ioc['defanged']}` ({ioc['type']})"]
        if ioc.get("malware"):
            lines.append("*Malware:* " + ioc["malware"])
        if ioc.get("campaign"):
            lines.append("*Campaign:* " + ioc["campaign"])
        if ioc.get("actor"):
            lines.append("*Actor:* " + ioc["actor"])
        lines.append(f"*Sources:* {len(ioc.get('evidence', []))}")
        lines.append(f"*Related:* {len(r['relationships'])} link(s)")
        return _truncate("\n".join(lines))

    def cmd_attack(self, args) -> str:
        tid = self._arg(args)
        if not tid:
            return "Usage: /attack <T####|name> — e.g. /attack T1566"
        d = self.engine.technique(tid)
        if d is None:
            return f"No ATT&CK technique matching '{tid}'."
        t = d["technique"]
        lines = [f"⚔️ *{t['technique_id']} — {t['name']}*"]
        if t.get("tactics"):
            lines.append("*Tactics:* " + ", ".join(t["tactics"]))
        if d["mitigations"]:
            lines.append("*Mitigations:* " + ", ".join(
                m["name"] for m in d["mitigations"]))
        if d["capec"]:
            lines.append("*CAPEC:* " + ", ".join(p["capec_id"] for p in d["capec"]))
        if t.get("description"):
            lines.append("\n" + t["description"][:600])
        return _truncate("\n".join(lines))

    def cmd_capec(self, args) -> str:
        cid = self._arg(args)
        if not cid:
            return "Usage: /capec <CAPEC-##> — e.g. /capec CAPEC-98"
        if not cid.upper().startswith("CAPEC-") and cid.isdigit():
            cid = f"CAPEC-{cid}"
        p = self.engine.capec_pattern(cid)
        if p is None:
            return f"No CAPEC pattern matching '{cid}'."
        lines = [f"🧩 *{p['capec_id']} — {p['name']}*"]
        if p.get("abstraction"):
            lines.append("*Abstraction:* " + p["abstraction"])
        if p.get("related_techniques"):
            lines.append("*ATT&CK:* " + ", ".join(p["related_techniques"]))
        if p.get("related_weaknesses"):
            lines.append("*CWE:* " + ", ".join(p["related_weaknesses"]))
        return _truncate("\n".join(lines))

    def cmd_report(self, args) -> str:
        name = self._arg(args)
        fmt = self._opt(args, "fmt", "markdown")
        kind = self._opt(args, "type", "")
        if not name:
            return "Usage: /report <actor|campaign|malware name> [type=actor] [fmt=markdown]"
        for builder, k in ((self.engine.actor_report, "actor"),
                           (self.engine.campaign_report, "campaign"),
                           (self.engine.malware_report, "malware")):
            if kind and kind != k:
                continue
            out = builder(name, fmt=fmt)
            if out:
                return _truncate(out if isinstance(out, str) else str(out))
        return f"No entity found for '{name}'."

    def cmd_timeline(self, args) -> str:
        name = self._arg(args)
        if not name:
            return "Usage: /timeline <actor|campaign>"
        tl = self.engine.timeline(name)
        if tl is None:
            return f"No timeline for '{name}'."
        lines = [f"🕒 *Timeline* — {tl.get('event_count', 0)} events "
                 f"({tl.get('period_start_iso', '')} → {tl.get('period_end_iso', '')})",
                 ""]
        for ev in tl.get("events", [])[:30]:
            lines.append(f"`{ev.get('iso', '')[:10]}` {ev.get('kind')}: {ev.get('label')}")
        return _truncate("\n".join(lines))

    def cmd_actor_graph(self, args) -> str:
        name = self._arg(args)
        fmt = self._opt(args, "fmt", "json")
        if not name:
            return "Usage: /actor_graph <name> [fmt=json|dot|graphml|gexf]"
        g = self.engine.actor_graph(name, fmt=fmt)
        if g is None:
            return f"No actor found for '{name}'."
        return _truncate(g)

    def cmd_campaign_graph(self, args) -> str:
        name = self._arg(args)
        fmt = self._opt(args, "fmt", "json")
        if not name:
            return "Usage: /campaign_graph <name> [fmt=json|dot|graphml|gexf]"
        g = self.engine.campaign_graph(name, fmt=fmt)
        if g is None:
            return f"No campaign found for '{name}'."
        return _truncate(g)

    def cmd_ioc_report(self, args) -> str:
        name = self._arg(args)
        fmt = self._opt(args, "fmt", "csv")
        if not name:
            return "Usage: /ioc_report <campaign name> [fmt=csv|json]"
        d = self.engine.campaign_report(name, fmt="dict")
        if d is None:
            return f"No campaign found for '{name}'."
        from ..reports import csv_report, json_report
        if fmt == "json":
            return _truncate(json_report.render({"iocs": d["iocs"]}))
        return _truncate(csv_report.ioc_csv(d) or "no IOCs")


# -- thin async handlers ---------------------------------------------------- #

_service_singleton: Optional[TAICommandService] = None


def _svc() -> TAICommandService:
    global _service_singleton
    if _service_singleton is None:
        _service_singleton = TAICommandService()
    return _service_singleton


def _make_handler(method_name: str):  # pragma: no cover - requires PTB
    async def handler(update, context):
        svc = _svc()
        method = getattr(svc, method_name)
        try:
            text = method(context.args if context else [])
        except Exception as exc:
            logger.exception("tai command failed")
            text = f"Command failed: {exc}"
        if update and getattr(update, "message", None):
            await update.message.reply_text(text, parse_mode="Markdown",
                                            disable_web_page_preview=True)
    return handler


_HANDLER_MAP = {
    "actor": "cmd_actor", "campaign": "cmd_campaign", "malware": "cmd_malware",
    "ioc": "cmd_ioc", "attack": "cmd_attack", "capec": "cmd_capec",
    "report": "cmd_report", "timeline": "cmd_timeline",
    "actor_graph": "cmd_actor_graph", "campaign_graph": "cmd_campaign_graph",
    "ioc_report": "cmd_ioc_report",
}


def register(application, *, service: Optional[TAICommandService] = None) -> int:
    """Register the CTI commands on a python-telegram-bot Application. Collision-
    safe: skips a command already registered by another module. Returns count."""
    if not HAVE_PTB or application is None:  # pragma: no cover
        return 0
    global _service_singleton
    if service is not None:
        _service_singleton = service
    existing = set()
    try:  # pragma: no cover
        handlers = getattr(application, "handlers", {})
        # PTB uses {group: [handler, ...]}; tolerate a flat list too so the
        # collision check never silently no-ops and double-registers a command.
        groups = handlers.values() if hasattr(handlers, "values") else [handlers]
        for group in groups:
            for h in group:
                cmds = getattr(h, "commands", None)
                if cmds:
                    existing.update(str(c) for c in cmds)
    except Exception:  # pragma: no cover
        pass
    n = 0
    for cmd, method in _HANDLER_MAP.items():  # pragma: no cover
        if cmd in existing:
            continue
        application.add_handler(CommandHandler(cmd, _make_handler(method)))
        n += 1
    return n


__all__ = ["TAICommandService", "register", "COMMANDS", "HAVE_PTB", "_svc"]
