"""
news_intelligence.telegram.commands — the /news* command surface.

Commands (spec TELEGRAM COMMANDS):
  /news /news_today /news_week /news_search /news_actor /news_campaign /news_cve
  /news_malware /news_org /news_country /news_graph /news_brief /news_report

Design mirrors ``threat_actor_intelligence.telegram``: the analytical logic lives in
``NewsCommandService`` (pure, returns rendered strings — fully testable without a
running bot); the ``async def cmd_*`` handlers are thin adapters. ``python-telegram-bot``
is imported defensively so this module imports in the pure test environment. All
commands are read-only public-news queries; they carry no destructive action and expose
no secrets.
"""

from __future__ import annotations

import logging
import time
from typing import List, Optional

from ..configuration import NewsIntelConfig, get_config
from ..engine import NewsIntelligenceEngine

logger = logging.getLogger("modbot.news.telegram")

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

COMMANDS = ["news", "news_today", "news_week", "news_search", "news_actor",
            "news_campaign", "news_cve", "news_malware", "news_org",
            "news_country", "news_graph", "news_brief", "news_report"]


def _truncate(text: str, limit: int = _TELEGRAM_LIMIT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit - 48].rstrip() + "\n… (truncated; use /news_report for full)"


def _fmt_date(ts: float) -> str:
    if not ts:
        return "—"
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(ts))
    except Exception:
        return "—"


class NewsCommandService:
    """Pure command implementations returning rendered Markdown text."""

    def __init__(self, *, config: Optional[NewsIntelConfig] = None,
                 engine: Optional[NewsIntelligenceEngine] = None):
        self.config = config or get_config()
        self.engine = engine or NewsIntelligenceEngine(config=self.config)

    # -- helpers ---------------------------------------------------------- #
    @staticmethod
    def _arg(args, default: str = "") -> str:
        return " ".join(a for a in (args or []) if "=" not in a).strip() or default

    @staticmethod
    def _opt(args, key: str, default: str = "") -> str:
        for a in (args or []):
            if a.startswith(key + "="):
                return a.split("=", 1)[1]
        return default

    # -- overview --------------------------------------------------------- #
    def cmd_news(self, args=None) -> str:
        s = self.engine.stats()["store"]
        actors = self.engine.actors_today(limit=5)
        cves = self.engine.top_entities("cve", days=1, limit=5)
        lines = ["📰 *News Intelligence — overview*",
                 f"Corpus: {s['articles']} articles · {s['sources']} sources · "
                 f"{s['iocs']} IOCs · {s['campaigns']} campaigns",
                 ""]
        if actors:
            lines.append("*Top actors (24h):* " +
                         ", ".join(f"{a['value']} ({a['count']})" for a in actors))
        if cves:
            lines.append("*Top CVEs (24h):* " +
                         ", ".join(f"{c['value']} ({c['count']})" for c in cves))
        lines += ["", "Commands: /news_today /news_week /news_search <q> "
                  "/news_actor <name> /news_cve <id> /news_malware <name> "
                  "/news_campaign <name> /news_org <name> /news_country <name> "
                  "/news_brief /news_graph"]
        return _truncate("\n".join(lines))

    def cmd_news_today(self, args=None) -> str:
        nw = self.engine.whats_new(days=1)
        lines = [f"🗞️ *Today* — {nw['new_articles']} new articles"]
        if nw["new_actors"]:
            lines.append("*Actors:* " + ", ".join(
                f"{a['value']} ({a['count']})" for a in nw["new_actors"][:8]))
        if nw["new_cves"]:
            lines.append("*CVEs:* " + ", ".join(
                f"{c['value']} ({c['count']})" for c in nw["new_cves"][:8]))
        if nw["new_malware"]:
            lines.append("*Malware:* " + ", ".join(
                f"{m['value']} ({m['count']})" for m in nw["new_malware"][:8]))
        if nw["emerging_trends"]:
            lines.append("*Emerging CVE trends:* " + ", ".join(
                f"{t['subject']}({t['direction']})" for t in nw["emerging_trends"][:6]))
        if len(lines) == 1:
            lines.append("_No new articles in the last 24h._")
        return _truncate("\n".join(lines))

    def cmd_news_week(self, args=None) -> str:
        actors = self.engine.top_entities("threat_actor", days=7, limit=8)
        malware = self.engine.malware_this_week(limit=8)
        cves = self.engine.top_entities("cve", days=7, limit=8)
        lines = ["📅 *This week*"]
        lines.append("*Actors:* " + (", ".join(
            f"{a['value']} ({a['count']})" for a in actors) or "—"))
        lines.append("*Malware:* " + (", ".join(
            f"{m['value']} ({m['count']})" for m in malware) or "—"))
        lines.append("*CVEs:* " + (", ".join(
            f"{c['value']} ({c['count']})" for c in cves) or "—"))
        return _truncate("\n".join(lines))

    def cmd_news_search(self, args) -> str:
        q = self._arg(args)
        if not q:
            return "Usage: /news_search <text> — e.g. /news_search ransomware healthcare"
        hits = self.engine.search(q, limit=10)
        if not hits:
            return f"No articles match '{q}'."
        lines = [f"🔎 *Search:* {q}"]
        for h in hits:
            lines.append(f"• [{_fmt_date(h['published'])}] {h['title'][:80]} "
                         f"— _{h['source']}_")
        return _truncate("\n".join(lines))

    def cmd_news_actor(self, args) -> str:
        name = self._arg(args)
        if not name:
            return "Usage: /news_actor <name|alias> — e.g. /news_actor APT29"
        d = self.engine.actor_report(name, fmt="dict")
        return _truncate(self._render_profile(d, "🎯"))

    def cmd_news_malware(self, args) -> str:
        name = self._arg(args)
        if not name:
            return "Usage: /news_malware <family> — e.g. /news_malware LockBit"
        d = self.engine.malware_report(name, fmt="dict")
        return _truncate(self._render_profile(d, "🦠"))

    def cmd_news_cve(self, args) -> str:
        cve = self._arg(args)
        if not cve:
            return "Usage: /news_cve <CVE-YYYY-NNNN>"
        d = self.engine.cve_report(cve, fmt="dict")
        return _truncate(self._render_profile(d, "🐞"))

    def cmd_news_campaign(self, args) -> str:
        name = self._arg(args)
        if not name:
            return "Usage: /news_campaign <name>"
        d = self.engine.campaign_report(name, fmt="dict")
        return _truncate(self._render_profile(d, "🏴"))

    def cmd_news_org(self, args) -> str:
        name = self._arg(args)
        if not name:
            return "Usage: /news_org <organization>"
        hits = self.engine.search("", organization=name, limit=10)
        if not hits:
            return f"No articles mention '{name}'."
        lines = [f"🏢 *{name}* — {len(hits)} recent articles"]
        for h in hits:
            lines.append(f"• [{_fmt_date(h['published'])}] {h['title'][:80]} "
                         f"— _{h['source']}_")
        return _truncate("\n".join(lines))

    def cmd_news_country(self, args) -> str:
        name = self._arg(args)
        if not name:
            return "Usage: /news_country <country>"
        hits = self.engine.search("", country=name, limit=10)
        if not hits:
            return f"No articles mention '{name}'."
        lines = [f"🌍 *{name}* — {len(hits)} recent articles"]
        for h in hits:
            lines.append(f"• [{_fmt_date(h['published'])}] {h['title'][:80]} "
                         f"— _{h['source']}_")
        return _truncate("\n".join(lines))

    def cmd_news_graph(self, args) -> str:
        kind = self._opt(args, "kind", "news")
        subject = self._arg(args)
        g = self.engine.graph(kind=kind, subject=subject, days=14, fmt="json")
        import json
        data = json.loads(g)
        st = data.get("stats", {})
        return (f"🕸️ *News graph* ({kind}) — {st.get('nodes',0)} nodes, "
                f"{st.get('edges',0)} edges.\nNode types: " +
                ", ".join(f"{k}={v}" for k, v in st.get("node_types", {}).items()))

    def cmd_news_brief(self, args) -> str:
        which = self._arg(args, "daily").lower()
        if which.startswith("week"):
            return _truncate(self.engine.weekly_brief(fmt="markdown"))
        if which.startswith("exec"):
            return _truncate(self.engine.executive_summary(fmt="markdown"))
        return _truncate(self.engine.daily_brief(fmt="markdown"))

    def cmd_news_report(self, args) -> str:
        """Full report for a subject: /news_report actor APT29 | cve CVE-… | etc."""
        kind = (args[0].lower() if args else "daily")
        subject = " ".join(args[1:]) if args and len(args) > 1 else ""
        try:
            if kind == "actor" and subject:
                return _truncate(self.engine.actor_report(subject, fmt="markdown"))
            if kind == "malware" and subject:
                return _truncate(self.engine.malware_report(subject, fmt="markdown"))
            if kind == "cve" and subject:
                return _truncate(self.engine.cve_report(subject, fmt="markdown"))
            if kind == "campaign" and subject:
                return _truncate(self.engine.campaign_report(subject, fmt="markdown"))
            if kind in ("weekly", "week"):
                return _truncate(self.engine.weekly_brief(fmt="markdown"))
            if kind in ("exec", "executive"):
                return _truncate(self.engine.executive_summary(fmt="markdown"))
            return _truncate(self.engine.daily_brief(fmt="markdown"))
        except Exception as exc:  # pragma: no cover
            return f"Report error: {exc}"

    # -- shared profile renderer ----------------------------------------- #
    def _render_profile(self, d, icon: str) -> str:
        if not d or not d.get("sections"):
            return f"{icon} No data for that subject yet."
        lines = [f"{icon} *{d.get('title', 'Profile')}*"]
        if d.get("summary"):
            lines.append(d["summary"])
        for sec in d["sections"][:6]:
            body = sec.get("lines", [])[:6]
            rows = sec.get("rows", [])[:6]
            if body:
                lines.append(f"\n*{sec['title']}:* " + "; ".join(body))
            elif rows:
                cols = sec.get("columns", [])
                lines.append(f"\n*{sec['title']}:*")
                for r in rows:
                    lines.append("  " + " · ".join(str(r.get(c, "")) for c in cols))
        return "\n".join(lines)


# ---------------------------------------------------------------------------- #
# thin async adapters
# ---------------------------------------------------------------------------- #
_svc_singleton: Optional[NewsCommandService] = None


def _svc() -> NewsCommandService:
    global _svc_singleton
    if _svc_singleton is None:
        _svc_singleton = NewsCommandService()
    return _svc_singleton


def _make_handler(method_name: str):
    async def handler(update, context):  # pragma: no cover - needs bot
        args = getattr(context, "args", []) or []
        try:
            text = getattr(_svc(), method_name)(args)
        except Exception as exc:
            text = f"Error: {exc}"
        if update and getattr(update, "message", None):
            await update.message.reply_text(text, parse_mode="Markdown",
                                            disable_web_page_preview=True)
    return handler


def register(application, *, service: Optional[NewsCommandService] = None) -> int:
    """Register the /news* commands, skipping any already registered."""
    if not HAVE_PTB or application is None:  # pragma: no cover
        return 0
    global _svc_singleton
    if service is not None:
        _svc_singleton = service
    method_map = {
        "news": "cmd_news", "news_today": "cmd_news_today",
        "news_week": "cmd_news_week", "news_search": "cmd_news_search",
        "news_actor": "cmd_news_actor", "news_campaign": "cmd_news_campaign",
        "news_cve": "cmd_news_cve", "news_malware": "cmd_news_malware",
        "news_org": "cmd_news_org", "news_country": "cmd_news_country",
        "news_graph": "cmd_news_graph", "news_brief": "cmd_news_brief",
        "news_report": "cmd_news_report",
    }
    existing = set()
    try:  # pragma: no cover
        for group in application.handlers.values():
            for h in group:
                cmds = getattr(h, "commands", None)
                if cmds:
                    existing.update(cmds)
    except Exception:
        pass
    n = 0
    for cmd, method in method_map.items():
        if cmd in existing:
            continue
        application.add_handler(CommandHandler(cmd, _make_handler(method)))
        n += 1
    return n


__all__ = ["NewsCommandService", "COMMANDS", "register", "HAVE_PTB"]
