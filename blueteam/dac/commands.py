"""
blueteam/dac/commands.py — the ``/rule`` command surface as a pure service.

Plain-text renders; writes (import/new/enable/disable/shadow/canary/rollback/pack/
delete) require ``OWNER``; reads require ``ADMIN``. Rule bodies arrive as a JSON
string argument — parsed as **data**, compiled by the no-eval compiler, never
executed.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ..platform.tenancy import Role
from .service import DacService

_USAGE = ("ใช้งาน: /rule list|show <id>|import <json>|enable <id>|disable <id>|"
          "shadow <id>|canary <id> <chat...>|rollback <id> <ver>|test <id> <json>|"
          "lint <json>|backtest <id>|history <id>|stats|pack")


def _can(role: Role, required: Role) -> bool:
    order = {Role.VIEWER: 0, Role.ADMIN: 1, Role.OWNER: 2}
    return order.get(role, 0) >= order.get(required, 0)


class RuleCommandService:
    def __init__(self, service: DacService, *, pack: Optional[List[dict]] = None):
        self.svc = service
        self._pack = pack or []

    def handle(self, args: List[str], *, raw: str = "", actor: Optional[int] = None,
               role: Role = Role.VIEWER) -> str:
        sub = (args[0].lower() if args else "list")
        rest = args[1:]
        # ---- reads (ADMIN) ----
        if sub in ("list", ""):
            return self._list()
        if sub == "stats":
            return self._stats()
        if sub == "show":
            return self._show(rest)
        if sub == "history":
            return self._history(rest)
        if sub == "backtest":
            return self._backtest(rest)
        if sub in ("lint", "test"):
            if not _can(role, Role.ADMIN):
                return "⛔ ต้องเป็น ADMIN ขึ้นไป"
            return self._lint_or_test(sub, raw)
        # ---- writes (OWNER) ----
        if sub in ("import", "new", "enable", "disable", "shadow", "canary",
                   "rollback", "pack", "delete"):
            if not _can(role, Role.OWNER):
                return "⛔ ต้องเป็น OWNER จึงจะแก้ไขกฎได้"
            if sub in ("import", "new"):
                return self._import(raw, actor)
            if sub == "enable":
                return self._transition("enable", rest, actor)
            if sub == "disable":
                return self._transition("disable", rest, actor)
            if sub == "shadow":
                return self._transition("shadow", rest, actor)
            if sub == "canary":
                return self._canary(rest, actor)
            if sub == "rollback":
                return self._rollback(rest, actor)
            if sub == "pack":
                return self._pack_cmd(actor)
            if sub == "delete":
                return self._delete(rest)
        return _USAGE

    # ---------------- reads ----------------
    def _list(self) -> str:
        rules = self.svc.list_rules()
        if not rules:
            return "ยังไม่มีกฎ ใช้ /rule pack เพื่อโหลดชุดเริ่มต้น"
        icon = {"enabled": "🟢", "canary": "🟡", "shadow": "🌓", "disabled": "⚪"}
        out = [f"📏 กฎทั้งหมด: {len(rules)}"]
        for r in rules[:60]:
            out.append(f"{icon.get(r['state'], '⚪')} {r['rule_id']} v{r['version']} "
                       f"[{r['level']}] — {r['title']}")
        return "\n".join(out)

    def _show(self, rest: List[str]) -> str:
        if not rest:
            return "ใช้งาน: /rule show <id>"
        r = self.svc.show_rule(rest[0])
        if not r:
            return "ไม่พบกฎนี้"
        body = json.dumps(r.get("body", {}), ensure_ascii=False, indent=2)
        if len(body) > 1500:
            body = body[:1500] + "…"
        return (f"📏 {r['rule_id']} v{r['version']} [{r['level']}] state={r['state']}\n"
                f"{r['title']}\ncanary_chats={r.get('canary_chats')}\n---\n{body}")

    def _history(self, rest: List[str]) -> str:
        if not rest:
            return "ใช้งาน: /rule history <id>"
        h = self.svc.history(rest[0])
        if not h["versions"]:
            return "ไม่มีประวัติเวอร์ชัน"
        chain = "✅ ห่วงโซ่แฮชสมบูรณ์" if h["chain_ok"] else f"⚠️ ห่วงโซ่เสียที่ {h['first_bad']}"
        out = [f"🕘 ประวัติ {rest[0]} ({chain}):"]
        for v in h["versions"]:
            out.append(f"• v{v['version']} — {v.get('notes', '')} ({v['sha256'][:12]}…)")
        return "\n".join(out)

    def _backtest(self, rest: List[str]) -> str:
        if not rest:
            return "ใช้งาน: /rule backtest <id> (ทดสอบกับตัวอย่างในระบบ)"
        recent = self.svc._repo.recent_hits(rest[0], 200)  # noqa: SLF001 - service helper
        res = self.svc.backtest(rest[0], recent)
        return (f"🧪 backtest {rest[0]}: {res.get('matches', 0)}/{res.get('total', 0)} "
                f"(rate {res.get('rate', 0)})") if res.get("ok") else "ไม่พบกฎนี้"

    def _lint_or_test(self, sub: str, raw: str) -> str:
        body = _extract_json(raw)
        if body is None:
            return f"ใช้งาน: /rule {sub} <json rule>"
        if sub == "lint":
            res = self.svc.lint(body)
            return "✅ ผ่าน lint" if res["ok"] else "❌ ปัญหา:\n" + "\n".join(res["problems"])
        return "ใช้งาน: /rule test <id|json> — ระบุ record ตัวอย่างผ่าน API"

    def _stats(self) -> str:
        s = self.svc.stats()
        return (f"📊 DaC stats\nกฎทั้งหมด: {s['total']} | active: {s['active']}\n"
                f"ตามสถานะ: {s['by_state']}\nเบรกเกอร์เปิด: {s['breakers_open'] or '—'}\n"
                f"ยิงใน 24 ชม.: {sum(s['hits_24h'].values())}")

    # ---------------- writes ----------------
    def _import(self, raw: str, actor: Optional[int]) -> str:
        body = _extract_json(raw)
        if body is None:
            return "ใช้งาน: /rule import <json rule>"
        res = self.svc.import_rule(body, actor=actor)
        if not res.get("ok"):
            return "❌ นำเข้าไม่สำเร็จ:\n" + "\n".join(res.get("problems", ["unknown"]))
        return f"✅ นำเข้ากฎ {res['rule_id']} v{res['version']} (sha {res['sha256'][:12]}…, สถานะ disabled)"

    def _transition(self, op: str, rest: List[str], actor: Optional[int]) -> str:
        if not rest:
            return f"ใช้งาน: /rule {op} <id>"
        fn = getattr(self.svc, op)
        res = fn(rest[0], actor=actor)
        return (f"✅ {rest[0]} → {res['state']}" if res.get("ok")
                else f"❌ {res.get('error', 'ผิดพลาด')}")

    def _canary(self, rest: List[str], actor: Optional[int]) -> str:
        if len(rest) < 2:
            return "ใช้งาน: /rule canary <id> <chat_id...>"
        chats = [int(c) for c in rest[1:] if c.lstrip("-").isdigit()]
        res = self.svc.canary(rest[0], chats, actor=actor)
        return (f"✅ {rest[0]} → canary ใน {chats}" if res.get("ok")
                else f"❌ {res.get('error', 'ผิดพลาด')}")

    def _rollback(self, rest: List[str], actor: Optional[int]) -> str:
        if len(rest) < 2:
            return "ใช้งาน: /rule rollback <id> <version>"
        res = self.svc.rollback(rest[0], rest[1], actor=actor)
        return (f"✅ rollback {rest[0]} → v{res['version']}" if res.get("ok")
                else f"❌ {res.get('error', 'ผิดพลาด')}")

    def _pack_cmd(self, actor: Optional[int]) -> str:
        if not self._pack:
            return "ไม่พบชุดกฎเริ่มต้น"
        res = self.svc.load_pack(self._pack, actor=actor, activate=True)
        return (f"📦 โหลดชุดเริ่มต้น: สำเร็จ {res['loaded']} กฎ (สถานะ shadow)"
                + (f" | ล้มเหลว {res['failed']}" if res["failed"] else ""))

    def _delete(self, rest: List[str]) -> str:
        if not rest:
            return "ใช้งาน: /rule delete <id>"
        return "🗑️ ลบแล้ว" if self.svc.delete_rule(rest[0]) else "ไม่พบกฎนี้"


def _extract_json(raw: str) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    start = raw.find("{")
    if start < 0:
        return None
    try:
        obj = json.loads(raw[start:])
        return obj if isinstance(obj, dict) else None
    except ValueError:
        return None


__all__ = ["RuleCommandService"]
