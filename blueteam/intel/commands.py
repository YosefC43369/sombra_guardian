"""
blueteam/intel/commands.py — the ``/intel`` command surface as a pure service.

Methods take primitives (args, actor, role) and return rendered **plain text**
with every IOC **defanged** (spec gติกา: feed data and user input are data, not
commands). Global/write actions require ``OWNER``; reads require ``ADMIN``. The
Telegram plugin adapter is a thin wrapper that resolves the role via TenantScope
and forwards here, running network-bound ``sync`` in an executor.
"""

from __future__ import annotations

from typing import List, Optional

from ..platform.tenancy import Role
from .domain import IOCType, detect_type
from .service import IntelService

_USAGE = ("ใช้งาน: /intel status|feeds|sync [feed]|lookup <ioc>|add <ioc> [type]|"
          "del <ioc>|whitelist add|del|list <value>|sightings <ioc>|export [type]|stats|health")


def _defang_value(ioc_type: IOCType, value: str) -> str:
    if ioc_type in (IOCType.URL, IOCType.DOMAIN):
        from ..urlkit import defang
        return defang(value)
    if ioc_type in (IOCType.IP, IOCType.CIDR):
        return value.replace(".", "[.]")
    return value


class IntelCommandService:
    def __init__(self, service: IntelService):
        self.svc = service

    def handle(self, args: List[str], *, actor: Optional[int] = None,
               role: Role = Role.VIEWER) -> str:
        sub = (args[0].lower() if args else "status")
        rest = args[1:]
        if sub in ("status", ""):
            return self._status()
        if sub == "feeds":
            return self._feeds()
        if sub == "stats":
            return self._stats()
        if sub == "health":
            h = self.svc.health()
            fail = ("; ฟีดมีปัญหา: " + ", ".join(h["failing_feeds"])) if h["failing_feeds"] else ""
            return f"🩺 Intel: {'ปกติ' if h['ok'] else 'เตือน'} | IOC {h['engine_size']} | ฟีด {h['feeds']}{fail}"
        if sub == "lookup":
            return self._lookup(rest)
        if sub == "sightings":
            return self._sightings(rest)
        if sub == "export":
            return self._export(rest, role)
        # ---- write / global actions require OWNER ----
        if sub in ("sync", "add", "del", "whitelist"):
            if not _can(role, Role.OWNER):
                return "⛔ ต้องเป็น OWNER จึงจะแก้ไขข้อมูล Threat Intel ได้"
            if sub == "sync":
                return self._sync(rest)
            if sub == "add":
                return self._add(rest, actor)
            if sub == "del":
                return self._del(rest)
            if sub == "whitelist":
                return self._whitelist(rest, actor)
        return _USAGE

    # ---------------- read ----------------
    def _status(self) -> str:
        s = self.svc.stats()
        by = s.get("by_type", {})
        top = ", ".join(f"{k}:{v}" for k, v in sorted(by.items(), key=lambda x: -x[1])[:5])
        return (f"🛡️ Threat Intel\nIOC ทั้งหมด: {s.get('total', 0)} (local {s.get('local', 0)})\n"
                f"ในหน่วยความจำ: {s.get('engine_size', 0)}\nชนิด: {top or '—'}\n"
                f"การพบเห็น: {s.get('sightings', 0)}")

    def _feeds(self) -> str:
        rows = self.svc.feed_status()
        if not rows:
            return "ยังไม่มีฟีดที่ตั้งค่าไว้"
        out = ["📡 ฟีด Threat Intel:"]
        for r in rows:
            lic = "✓" if r["license_ok"] else "✗license"
            en = "🟢" if r["enabled"] else "⚪"
            out.append(f"{en} {r['feed']} [{lic}] — {r['last_status']} "
                       f"({r['item_count']} รายการ, fail {r['failures']})")
        return "\n".join(out)

    def _stats(self) -> str:
        s = self.svc.stats()
        return (f"📊 Intel stats\nรวม: {s.get('total', 0)}\nlocal: {s.get('local', 0)}\n"
                f"engine: {s.get('engine_size', 0)}\nsightings: {s.get('sightings', 0)}\n"
                f"by_type: {s.get('by_type', {})}")

    def _lookup(self, rest: List[str]) -> str:
        if not rest:
            return "ใช้งาน: /intel lookup <ioc>"
        raw = rest[0]
        mr = self.svc.lookup(raw)
        if mr is None:
            return f"✅ ไม่พบใน Threat Intel: {_defang_raw(raw)}"
        return (f"⚠️ พบใน Threat Intel\nชนิด: {mr.ioc_type.value}\n"
                f"ค่า: {_defang_value(mr.ioc_type, mr.matched_value)}\n"
                f"เหตุผล: {mr.reason}\nความมั่นใจ: {mr.confidence}/100 | ระดับ: {mr.severity}\n"
                f"แหล่ง: {', '.join(mr.sources) or '—'}")

    def _sightings(self, rest: List[str]) -> str:
        if not rest:
            return "ใช้งาน: /intel sightings <ioc>"
        rows = self.svc.sightings(rest[0], limit=15)
        if not rows:
            return "ยังไม่มีบันทึกการพบเห็น"
        out = ["👁️ การพบเห็นล่าสุด:"]
        for r in rows:
            out.append(f"• chat {r.get('chat_id')} — {r.get('context', '')[:40]}")
        return "\n".join(out)

    def _export(self, rest: List[str], role: Role) -> str:
        if not _can(role, Role.ADMIN):
            return "⛔ ต้องเป็น ADMIN ขึ้นไปจึงจะส่งออกได้"
        t = None
        if rest:
            try:
                t = IOCType(rest[0].lower())
            except ValueError:
                t = None
        bundle = self.svc.export_stix(ioc_type=t, min_confidence=50)
        n = len(bundle.get("objects", []))
        return (f"📦 STIX 2.1-lite bundle พร้อมส่งออก: {n} objects "
                f"(id {bundle.get('id', '')[:20]}…)\n"
                f"ใช้ปุ่มดาวน์โหลดของบอท หรือ /intel export json เพื่อรับไฟล์เต็ม")

    # ---------------- write (OWNER) ----------------
    def _sync(self, rest: List[str]) -> str:
        if rest:
            res = self.svc.sync_feed(rest[0])
            return f"🔄 ซิงก์ {res['feed']}: {res['status']} (+{res.get('ingested', 0)})"
        results = self.svc.sync_all(only_enabled=True)
        ok = sum(1 for r in results if r["status"] == "ok")
        ing = sum(r.get("ingested", 0) for r in results)
        return f"🔄 ซิงก์ฟีดทั้งหมด: สำเร็จ {ok}/{len(results)} | เพิ่ม/อัปเดต {ing} IOC"

    def _add(self, rest: List[str], actor: Optional[int]) -> str:
        if not rest:
            return "ใช้งาน: /intel add <ioc> [type]"
        t = None
        if len(rest) >= 2:
            try:
                t = IOCType(rest[1].lower())
            except ValueError:
                t = None
        ioc = self.svc.add_local(rest[0], ioc_type=t, added_by=actor)
        if ioc is None:
            return "❌ ไม่รู้จักชนิด IOC นี้ ระบุชนิดต่อท้าย เช่น /intel add value domain"
        return f"✅ เพิ่ม IOC local: {ioc.defanged()} ({ioc.ioc_type.value}, conf {ioc.confidence})"

    def _del(self, rest: List[str]) -> str:
        if not rest:
            return "ใช้งาน: /intel del <ioc>"
        ok = self.svc.delete_local(rest[0])
        return "🗑️ ลบแล้ว" if ok else "ไม่พบ IOC นี้"

    def _whitelist(self, rest: List[str], actor: Optional[int]) -> str:
        if not rest:
            return "ใช้งาน: /intel whitelist add|del|list <value>"
        op = rest[0].lower()
        if op == "list":
            wl = self.svc.list_whitelist()
            return "รายการ whitelist:\n" + ("\n".join(f"• {w}" for w in wl) if wl else "—")
        if op in ("add", "del") and len(rest) >= 2:
            value = rest[1]
            if op == "add":
                self.svc.add_whitelist(value, added_by=actor)
                return f"✅ เพิ่ม {value} เข้า whitelist (จะไม่ถูกบล็อก)"
            return "🗑️ ลบออกจาก whitelist แล้ว" if self.svc.remove_whitelist(value) else "ไม่พบ"
        return "ใช้งาน: /intel whitelist add|del|list <value>"


def _can(role: Role, required: Role) -> bool:
    order = {Role.VIEWER: 0, Role.ADMIN: 1, Role.OWNER: 2}
    return order.get(role, 0) >= order.get(required, 0)


def _defang_raw(raw: str) -> str:
    t = detect_type(raw)
    return _defang_value(t, raw) if t else raw


__all__ = ["IntelCommandService"]
