"""
blueteam/posture/commands.py — the ``/posture`` command surface (pure service).

Plain-text renders. Reads (status/score/explain/whatif/trend/portfolio) require
ADMIN; report/export/brand require OWNER; verify requires ADMIN. Report generation
returns a summary + the artifact via the bot's file sender (wiring), not inline.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..platform.tenancy import Role
from .service import PostureService


def _can(role: Role, required: Role) -> bool:
    order = {Role.VIEWER: 0, Role.ADMIN: 1, Role.OWNER: 2}
    return order.get(role, 0) >= order.get(required, 0)


class PostureCommandService:
    def __init__(self, service: PostureService):
        self.svc = service

    def handle(self, chat_id: int, args: List[str], *, actor: Optional[int] = None,
               role: Role = Role.VIEWER, portfolio_chats: Optional[List[int]] = None) -> str:
        sub = (args[0].lower() if args else "status")
        rest = args[1:]
        if not _can(role, Role.ADMIN):
            return "⛔ ต้องเป็น ADMIN ขึ้นไปจึงจะดูสถานะความปลอดภัยได้"
        if sub in ("status", "score", ""):
            return self._status(chat_id)
        if sub == "explain":
            return self._explain(chat_id)
        if sub == "whatif":
            return self._whatif(chat_id, rest)
        if sub == "trend":
            return self._trend(chat_id)
        if sub == "portfolio":
            return self._portfolio(portfolio_chats or [chat_id])
        if sub == "verify":
            return "ใช้งาน: /posture verify <report_id> (แนบไฟล์เพื่อเทียบ SHA-256)"
        # ---- OWNER ----
        if sub in ("report", "export", "brand", "schedule"):
            if not _can(role, Role.OWNER):
                return "⛔ ต้องเป็น OWNER จึงจะสร้างรายงาน/ตั้งค่าแบรนด์ได้"
            if sub in ("report", "export"):
                return self._report(chat_id, rest)
            if sub == "brand":
                return self._brand(chat_id, rest)
            if sub == "schedule":
                return ("ตั้งเวลาออกรายงานอัตโนมัติผ่านตัวจัดงานของบอท "
                        "(รายวัน/รายสัปดาห์) — ดูคู่มือผู้ดูแล")
        return ("ใช้งาน: /posture status|explain|whatif <ctrl>=<status>|trend|report [fmt] "
                "[client|internal]|export <fmt>|brand name|color|footer <v>|portfolio|verify")

    def _status(self, chat_id: int) -> str:
        r = self.svc.score(chat_id)
        gate = f"\n⚠️ เกรดถูกจำกัดโดย: {', '.join(r.gates)}" if r.gates else ""
        return (f"🛡️ สถานะความปลอดภัย\nเกรด {r.grade.value} | คะแนน {r.score:.1f}/100\n"
                f"ครอบคลุม {r.coverage*100:.0f}% ({r.covered}/{r.applicable} การควบคุม){gate}")

    def _explain(self, chat_id: int) -> str:
        e = self.svc.explain(chat_id, top=6)
        out = [f"🔎 คะแนน {e['current']['score']} เกรด {e['current']['grade']} — สิ่งที่ควรแก้ก่อน:"]
        for a in e["top_actions"]:
            out.append(f"• {a['name']} (+{a['potential_gain']}) — {a['reason']}")
        return "\n".join(out) if e["top_actions"] else out[0] + "\n(ทุกการควบคุมผ่านแล้ว)"

    def _whatif(self, chat_id: int, rest: List[str]) -> str:
        changes: Dict[str, str] = {}
        for tok in rest:
            if "=" in tok:
                k, v = tok.split("=", 1)
                changes[k.strip()] = v.strip().lower()
        if not changes:
            return "ใช้งาน: /posture whatif <control_id>=<pass|partial|fail|...>"
        w = self.svc.whatif(chat_id, changes)
        return (f"🔮 what-if {changes}\nก่อน: {w['before']['score']} ({w['before']['grade']})\n"
                f"หลัง: {w['after']['score']} ({w['after']['grade']})\nเปลี่ยน: {w['delta']:+.1f} "
                f"({w['grade_change']})")

    def _trend(self, chat_id: int) -> str:
        t = self.svc.trend(chat_id)
        if len(t) < 2:
            return "ยังมีข้อมูลไม่พอสำหรับแนวโน้ม (ต้องมีสแนปช็อตหลายช่วงเวลา)"
        arrow = "↑" if t[-1] > t[0] else ("↓" if t[-1] < t[0] else "→")
        return f"📈 แนวโน้มคะแนน: {t[0]:.0f} → {t[-1]:.0f} {arrow} (จุดข้อมูล {len(t)})"

    def _portfolio(self, chats: List[int]) -> str:
        p = self.svc.portfolio(chats)
        out = [f"🗂️ พอร์ตโฟลิโอ {p['count']} กลุ่ม | เฉลี่ย {p['avg_score']}"]
        for g in p["groups"][:15]:
            out.append(f"• กลุ่ม {g['chat_id']}: {g['score']} ({g['grade']})")
        if p["weakest"]:
            out.append(f"อ่อนสุด: {p['weakest']['chat_id']} ({p['weakest']['score']})")
        return "\n".join(out)

    def _report(self, chat_id: int, rest: List[str]) -> str:
        fmt, profile = "html", "internal"
        for tok in rest:
            low = tok.lower()
            if low in ("html", "md", "json", "csv", "pdf"):
                fmt = low
            elif low in ("client", "internal"):
                profile = low
        res = self.svc.generate_report(chat_id, fmt=("html" if fmt == "pdf" else fmt),
                                       profile=profile)
        pdf = " (มี PDF)" if (fmt == "pdf" and res["pdf_available"]) else \
              (" (ไม่มีไลบรารี PDF จึงส่ง HTML แทน)" if fmt == "pdf" else "")
        return (f"📄 สร้างรายงานแล้ว: {res['fmt']} · profile {profile}\n"
                f"report_id: {res['report_id']}\nSHA-256: {res['sha256']}\n"
                f"ผนึกลงบัญชีตรวจสอบเรียบร้อย ใช้ /posture verify ตรวจความถูกต้อง{pdf}")

    def _brand(self, chat_id: int, rest: List[str]) -> str:
        if len(rest) < 2:
            return "ใช้งาน: /posture brand name|color|footer <ค่า>"
        key = {"name": "brand_name", "color": "brand_color", "footer": "brand_footer"}.get(rest[0].lower())
        if not key:
            return "ฟิลด์ที่รองรับ: name, color, footer"
        self.svc.set_branding(chat_id, **{key: " ".join(rest[1:])})
        return f"✅ ตั้งค่าแบรนด์ {rest[0]} แล้ว"


__all__ = ["PostureCommandService"]
