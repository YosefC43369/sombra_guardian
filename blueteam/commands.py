"""
blueteam/commands.py — the admin/member command surfaces as pure services.

Each method takes primitives (chat_id, args, actor) and returns rendered *text*
(plain, URLs defanged), so the whole command surface is testable without a running
bot. The Telegram plugin adapters (``plugins/builtin/blueteam_*``) are thin wrappers
that gate on ``is_admin`` and forward here.

Commands (spec §A9, §B8, §C7, dashboard):
  /linkguard  status|on|off|mode|allow|deny|history|stats|feed
  /linkcheck  <url>                       (members, rate-limited, private reply)
  /scamguard  status|on|off|mode|sensitivity|rules|test|vip|review|stats
  /joinguard  status|on|off|mode|verify|timeout|threshold|lockdown|unlock|list|undo|stats
  /blueteam   [24h|7d] | setup [preset]
"""

from __future__ import annotations

import time
from collections import OrderedDict
from typing import List, Optional

from .dashboard import PRESETS
from .messages_th import msg
from .models import PolicyAction, Verdict
from .rules import reload_registry
from .urlkit import defang, extract_urls, etld1


def _onoff(enabled: bool) -> str:
    return "🟢 เปิด" if enabled else "⚪ ปิด"


class CommandService:
    def __init__(self, runtime):
        self.rt = runtime
        self.store = runtime.store
        self._linkcheck_seen: "OrderedDict[int, float]" = OrderedDict()

    # ---- /linkguard ------------------------------------------------------
    def linkguard(self, chat_id: int, args: List[str], actor: Optional[int]) -> str:
        sub = (args[0].lower() if args else "status")
        pol = self.rt.policy(chat_id, "linkguard")
        if sub in ("status", ""):
            return (f"🔗 Link Guard: {_onoff(pol['enabled'])} | โหมด {pol['mode'].name} "
                    f"| เกณฑ์ {pol['threshold']}")
        if sub == "on":
            self.store.set_policy(chat_id, "linkguard", enabled=True, actor=actor)
            return "🔗 เปิด Link Guard แล้ว (โหมดปัจจุบัน: " + pol["mode"].name + ")"
        if sub == "off":
            self.store.set_policy(chat_id, "linkguard", enabled=False, mode="OFF", actor=actor)
            return "🔗 ปิด Link Guard แล้ว"
        if sub == "mode" and len(args) >= 2:
            mode = PolicyAction.parse(args[1])
            self.store.set_policy(chat_id, "linkguard", mode=mode.name, actor=actor)
            return f"🔗 ตั้งโหมดเป็น {mode.name}"
        if sub == "threshold" and len(args) >= 2 and args[1].isdigit():
            self.store.set_policy(chat_id, "linkguard", threshold=int(args[1]), actor=actor)
            return f"🔗 ตั้งเกณฑ์เป็น {int(args[1])}"
        if sub in ("allow", "deny") and len(args) >= 2:
            value = etld1(args[1].lower().strip())
            self.store.add_list_entry(chat_id, sub, "domain", value, actor=actor)
            return f"🔗 เพิ่ม {value} ลงรายการ {sub} แล้ว"
        if sub == "unallow" and len(args) >= 2:
            ok = self.store.remove_list_entry(chat_id, "allow", "domain", etld1(args[1].lower()))
            return "ลบออกแล้ว" if ok else "ไม่พบในรายการ"
        if sub == "list":
            allow = [e["value"] for e in self.store.list_entries(chat_id, "allow")]
            deny = [e["value"] for e in self.store.list_entries(chat_id, "deny")]
            return f"อนุญาต: {', '.join(allow) or '—'}\nปฏิเสธ: {', '.join(deny) or '—'}"
        if sub == "history":
            rows = self.store.recent_events(chat_id, "linkguard", limit=10)
            if not rows:
                return "ยังไม่มีประวัติ"
            return "🔗 ประวัติล่าสุด:\n" + "\n".join(
                f"• {r['verdict']} ({r['score']}) → {r['action']}" for r in rows)
        if sub == "stats":
            return self.rt.dashboard.render(chat_id, "24h")
        if sub == "feed":
            return f"ฟีด blocklist: {self.store.feed_count()} รายการ"
        return ("ใช้งาน: /linkguard status|on|off|mode <M>|threshold <n>|"
                "allow <domain>|deny <domain>|list|history|stats|feed")

    # ---- /linkcheck (members, rate-limited) ------------------------------
    async def linkcheck(self, chat_id: int, user_id: int, url: str,
                        is_admin: bool = False) -> str:
        if not url:
            return "ใช้งาน: /linkcheck <url>"
        # rate limit per user (skip for admins)
        if not is_admin:
            now = time.time()
            last = self._linkcheck_seen.get(user_id, 0)
            cooldown = self.rt.config.linkcheck_cooldown_s
            if now - last < cooldown:
                return f"⏳ โปรดรอ {int(cooldown - (now - last))} วินาที ก่อนตรวจอีกครั้ง"
            self._linkcheck_seen[user_id] = now
            while len(self._linkcheck_seen) > 4096:
                self._linkcheck_seen.popitem(last=False)
        urls = extract_urls(url)
        if not urls:
            return "ไม่พบ URL ที่ตรวจสอบได้"
        eu = urls[0]
        a = self.rt.linkguard.analyze(chat_id, eu)
        reasons = "\n".join(f"• {s.fact}" for s in a.top_reasons(3)) or "• ไม่พบสัญญาณเด่น"
        return msg("lg_result", emoji=a.verdict.emoji, verdict=a.verdict.label_th,
                   score=a.score, url=defang(eu.url), reasons=reasons,
                   limitation=msg("limitation"))

    # ---- /scamguard ------------------------------------------------------
    def scamguard(self, chat_id: int, args: List[str], actor: Optional[int]) -> str:
        sub = (args[0].lower() if args else "status")
        pol = self.rt.policy(chat_id, "scamguard")
        if sub in ("status", ""):
            return (f"🛡️ Scam Guard: {_onoff(pol['enabled'])} | โหมด {pol['mode'].name} "
                    f"| ความไว {pol['sensitivity']}")
        if sub == "on":
            self.store.set_policy(chat_id, "scamguard", enabled=True, actor=actor)
            return "🛡️ เปิด Scam Guard แล้ว"
        if sub == "off":
            self.store.set_policy(chat_id, "scamguard", enabled=False, mode="OFF", actor=actor)
            return "🛡️ ปิด Scam Guard แล้ว"
        if sub == "mode" and len(args) >= 2:
            m = PolicyAction.parse(args[1])
            self.store.set_policy(chat_id, "scamguard", mode=m.name, actor=actor)
            return f"🛡️ ตั้งโหมดเป็น {m.name}"
        if sub in ("sensitivity", "sens") and len(args) >= 2:
            self.store.set_policy(chat_id, "scamguard", sensitivity=args[1].lower(), actor=actor)
            return f"🛡️ ตั้งความไวเป็น {args[1].lower()}"
        if sub == "rules":
            if len(args) >= 2 and args[1] == "reload":
                st = reload_registry()
                return f"♻️ โหลดกฎใหม่แล้ว: {st}"
            st = self.rt.registry.status()
            return (f"กฎสแกม TH:{st['scam_th']} EN:{st['scam_en']} | "
                    f"checksum {'ok' if st['checksums_ok'] else 'MISMATCH'}")
        if sub == "test" and len(args) >= 2:
            a = self.rt.scamguard.analyze(chat_id, " ".join(args[1:]), user_id=actor,
                                          sensitivity=pol["sensitivity"])
            reasons = "\n".join(f"• {s.fact}" for s in a.top_reasons(3)) or "• ไม่พบสัญญาณ"
            return msg("sg_result", emoji=a.verdict.emoji, verdict=a.verdict.label_th,
                       score=a.score, categories=", ".join(a.meta.get("categories", [])),
                       reasons=reasons, limitation=msg("limitation"))
        if sub == "vip":
            return self._vip(chat_id, args[1:], actor)
        if sub == "review":
            rows = self.store.list_reviews(chat_id, "OPEN", limit=10)
            if not rows:
                return "ไม่มีรายการรอตรวจสอบ"
            return "🔎 คิวตรวจสอบ:\n" + "\n".join(
                f"• #{r['id']} {r['module']} user={r['user_id']} "
                f"{r['verdict']}({r['score']})" for r in rows)
        if sub == "stats":
            return self.rt.dashboard.render(chat_id, "24h")
        return ("ใช้งาน: /scamguard status|on|off|mode <M>|sensitivity <lvl>|"
                "rules [reload]|test <ข้อความ>|vip add|list|del|review|stats")

    def _vip(self, chat_id: int, args: List[str], actor: Optional[int]) -> str:
        if not args:
            vips = self.store.list_vips(chat_id)
            if not vips:
                return "ยังไม่มี VIP"
            return "⭐ VIP:\n" + "\n".join(
                f"• {v['display_name'] or v['username'] or v['user_id']} ({v['role']})"
                for v in vips)
        op = args[0].lower()
        if op == "list":
            return self._vip(chat_id, [], actor)
        if op == "add" and len(args) >= 2:
            handle = args[1]
            self.store.add_vip(chat_id, username=handle.lstrip("@"),
                               display_name=" ".join(args[2:]), role="vip", actor=actor)
            return f"⭐ เพิ่ม VIP {handle} แล้ว"
        if op == "del" and len(args) >= 2:
            ok = self.store.remove_vip(chat_id, username=args[1].lstrip("@"))
            return "ลบ VIP แล้ว" if ok else "ไม่พบ VIP"
        return "ใช้งาน: /scamguard vip add <@user> [ชื่อ] | list | del <@user>"

    def review_decide(self, chat_id: int, review_id: int, decision: str,
                      actor: Optional[int]) -> bool:
        status = {"not_spam": "NOT_SPAM", "delete": "DELETED", "mute": "MUTED",
                  "ban": "BANNED"}.get(decision, "NOT_SPAM")
        return self.store.decide_review(review_id, chat_id, status, actor)

    # ---- /joinguard ------------------------------------------------------
    def joinguard(self, chat_id: int, args: List[str], actor: Optional[int]) -> str:
        sub = (args[0].lower() if args else "status")
        pol = self.rt.policy(chat_id, "joinguard")
        state = self.store.get_raid_state(chat_id)["state"]
        if sub in ("status", ""):
            return (f"👮 Join Guard: {_onoff(pol['enabled'])} | โหมด {pol['mode'].name} "
                    f"| สถานะ: {state}")
        if sub == "on":
            self.store.set_policy(chat_id, "joinguard", enabled=True, actor=actor)
            return "👮 เปิด Join Guard แล้ว"
        if sub == "off":
            self.store.set_policy(chat_id, "joinguard", enabled=False, mode="OFF", actor=actor)
            return "👮 ปิด Join Guard แล้ว"
        if sub == "mode" and len(args) >= 2:
            m = PolicyAction.parse(args[1])
            self.store.set_policy(chat_id, "joinguard", mode=m.name, actor=actor)
            return f"👮 ตั้งโหมดเป็น {m.name}"
        if sub in ("verify", "timeout", "threshold") and len(args) >= 2:
            self.store.set_policy(chat_id, "joinguard",
                                  settings={sub: args[1]}, actor=actor)
            return f"👮 ตั้งค่า {sub} = {args[1]}"
        if sub == "lockdown":
            self.store.set_raid_state(chat_id, "RAID", meta={"manual": True})
            return "🔒 เปิดโหมดล็อกกลุ่มด้วยตนเองแล้ว (ใช้ /joinguard unlock เพื่อปลด)"
        if sub == "unlock":
            self.store.set_raid_state(chat_id, "NORMAL")
            return msg("jg_lockdown_off")
        if sub == "stats":
            return self.rt.dashboard.render(chat_id, "24h")
        if sub == "list":
            return f"สถานะปัจจุบัน: {state}"
        return ("ใช้งาน: /joinguard status|on|off|mode <M>|verify <type>|"
                "timeout <sec>|threshold <n>|lockdown|unlock|list|undo|stats")

    # ---- /blueteam dashboard + setup wizard ------------------------------
    def blueteam(self, chat_id: int, args: List[str], actor: Optional[int]) -> str:
        if args and args[0].lower() == "setup":
            if len(args) >= 2 and args[1].lower() in PRESETS:
                self.rt.dashboard.apply_preset(chat_id, args[1].lower(), actor or 0)
                return f"✅ ใช้ชุดค่า '{args[1].lower()}' กับกลุ่มนี้แล้ว"
            return self.rt.dashboard.wizard_intro()
        window = args[0] if args and args[0] in ("24h", "7d") else "24h"
        return self.rt.dashboard.render(chat_id, window)
