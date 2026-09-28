"""
blueteam/dashboard.py — /blueteam summary + first-run setup wizard (pure builders).

Produces the *text* for the Blue Team dashboard (24h / 7d counts of links scanned/
blocked, scams found, raids, top signals) and the setup-wizard presets. Rendering is
pure (reads the store, returns strings/dicts) so it is testable without a bot; the
plugin attaches inline-keyboard pagination.
"""

from __future__ import annotations

from typing import Any, Dict, List

_WINDOWS = {"24h": 86400, "7d": 604800}

# One-tap presets the setup wizard offers per group.
PRESETS: Dict[str, Dict[str, Any]] = {
    "starter": {
        "label": "เริ่มต้น (เฝ้าระวัง)",
        "linkguard": {"enabled": True, "mode": "MONITOR", "threshold": 60},
        "scamguard": {"enabled": True, "mode": "MONITOR", "sensitivity": "relaxed"},
        "joinguard": {"enabled": True, "mode": "MONITOR"},
    },
    "balanced": {
        "label": "สมดุล (เตือน+ลบเสี่ยงสูง)",
        "linkguard": {"enabled": True, "mode": "DELETE", "threshold": 70},
        "scamguard": {"enabled": True, "mode": "WARN", "sensitivity": "balanced"},
        "joinguard": {"enabled": True, "mode": "WARN"},
    },
    "strict": {
        "label": "เข้มงวด (ลบ+จำกัดสิทธิ์)",
        "linkguard": {"enabled": True, "mode": "DELETE_RESTRICT", "threshold": 55},
        "scamguard": {"enabled": True, "mode": "DELETE", "sensitivity": "strict"},
        "joinguard": {"enabled": True, "mode": "DELETE_RESTRICT"},
    },
}


class Dashboard:
    def __init__(self, store):
        self._store = store

    def summary(self, chat_id: int, window: str = "24h") -> Dict[str, Any]:
        seconds = _WINDOWS.get(window, 86400)
        stats = self._store.stats(chat_id, seconds)
        return {"window": window, "total": stats["total"],
                "by_module": stats["by_module"], "by_action": stats["by_action"]}

    def top_signals(self, chat_id: int, window: str = "24h",
                    limit: int = 5) -> List[Dict[str, Any]]:
        seconds = _WINDOWS.get(window, 86400)
        events = self._store.recent_events(chat_id, limit=500)
        counts: Dict[str, int] = {}
        import time
        cutoff = time.time() - seconds
        for e in events:
            if e.get("created_at", 0) < cutoff:
                continue
            key = f"{e.get('module')}/{e.get('verdict') or e.get('action') or '?'}"
            counts[key] = counts.get(key, 0) + 1
        top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
        return [{"signal": k, "count": v} for k, v in top]

    def render(self, chat_id: int, window: str = "24h") -> str:
        s = self.summary(chat_id, window)
        lines = [f"🛡️ Blue Team — สรุป {window}",
                 f"รวมเหตุการณ์: {s['total']}"]
        bm = s["by_module"]
        lines.append(f"• 🔗 Link Guard: {bm.get('linkguard', 0)}")
        lines.append(f"• 🛡️ Scam Guard: {bm.get('scamguard', 0)}")
        lines.append(f"• 🥸 Impersonation: {bm.get('impersonation', 0)}")
        lines.append(f"• 👮 Join Guard: {bm.get('joinguard', 0)}")
        if s["by_action"]:
            acts = ", ".join(f"{k}:{v}" for k, v in sorted(s["by_action"].items()))
            lines.append(f"การดำเนินการ: {acts}")
        tops = self.top_signals(chat_id, window)
        if tops:
            lines.append("สัญญาณเด่น:")
            lines.extend(f"  • {t['signal']} ({t['count']})" for t in tops)
        lines.append("\nℹ️ ตัวเลขคือกิจกรรมของระบบ ไม่ใช่ข้อสรุปความผิดของสมาชิก")
        return "\n".join(lines)

    @staticmethod
    def wizard_intro() -> str:
        lines = ["🧙 ตั้งค่า Blue Team ครั้งแรก — เลือกชุดค่าที่เหมาะกับกลุ่ม:"]
        for key, preset in PRESETS.items():
            lines.append(f"• /blueteam setup {key} — {preset['label']}")
        lines.append("\nทุกโหมดเริ่มต้นแบบปลอดภัย: การแบนถาวรต้องมีแอดมินยืนยันเสมอ")
        return "\n".join(lines)

    def apply_preset(self, chat_id: int, preset: str, actor: int) -> bool:
        cfg = PRESETS.get(preset)
        if not cfg:
            return False
        for module in ("linkguard", "scamguard", "joinguard"):
            m = cfg[module]
            self._store.set_policy(
                chat_id, module, enabled=m.get("enabled", True),
                mode=m.get("mode", "MONITOR"), threshold=m.get("threshold", 45),
                sensitivity=m.get("sensitivity", "balanced"), actor=actor)
        return True
