"""
blueteam/messages_th.py — message catalog (Thai primary, English fallback).

All user/admin-facing strings live here so wording is consistent and translatable.
:func:`msg` formats a key; unknown keys fall back to the key itself, and a missing
Thai string falls back to English, so a lookup never raises in a live handler.

SAFETY: these are *templates*. Callers must pass already-defanged URLs and must
NOT send user-supplied content with a Markdown/HTML parse_mode (กติกาข้อ 7).
"""

from __future__ import annotations

from typing import Dict

_CATALOG: Dict[str, Dict[str, str]] = {
    # --- shared ---
    "admin_only": {
        "th": "❌ คำสั่งนี้ใช้ได้เฉพาะแอดมิน",
        "en": "❌ Admins only.",
    },
    "not_in_group": {
        "th": "คำสั่งนี้ใช้ได้เฉพาะในกลุ่ม",
        "en": "This command only works in a group.",
    },
    "disabled_globally": {
        "th": "โมดูลนี้ถูกปิดโดยผู้ดูแลระบบ (kill switch)",
        "en": "This module is disabled by the operator (kill switch).",
    },
    # --- link guard ---
    "lg_status": {
        "th": "🔗 Link Guard: {state} | โหมด: {mode} | เกณฑ์: {threshold}",
        "en": "🔗 Link Guard: {state} | mode: {mode} | threshold: {threshold}",
    },
    "lg_result": {
        "th": "🔗 ผลตรวจลิงก์: {emoji} {verdict} (คะแนน {score}/100)\nลิงก์: {url}\nเหตุผล:\n{reasons}\n\n{limitation}",
        "en": "🔗 Link check: {emoji} {verdict} (score {score}/100)\nURL: {url}\nReasons:\n{reasons}\n\n{limitation}",
    },
    "lg_warn_group": {
        "th": "⚠️ ตรวจพบลิงก์น่าสงสัย ({verdict}) — โปรดใช้ความระมัดระวัง\n{url}",
        "en": "⚠️ Suspicious link detected ({verdict}) — please be careful.\n{url}",
    },
    "lg_deleted": {
        "th": "🗑️ ลบข้อความที่มีลิงก์อันตราย ({verdict})",
        "en": "🗑️ Removed a message with a dangerous link ({verdict}).",
    },
    "lg_reason_line": {"th": "• {fact}", "en": "• {fact}"},
    # --- scam guard ---
    "sg_result": {
        "th": "🛡️ ตรวจสแกม: {emoji} {verdict} (คะแนน {score}/100)\nหมวด: {categories}\nเหตุผล:\n{reasons}\n\n{limitation}",
        "en": "🛡️ Scam check: {emoji} {verdict} (score {score}/100)\nCategories: {categories}\nReasons:\n{reasons}\n\n{limitation}",
    },
    "sg_impersonation": {
        "th": "🥸 อาจปลอมเป็น {target} (ความคล้าย {score}/100) — โปรดตรวจสอบ",
        "en": "🥸 Possible impersonation of {target} (similarity {score}/100) — please verify.",
    },
    # --- join guard ---
    "jg_challenge": {
        "th": "👋 ยินดีต้อนรับ! กรุณายืนยันว่าไม่ใช่บอทโดยกดปุ่มด้านล่างภายใน {timeout} วินาที",
        "en": "👋 Welcome! Please prove you're human by tapping the button below within {timeout}s.",
    },
    "jg_challenge_button": {"th": "✅ ฉันไม่ใช่บอท", "en": "✅ I'm not a bot"},
    "jg_passed": {"th": "✅ ยืนยันตัวตนสำเร็จ ยินดีต้อนรับ!", "en": "✅ Verified — welcome!"},
    "jg_failed": {"th": "❌ ยืนยันตัวตนไม่สำเร็จ", "en": "❌ Verification failed."},
    "jg_challenge_expired": {
        "th": "⌛ หมดเวลายืนยันตัวตน", "en": "⌛ Verification timed out.",
    },
    "jg_not_your_challenge": {
        "th": "ปุ่มนี้ไม่ใช่ของคุณ", "en": "This button isn't for you.",
    },
    "jg_raid_detected": {
        "th": "🚨 ตรวจพบการบุกกลุ่ม (raid) — เปิดโหมดป้องกันชั่วคราว",
        "en": "🚨 Raid detected — temporary protection enabled.",
    },
    "jg_lockdown_on": {
        "th": "🔒 ล็อกกลุ่มชั่วคราว (จำกัดสิทธิ์ผู้เข้าใหม่) นาน {minutes} นาที",
        "en": "🔒 Group locked down (new-member restrictions) for {minutes} min.",
    },
    "jg_lockdown_off": {
        "th": "🔓 ปลดล็อกกลุ่ม กู้คืนสิทธิ์เดิมแล้ว",
        "en": "🔓 Lockdown lifted; original permissions restored.",
    },
    # --- dashboard ---
    "bt_dashboard_title": {
        "th": "🛡️ Blue Team — สรุป {window}", "en": "🛡️ Blue Team — {window} summary",
    },
    "limitation": {
        "th": "ℹ️ คะแนนคือเครื่องมือช่วยจัดลำดับตรวจสอบ ไม่ใช่ข้อพิสูจน์ความผิด",
        "en": "ℹ️ The score is a triage aid, not proof of wrongdoing.",
    },
}


def msg(key: str, lang: str = "th", **kwargs) -> str:
    entry = _CATALOG.get(key)
    if not entry:
        return key
    template = entry.get(lang) or entry.get("en") or entry.get("th") or key
    try:
        return template.format(**kwargs) if kwargs else template
    except (KeyError, IndexError):
        return template
