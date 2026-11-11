# -*- coding: utf-8 -*-
"""group_security_intelligence — ชั้นข่าวกรองความปลอดภัยกลุ่ม (เสริม ไม่แทนของเดิม)

โมดูลอิสระที่เพิ่มการเฝ้าระวัง/ข่าวกรองความปลอดภัยระดับกลุ่มให้บอตเดิม โดย:
  * ใช้เฉพาะข้อมูลที่ Telegram Bot API เปิดให้ (ไม่อ้าง session/อุปกรณ์/IP)
  * reuse ของเดิม: integrity_ledger (audit tamper-evident), gemini (AI เสริม),
    is_admin (สิทธิ์), ช่องแจ้งเตือนเข้า group, on_chat_member_update (event แอดมิน)
  * ไม่ซ้ำกับ anti-spam/moderation/member-incident ที่มีอยู่

ส่วนประกอบ:
  store.py      เก็บ snapshot/finding/incident/backup (atomic JSON, pure)
  detectors.py  ตรวจข้อมูลลับ (redact) + social engineering (เชิงบริบท)
  monitor.py    snapshot/diff แอดมิน-คอนฟิก-ลิงก์เชิญ + สถานะ integrity
  correlate.py  เอนจินรวมเหตุการณ์เป็น incident (INFO..CRITICAL)
  service.py    ประสานงาน async + audit + แจ้งเตือน + loop + backup/recovery
  commands.py   คำสั่ง /security_* + แดชบอร์ด

การผูกกับ app.py (ต่อสายไว้ให้แล้ว — ดู README.md):
  import group_security_intelligence as gsi
  # คำสั่ง: gsi.register_commands(app, is_admin)  (หรือเพิ่ม CommandHandler เอง)
  # loop:   _start_background_task(app, "gsi_task", lambda: gsi.background_loop(app.bot))
  # ข้อความ: gsi.on_message(bot, chat_id, user_id, text, ...)  ใน handle_message
  # แอดมิน:  gsi.on_admin_update(bot, chat_id, old, new, actor)  ใน on_chat_member_update
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from . import store, detectors, monitor, correlate, service, commands
from .service import background_loop, scan_message, ensure_baseline
from .monitor import ADMIN_PERMS

logger = logging.getLogger("modbot.gsi")

# ชื่อคำสั่ง -> handler (ผูกใน app.py)
COMMAND_MAP = {
    "group_security": commands.cmd_group_security,
    "security_audit": commands.cmd_security_audit,
    "security_admins": commands.cmd_security_admins,
    "security_integrity": commands.cmd_security_integrity,
    "security_invites": commands.cmd_security_invites,
    "security_secrets": commands.cmd_security_secrets,
    "security_incidents": commands.cmd_security_incidents,
    "security_backup": commands.cmd_security_backup,
    "security_recovery": commands.cmd_security_recovery,
    "security_report": commands.cmd_security_report,
}


def register_commands(app, is_admin) -> int:
    """ลงทะเบียนคำสั่ง /security_* ทั้งหมดกับ Application (คืนจำนวนที่ลง)

    is_admin = ฟังก์ชัน async เดิมของ app.py — ส่งเข้ามาเพื่อไม่ import วน
    """
    from telegram.ext import CommandHandler
    n = 0
    for name, handler in COMMAND_MAP.items():
        app.add_handler(CommandHandler(
            name, (lambda h: (lambda u, c: h(u, c, is_admin)))(handler)))
        n += 1
    logger.info("GSI | registered %d security commands", n)
    return n


# ---- hook ที่ app.py เรียกจาก event handler เดิม ----

def on_message(bot, chat_id, user_id, text: str, username: Optional[str] = None,
               message_id: Optional[int] = None, delete_cb=None):
    """เรียกจาก handle_message — คืน coroutine ให้ app.py schedule เป็น task

    (ไม่ await ในตัว handler หลัก เพื่อไม่บล็อก event loop)
    """
    return scan_message(bot, chat_id, user_id, text, username=username,
                        message_id=message_id, delete_cb=delete_cb)


def on_admin_update(bot, chat_id, old_member: Optional[Dict[str, Any]],
                    new_member: Dict[str, Any], actor_id: Optional[int] = None):
    """เรียกจาก on_chat_member_update — คืน coroutine สำหรับ schedule"""
    return service.observe_admin_transition(bot, chat_id, old_member, new_member, actor_id)


def member_to_dict(chat_member) -> Dict[str, Any]:
    """แปลง telegram ChatMember -> dict สำหรับ monitor.diff_admin_transition

    ใช้ใน app.on_chat_member_update ก่อนส่งเข้า on_admin_update
    """
    if chat_member is None:
        return {}
    u = getattr(chat_member, "user", None)
    d = {
        "user_id": getattr(u, "id", None),
        "status": str(getattr(chat_member, "status", "")),
        "username": getattr(u, "username", None),
        "display": getattr(u, "full_name", None),
    }
    for p in ADMIN_PERMS:
        d[p] = bool(getattr(chat_member, p, False))
    return d


def on_invite_seen(bot, chat_id, link: str, name: Optional[str],
                   creator_id: Optional[int]):
    """เรียกจาก on_chat_member_update เมื่อมี invite_link ติดมากับการ join"""
    return service.observe_invite_from_join(bot, chat_id, link, name, creator_id)


__all__ = [
    "store", "detectors", "monitor", "correlate", "service", "commands",
    "background_loop", "scan_message", "ensure_baseline",
    "register_commands", "on_message", "on_admin_update", "on_invite_seen",
    "member_to_dict", "COMMAND_MAP",
]
