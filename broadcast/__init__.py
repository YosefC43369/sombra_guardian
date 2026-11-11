# -*- coding: utf-8 -*-
"""broadcast — ตั้งลิงก์เดียว ยิงออกไปทุกห้อง/ทุกคนอัตโนมัติตามรอบเวลา

ต่างจาก autolink (ที่โพสต์ "ในห้องตัวเอง") — broadcast ยิง "ออกไปยังปลายทางอื่น"
ตามทะเบียน targets ที่สะสมได้ทั้งแบบอัตโนมัติ (remember_chat) และเพิ่มเอง

การผูกเข้ากับ app.py (ต่อสายไว้ให้แล้ว — ดู broadcast/README.md)
--------------------------------------------------------------
    import broadcast

    # ลงทะเบียนคำสั่ง (ใน main())
    app.add_handler(CommandHandler("broadcast", broadcast.cmd_broadcast))

    # เริ่มลูปเบื้องหลัง (ใน post_init)
    _start_background_task(app, "broadcast_task",
                           lambda: broadcast.broadcast_background_loop(app.bot))

    # เก็บปลายทางอัตโนมัติ (ใน handle_message ต่อข้อความกลุ่ม/ส่วนตัว)
    broadcast.remember_chat(chat.id, title=..., ctype=chat.type)

    # post_shutdown: เพิ่ม "broadcast_task" เข้าชุดที่ cancel
"""

from __future__ import annotations

from . import store, core, loop, commands
from .loop import broadcast_background_loop, send_to_all, run_cycle
from .commands import cmd_broadcast, HELP


def remember_chat(chat_id, title: str = "", ctype: str = "") -> bool:
    """บันทึกปลายทางจากข้อความที่บอตเห็น (เรียกจาก handle_message ของ app.py)

    ทำงานเฉพาะเมื่อ config.collect=on และไม่เคยทำให้ handler หลักพัง (กลืน error เอง)
    คืน True ถ้าบันทึก/อัปเดตอะไร
    """
    return store.remember(chat_id, title=title or "", ctype=str(ctype or ""))


__all__ = [
    "store", "core", "loop", "commands",
    "broadcast_background_loop", "send_to_all", "run_cycle",
    "cmd_broadcast", "remember_chat", "HELP",
]
