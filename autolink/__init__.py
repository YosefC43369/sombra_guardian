# -*- coding: utf-8 -*-
"""autolink — ระบบส่งลิงก์เว็บอัตโนมัติแบบตลอดเวลา (สั่งงานผ่านคำสั่งบอต)

โครงสร้าง
---------
  store.py    ชั้นเก็บข้อมูล JSON atomic (pure)
  engine.py   ตรรกะกำหนดเวลา/เลือกลิงก์/ประกอบข้อความ (pure)
  loop.py     background loop ที่ยิงลิงก์ตลอดเวลา (async)
  commands.py handler คำสั่ง /autolink ของ Telegram

การผูกเข้ากับ app.py (เพิ่มแค่ไม่กี่บรรทัด — ดู autolink/README.md)
---------------------------------------------------------------
    import autolink

    # ใน main(): ลงทะเบียนคำสั่ง
    app.add_handler(CommandHandler(
        "autolink",
        lambda u, c: autolink.cmd_autolink(u, c, is_admin),
    ))

    # ใน post_init(app): เริ่มลูปเบื้องหลัง
    _start_background_task(
        app, "autolink_task",
        lambda: autolink.autolink_background_loop(app.bot),
    )

    # ใน post_shutdown(app): เพิ่ม "autolink_task" เข้าชุดที่ต้อง cancel
"""

from __future__ import annotations

from . import store, engine, loop, commands
from .loop import autolink_background_loop, run_cycle
from .commands import cmd_autolink, HELP

__all__ = [
    "store",
    "engine",
    "loop",
    "commands",
    "autolink_background_loop",
    "run_cycle",
    "cmd_autolink",
    "HELP",
]
