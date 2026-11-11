# -*- coding: utf-8 -*-
"""vuln_probe — Active Vulnerability Validation (safe-validation, gated) module 2/8

ยืนยัน *การมีอยู่ของ indicator* แบบไม่ทำลายข้อมูล (reflected XSS / error-based SQLi /
SSTI / open-redirect / CORS misconfig / subdomain takeover) ด้วย marker-based detection
— ไม่ exploit, ไม่ extract ข้อมูล, คำขอจำกัดจำนวน, ยิงผ่านด่าน scope+SSRF ของ
security_testing เสมอ. ผลเป็น indicator สำหรับยกเข้า observation → review gate ของ redteam

ส่วนประกอบ: probes.py (ตัววิเคราะห์ pure) · store.py · engine.py (ยิงผ่าน gate เดิม) · commands.py
ผูก: import vuln_probe; vuln_probe.register_commands(app, is_admin)
"""

from __future__ import annotations

import logging

from . import probes, store, engine, commands
from .engine import run_probe
from .commands import cmd_vprobe, HELP

logger = logging.getLogger("modbot.vuln_probe")


def register_commands(app, is_admin) -> int:
    from telegram.ext import CommandHandler
    app.add_handler(CommandHandler("vprobe", lambda u, c: cmd_vprobe(u, c, is_admin)))
    logger.info("vuln_probe | registered /vprobe")
    return 1


__all__ = ["probes", "store", "engine", "commands", "run_probe", "cmd_vprobe",
           "HELP", "register_commands"]
