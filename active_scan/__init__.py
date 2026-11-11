# -*- coding: utf-8 -*-
"""active_scan — Active Scanning & Enumeration (gated ด้วย scope_policy)

โมดูลสแกน active: TCP connect port scan + banner grab + service id + DNS AXFR
เปิด socket จริง จึง "ยิงได้เฉพาะเป้าหมายที่ผ่าน scope_policy.evaluate_target()
และเป็น IP สาธารณะ" (reuse ด่าน authorization + network guard ของ security_testing เดิม)

เสริม/ต่อยอดจาก security_testing (passive web checks) — ไม่ซ้ำ ไม่แทน

ส่วนประกอบ:
  store.py    เก็บผลสแกน (atomic JSON)
  guard.py    ด่าน scope + public-IP (reuse evaluate_target + _forbidden_ip_reason)
  scanner.py  async TCP connect + banner + service + AXFR (RFC 1035)
  engine.py   ประสานงานหนึ่งสแกน
  commands.py /ascan

การผูกกับ app.py: import active_scan; active_scan.register_commands(app, is_admin)
"""

from __future__ import annotations

import logging

from . import store, guard, scanner, engine, commands
from .engine import run_scan
from .commands import cmd_ascan, HELP

logger = logging.getLogger("modbot.active_scan")


def register_commands(app, is_admin) -> int:
    from telegram.ext import CommandHandler
    app.add_handler(CommandHandler("ascan", lambda u, c: cmd_ascan(u, c, is_admin)))
    logger.info("active_scan | registered /ascan")
    return 1


__all__ = ["store", "guard", "scanner", "engine", "commands",
           "run_scan", "cmd_ascan", "HELP", "register_commands"]
