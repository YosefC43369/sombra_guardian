# -*- coding: utf-8 -*-
"""red_team_orchestrator — ชั้นประสานงานกลางของแพลตฟอร์ม Red Team

ไม่สแกนเอง ไม่สร้างบอต/scanner ใหม่ — รับงานจาก Telegram handler, เลือกโมดูลเดิมที่
เกี่ยวข้อง, สร้าง execution plan (ต้องอนุมัติ), รันตามลำดับ (timeout+cancel), รวมผลเป็น
unified finding, correlate, สรุปด้วย AI เดิม (ออปชัน) แล้วส่งรายงานผ่านช่องทางเดิม

reuse: scope_policy/simple_scope (authorization — ไม่ bypass), โมดูลเดิมทุกตัวผ่าน run
function จริง, wva.classify (sanitize), gemini (AI), bot instance เดิม, SECURITY_REPORT_CHAT_ID

ส่วนประกอบ: store (tasks) · registry (adapters+pipelines) · engine (lifecycle) ·
report (render) · commands (/rt_*)

ผูก: import red_team_orchestrator as rto; rto.register_commands(app, is_admin)
"""

from __future__ import annotations

import logging

from . import store, registry, engine, report, commands
from .engine import create_task, run_task, build_plan, approve
from .commands import HELP

logger = logging.getLogger("modbot.rt_orch")


def register_commands(app, is_admin) -> int:
    from telegram.ext import CommandHandler
    pairs = {
        "rt_assess": commands.cmd_assess,
        "rt_plan": commands.cmd_plan,
        "rt_approve": commands.cmd_approve,
        "rt_status": commands.cmd_status,
        "rt_cancel": commands.cmd_cancel,
        "rt_report": commands.cmd_report,
    }
    n = 0
    for name, h in pairs.items():
        app.add_handler(CommandHandler(name, (lambda hh: (lambda u, c: hh(u, c, is_admin)))(h)))
        n += 1
    logger.info("red_team_orchestrator | registered %d commands", n)
    return n


__all__ = ["store", "registry", "engine", "report", "commands",
           "create_task", "run_task", "build_plan", "approve",
           "register_commands", "HELP"]
