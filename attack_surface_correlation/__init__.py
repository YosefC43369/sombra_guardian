# -*- coding: utf-8 -*-
"""attack_surface_correlation — เอนจินเชื่อมโยงพื้นที่โจมตี (Attack Surface Correlation)

เป็น "ส่วนวิเคราะห์+เชื่อมโยงข้อมูล" ไม่ใช่ scanner/recon ตัวใหม่ — รับ output ที่โมดูลเดิม
เก็บมาแล้ว (passive_recon · web_vulnerability_assessment · api_security_assessment ·
active_scan · unified findings ของ red_team_orchestrator) แล้ว normalize → dedupe →
หาความสัมพันธ์ → สร้างกราฟ → สร้าง insight → เทียบประวัติ → (อธิบายด้วย AI เดิมแบบออปชัน)

reuse ของเดิม (ไม่ทำซ้ำ):
  * unified finding schema + ModuleResult ของ red_team_orchestrator
  * output ดิบของ passive_recon / wva / api / active_scan
  * gemini.ask_gemini (AI — ไม่สร้าง client ใหม่)
  * atomic JSON store pattern + resource/ (เหมือนทุกโมดูล)
  * บอต + SECURITY_REPORT_CHAT_ID (web_vulnerability_assessment.notify)

ส่วนประกอบ:
  normalize.py  ตรรกะ normalize/dedupe asset (pure, stdlib) — เทสต์ได้ 100%
  relate.py     correlation rules + กันผลบวกลวง (pure)
  graph.py      สร้างกราฟ attack surface (pure, lightweight)
  insights.py   insight เชิงวิเคราะห์ + เทียบประวัติ (pure)
  store.py      เก็บผล + snapshot (atomic JSON)
  engine.py     ประสานทั้งหมด + AI ออปชัน + integration กับ orchestrator
  report.py     เรนเดอร์รายงาน (concise/markdown/json/graph)
  commands.py   /asc_* (reuse บอตเดิม)

การผูกกับ app.py:
  import attack_surface_correlation as asc
  asc.register_commands(app, is_admin)     # ลง /asc_correlate /asc_status /asc_report

การผูกกับ orchestrator (ออปชัน, non-invasive):
  หลัง task เสร็จ -> await asc.analyze_task(task_id)   # ไม่สแกนใหม่
"""

from __future__ import annotations

import logging

from . import normalize, relate, graph, insights, store, engine, report, commands
from .engine import correlate, build_result, analyze_task, from_task, ai_explain
from .commands import HELP

logger = logging.getLogger("modbot.asc")

__all__ = [
    "normalize", "relate", "graph", "insights", "store", "engine", "report",
    "commands", "correlate", "build_result", "analyze_task", "from_task",
    "ai_explain", "register_commands", "HELP",
]


def register_commands(app, is_admin) -> int:
    """ลง /asc_* กับ Application เดิม (คืนจำนวนที่ลง)"""
    from telegram.ext import CommandHandler
    pairs = {
        "asc_correlate": commands.cmd_correlate,
        "asc_status": commands.cmd_status,
        "asc_report": commands.cmd_report,
    }
    n = 0
    for name, h in pairs.items():
        app.add_handler(CommandHandler(
            name, (lambda hh: (lambda u, c: hh(u, c, is_admin)))(h)))
        n += 1
    logger.info("attack_surface_correlation | registered %d commands", n)
    return n
