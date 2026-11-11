# -*- coding: utf-8 -*-
"""risk_prioritization — เอนจินจัดลำดับความเสี่ยงขั้นสูง + Payload Execution Transparency

เอนจินความเสี่ยง "ตัวเดียว" ของแพลตฟอร์ม (ไม่สร้างซ้ำ) — รับ finding ที่โมดูลเดิมผลิตแล้ว
ให้คะแนนหลายปัจจัย (severity/exploitability/asset/evidence) จัดลำดับ อธิบายได้ แยกจากการ
"รันทดสอบ" และแยก technical severity ออกจาก overall risk

Payload Execution Transparency: บันทึก payload ที่ "ส่งจริง" ต่อ finding, แยก executed /
suggested / verified, เชื่อม evidence, และต่อยอดรายงาน (TXT/JSON) — reuse payload registry
เดิม (payload_engine) + report เดิม ไม่สร้างใหม่

reuse ของเดิม (ไม่ทำซ้ำ):
  * unified finding schema (orchestrator) — severity/state/request/test_case_id/evidence
  * attack_surface_correlation (asset context) · evidence_management (evidence confidence)
  * web_vulnerability_assessment.payload_engine (payload registry, ขยายแล้ว)
  * classify.sanitize (redact) · gemini.ask_gemini (AI) · atomic store · บอต/report chat/perms

ส่วนประกอบ:
  model.py         โมเดลให้คะแนนหลายปัจจัย (pure, documented formula)
  engine.py        ประสาน + integration (asc/evidence) + AI + analyze_task
  transparency.py  payload execution transparency (executed/suggested/verified + evidence)
  store.py         atomic JSON store + snapshot
  report.py        รายงานความเสี่ยง + PAYLOAD EXECUTION DETAILS (TXT/JSON)
  commands.py      /risk_* (reuse บอต)

การผูกกับ app.py:
  import risk_prioritization as risk
  risk.register_commands(app, is_admin)     # /risk_assess /risk_status /risk_report /risk_payloads
"""

from __future__ import annotations

import logging

from . import model, engine, transparency, store, report, commands
from .engine import run, prioritize, assess_finding, analyze_task, ai_explain
from .transparency import build_transparency, executed_from_findings, suggested_payloads
from .commands import HELP

logger = logging.getLogger("modbot.risk")

__all__ = [
    "model", "engine", "transparency", "store", "report", "commands",
    "run", "prioritize", "assess_finding", "analyze_task", "ai_explain",
    "build_transparency", "executed_from_findings", "suggested_payloads",
    "register_commands", "HELP",
]


def register_commands(app, is_admin) -> int:
    """ลง /risk_* กับ Application เดิม (คืนจำนวนที่ลง)"""
    from telegram.ext import CommandHandler
    pairs = {
        "risk_assess": commands.cmd_assess,
        "risk_status": commands.cmd_status,
        "risk_report": commands.cmd_report,
        "risk_payloads": commands.cmd_payloads,
    }
    n = 0
    for name, h in pairs.items():
        app.add_handler(CommandHandler(
            name, (lambda hh: (lambda u, c: hh(u, c, is_admin)))(h)))
        n += 1
    logger.info("risk_prioritization | registered %d commands", n)
    return n
