# -*- coding: utf-8 -*-
"""evidence_management — คลังหลักฐาน & ข่าวกรองการประเมิน Red Team (Evidence Repository)

ศูนย์กลางเก็บ/รักษา/ตรวจสอบ/จัดระเบียบ/เชื่อมโยง/นำเสนอหลักฐานจากโมดูลประเมินที่มีอยู่
(passive_recon · web/api assessment · group_security_intelligence · attack_surface_correlation ·
red_team_orchestrator) — เป็นส่วนจัดการข้อมูลล้วน ไม่สแกน ไม่สร้าง scanner/orchestrator/
correlation engine ใหม่

reuse ของเดิม (ไม่ทำซ้ำ):
  * web_vulnerability_assessment.classify.sanitize/sanitize_headers (redaction ชุดเดียว)
  * integrity_ledger (Merkle/hash-chain + canonical_json — ของเดิม)
  * hashlib SHA-256 (แบบเดียวกับ findings.py)
  * unified finding schema (orchestrator) + correlation result (asc) + passive report
  * gemini.ask_gemini (AI — ไม่สร้าง client ใหม่)
  * atomic JSON store pattern + resource/ · บอต + SECURITY_REPORT_CHAT_ID + admin perms

ส่วนประกอบ:
  schema.py     unified evidence schema + validation (pure)
  redact.py     redaction (reuse classify) + ติดตามว่า redact จริง (pure)
  integrity.py  SHA-256 + chain-of-custody hash chain + verify (pure)
  store.py      atomic JSON store (evidence + custody, append-only)
  ingest.py     ingestion มาตรฐาน + file safety + ตัวแปลง output โมดูลเดิม (pure)
  timeline.py   ไทม์ไลน์การประเมิน (pure)
  service.py    ingest ชุด/verify/map/timeline/AI (orchestration)
  report.py     executive summary + technical appendix (pure)
  commands.py   /evd_* (reuse บอต + report chat + admin perms)

การผูกกับ app.py:
  import evidence_management as evd
  evd.register_commands(app, is_admin)     # ลง /evd_*

การผูกกับ orchestrator (ออปชัน, non-invasive):
  evd.service.ingest_task(task, module_outputs=..., correlation=...)   # ไม่สแกนใหม่
"""

from __future__ import annotations

import logging

from . import (schema, redact, integrity, store, ingest, timeline, service,
               report, commands)
from .service import (submit, submit_many, ingest_task, verify, verify_assessment,
                      evidence_for_finding, access, get_timeline, ai_explain_evidence)
from .commands import HELP

logger = logging.getLogger("modbot.evidence")

__all__ = [
    "schema", "redact", "integrity", "store", "ingest", "timeline", "service",
    "report", "commands", "submit", "submit_many", "ingest_task", "verify",
    "verify_assessment", "evidence_for_finding", "access", "get_timeline",
    "ai_explain_evidence", "register_commands", "HELP",
]


def register_commands(app, is_admin) -> int:
    """ลง /evd_* กับ Application เดิม (คืนจำนวนที่ลง)"""
    from telegram.ext import CommandHandler
    pairs = {
        "evd_collect": commands.cmd_collect,
        "evd_list": commands.cmd_list,
        "evd_get": commands.cmd_get,
        "evd_verify": commands.cmd_verify,
        "evd_finding": commands.cmd_finding,
        "evd_timeline": commands.cmd_timeline,
        "evd_report": commands.cmd_report,
    }
    n = 0
    for name, h in pairs.items():
        app.add_handler(CommandHandler(
            name, (lambda hh: (lambda u, c: hh(u, c, is_admin)))(h)))
        n += 1
    logger.info("evidence_management | registered %d commands", n)
    return n
