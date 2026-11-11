# -*- coding: utf-8 -*-
"""api_security_assessment — authorized API Security Assessment (safe-validation) module

ประเมินความปลอดภัย REST/GraphQL/JSON API แบบ detection (ไม่ bypass/forge/brute/DoS)
บนเป้าหมายที่ authorize ผ่าน scope_policy — นำเข้า OpenAPI/Swagger/Postman, วิเคราะห์
endpoint/auth/authz(BOLA/BFLA ด้วย test account)/input/GraphQL/CORS/misconfig/rate-limit,
ออก finding (CONFIRMED/POTENTIAL/INFORMATIONAL/NOT_REPRODUCIBLE), รายงาน JSON/TXT/MD,
แจ้งเตือนเข้า API_SECURITY_REPORT_CHAT_ID

reuse: scope_policy/security_testing (gate+SSRF) · web_vulnerability_assessment
(classify/sanitize/simple_scope/detectors) · vuln_probe.probes (ผ่าน WVA) · gemini · bot เดิม

ผูก: import api_security_assessment as api; api.register_commands(app, is_admin)
"""

from __future__ import annotations

import logging

from . import spec, analyzers, store, engine, report, notify, commands
from .engine import run_assessment
from .commands import HELP

logger = logging.getLogger("modbot.api")


def register_commands(app, is_admin) -> int:
    from telegram.ext import CommandHandler
    pairs = {
        "api_assess": commands.cmd_assess,
        "api_import": commands.cmd_import,
        "api_status": commands.cmd_status,
        "api_report": commands.cmd_report,
        "api_stop": commands.cmd_stop,
    }
    n = 0
    for name, h in pairs.items():
        app.add_handler(CommandHandler(name, (lambda hh: (lambda u, c: hh(u, c, is_admin)))(h)))
        n += 1
    logger.info("api_security_assessment | registered %d commands", n)
    return n


__all__ = ["spec", "analyzers", "store", "engine", "report", "notify", "commands",
           "run_assessment", "register_commands", "HELP"]
