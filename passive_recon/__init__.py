# -*- coding: utf-8 -*-
"""passive_recon — โมดูล Passive Reconnaissance & Intelligence (เสริม ไม่แทนของเดิม)

รับ URL/โดเมนผ่านคำสั่ง /recon แล้วเก็บข่าวกรองแบบ passive: DNS, WHOIS/RDAP,
subdomains (Certificate Transparency), เทคโนโลยี, TLS, HTTP metadata, ASN/ISP/geo,
และตัวชี้วัดความปลอดภัยเชิงข้อมูล — ออกรายงาน JSON/TXT/Markdown

reuse ของเดิม (ไม่ทำซ้ำ):
  osint.utils.async_http.AsyncHTTPClient   HTTP client (rate-limit/retry)
  osint.utils.validators                   เกณฑ์ IP สาธารณะ (SSRF)
  osint.sources.crtsh.fetch_subdomains     Certificate Transparency
  osint.sources.bgpview.BGPViewIPSource    ASN/prefix
  urlkit                                    eTLD+1

ส่วนประกอบ:
  parse.py      ตรรกะวิเคราะห์ล้วน (normalize/fingerprint/parse/report) — เทสต์ได้ 100%
  safehttp.py   ยิงเน็ตแบบปลอด SSRF + DoH + TLS cert
  collectors.py ตัวเก็บข้อมูลรายหมวด (async)
  recon.py      เวิร์กโฟลว์หลัก + render รายงาน
  commands.py   คำสั่ง /recon (เดี่ยว + ไฟล์ .txt)

การผูกกับ app.py (ต่อสายไว้ให้แล้ว — ดู README.md):
  import passive_recon
  passive_recon.register_commands(app, is_admin)    # ลง /recon
"""

from __future__ import annotations

import logging

from . import parse, safehttp, collectors, recon, commands
from .recon import run_recon, render, summary_line
from .commands import cmd_recon, HELP

logger = logging.getLogger("modbot.passive_recon")


def register_commands(app, is_admin) -> int:
    """ลง /recon กับ Application เดิม (คืนจำนวนที่ลง)"""
    from telegram.ext import CommandHandler
    app.add_handler(CommandHandler(
        "recon", lambda u, c: cmd_recon(u, c, is_admin)))
    logger.info("passive_recon | registered /recon")
    return 1


__all__ = [
    "parse", "safehttp", "collectors", "recon", "commands",
    "run_recon", "render", "summary_line", "register_commands",
    "cmd_recon", "HELP",
]
