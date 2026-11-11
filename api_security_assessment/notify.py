# -*- coding: utf-8 -*-
"""api_security_assessment/notify.py — แจ้งเตือนไปยัง API_SECURITY_REPORT_CHAT_ID

reuse ตัวแจ้งเตือนฐานร่วม (BaseNotifier) ของ web_vulnerability_assessment — ไม่ทำ
notification handler ซ้ำสองชุด; subclass แค่เปลี่ยนปลายทาง env + ตัว format ของ API
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from web_vulnerability_assessment.notify import BaseNotifier, _chat_from_env
from . import report

logger = logging.getLogger("modbot.api.notify")


def report_chat_id() -> Optional[int]:
    return _chat_from_env("API_SECURITY_REPORT_CHAT_ID")


class Notifier(BaseNotifier):
    """ตัวแจ้งเตือนของ API assessment — ปลายทาง API_SECURITY_REPORT_CHAT_ID"""
    report_env = "API_SECURITY_REPORT_CHAT_ID"
    file_prefix = "api"

    def _alert_text(self, finding: Dict[str, Any], target: str) -> str:
        return report.finding_alert(finding, target)

    def _summary_text(self, assessment: Dict[str, Any]) -> str:
        return report.summary_text(assessment)

    def _render_md(self, assessment: Dict[str, Any]) -> str:
        return report.render_markdown(assessment)

    def _render_json(self, assessment: Dict[str, Any]) -> str:
        return report.render_json(assessment)
