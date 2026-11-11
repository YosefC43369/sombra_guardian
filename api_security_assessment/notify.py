# -*- coding: utf-8 -*-
"""api_security_assessment/notify.py — แจ้งเตือนไปยัง API_SECURITY_REPORT_CHAT_ID

ใช้ bot instance เดิม ส่งไปปลายทางที่ตั้งแยกจาก WVA ได้ (API_SECURITY_REPORT_CHAT_ID)
กันแจ้งซ้ำภายใน run · ไม่ส่งข้อมูลอ่อนไหว (evidence ถูก sanitize มาก่อนแล้ว)
"""

from __future__ import annotations

import os
import io
import logging
from typing import Any, Dict, Optional, Set

from . import report

logger = logging.getLogger("modbot.api.notify")


def report_chat_id() -> Optional[int]:
    raw = (os.getenv("API_SECURITY_REPORT_CHAT_ID", "") or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


class Notifier:
    def __init__(self, bot, fallback_chat_id: Optional[int] = None):
        self.bot = bot
        self.fallback = fallback_chat_id
        self._sent: Set[str] = set()

    def _dest(self) -> Optional[int]:
        return report_chat_id() or self.fallback

    async def finding_alert(self, finding: Dict[str, Any], assessment: Dict[str, Any]) -> bool:
        dest = self._dest()
        if dest is None:
            return False
        key = f"{finding.get('category')}|{finding.get('endpoint')}|{finding.get('rule')}"
        if key in self._sent:
            return False
        self._sent.add(key)
        try:
            await self.bot.send_message(chat_id=dest,
                                        text=report.finding_alert(finding, assessment.get("target", "")),
                                        disable_web_page_preview=True)
            return True
        except Exception:
            logger.exception("API finding alert failed")
            return False

    async def summary(self, assessment: Dict[str, Any], attach: bool = True) -> bool:
        dest = self._dest()
        if dest is None:
            return False
        try:
            await self.bot.send_message(chat_id=dest, text=report.summary_text(assessment))
            if attach:
                from telegram import InputFile
                aid = assessment.get("id")
                for name, data in ((f"api_{aid}.md", report.render_markdown(assessment)),
                                   (f"api_{aid}.json", report.render_json(assessment))):
                    try:
                        bio = io.BytesIO(data.encode("utf-8"))
                        bio.name = name
                        await self.bot.send_document(chat_id=dest,
                                                     document=InputFile(bio, filename=name))
                    except Exception:
                        logger.exception("API attach %s failed", name)
            return True
        except Exception:
            logger.exception("API summary failed")
            return False
