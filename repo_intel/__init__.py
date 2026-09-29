# -*- coding: utf-8 -*-
"""
repo_intel — โมดูลวิเคราะห์ repository ที่ clone มาแล้ว (ต่อยอดจากสแต็ก git-clone เดิม)

หน้าที่: หลังบอต git clone แล้ว โมดูลนี้จะ (1) ระบุว่า repo ทำงานแบบไหน (2) "รันจริง"
ในแซนด์บ็อกซ์ของโปรเจกต์ (repository_sandbox.py) เพื่อดูว่าปัจจุบันยังใช้งานได้ไหม
(3) วิเคราะห์เชิงลึก (ช่องโหว่/ห่วงโซ่อุปทาน/OpSec/ความเก่า ฯลฯ) และ (4) ให้ AI
เรียบเรียงเป็นภาษาคนเข้าใจง่าย

กฎเหล็ก: คำตัดสิน "ใช้งานได้/ไม่ได้/ยังไม่ได้เทส" มาจากผลรันจริงเท่านั้น — ถ้าไม่ได้
รันเทส จะไม่มีทางรายงานว่า "เทสแล้ว" และถ้ารันแล้ว error จะไม่มีทางรายงานว่า "ผ่าน"

ข้อบังคับสถาปัตยกรรม: โมดูลนี้ "ห้าม" import หรืออ้างอิง scope_policy.py โดยเด็ดขาด
(ตรวจได้: ไม่มี `import scope_policy` หรือชื่อฟังก์ชันของมันในทุกไฟล์ของแพ็กเกจ)
"""

from .model import (RepoIntelReport, Verdict, VerdictStatus, Evidence,
                    ProbeKind, CapabilityResult, CapabilityStatus, Finding,
                    Fingerprint)
from .analyzer import analyze, analyze_sync
from .report import render
from .verdict import decide, verdict_banner

__all__ = [
    "analyze", "analyze_sync", "render", "decide", "verdict_banner",
    "RepoIntelReport", "Verdict", "VerdictStatus", "Evidence", "ProbeKind",
    "CapabilityResult", "CapabilityStatus", "Finding", "Fingerprint",
]

__version__ = "1.0.0"
