# -*- coding: utf-8 -*-
"""
repo_intel.capabilities.regression — #13 Regression / staleness / patch tracking

อ่านเมทาดาทา git (read-only: git log) เพื่อบอกว่า repo นี้ "เก่าแค่ไหน" อัปเดตล่าสุด
เมื่อไร กี่คอมมิต และสแกนร่องรอยโค้ดยุคเก่า (Python2, API ที่เลิกใช้) ที่มักทำให้
รันไม่ได้บนสภาพแวดล้อมปัจจุบัน — ช่วยตอบว่า "ทำไมของเก่า 10 ปีถึงพัง"
"""

import os
import re
import subprocess
from datetime import datetime, timezone
from typing import List, Optional

from ..model import CapabilityResult, CapabilityStatus, Finding
from ._common import iter_files, read_text, line_of

_PY2_MARKERS = [
    (re.compile(r"(?m)^\s*print\s+[^(\n]"), "โค้ดใช้ print แบบ Python 2 (print statement)"),
    (re.compile(r"except\s+\w+\s*,\s*\w+\s*:"), "ไวยากรณ์ except Python 2 (except E, e:)"),
    (re.compile(r"\b(urllib2|urlparse|cStringIO|__builtin__|itertools\.izip)\b"),
     "import ที่หายไปใน Python 3"),
    (re.compile(r"\bhas_key\s*\("), "dict.has_key() (ถูกลบใน Python 3)"),
]
_DEPRECATED = re.compile(r"\bimport\s+(imp|optparse|asyncore|asynchat|formatter)\b")


def _git(ws: str, args: List[str]) -> Optional[str]:
    try:
        p = subprocess.run(["git", "-C", ws] + args, capture_output=True,
                           text=True, timeout=15)
        return p.stdout.strip() if p.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def run(ctx) -> CapabilityResult:
    ws = ctx.workspace_path
    findings: List[Finding] = []
    data = {}

    last_iso = _git(ws, ["log", "-1", "--format=%cI"])
    if last_iso:
        data["last_commit"] = last_iso
        try:
            dt = datetime.fromisoformat(last_iso.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - dt).days
            data["age_days"] = age_days
            years = age_days / 365.0
            if years >= 5:
                findings.append(Finding("regression", "medium",
                                        f"repo ไม่ถูกอัปเดตมานาน ~{years:.1f} ปี",
                                        confidence="high"))
            elif years >= 2:
                findings.append(Finding("regression", "low",
                                        f"อัปเดตล่าสุด ~{years:.1f} ปีก่อน", confidence="high"))
        except ValueError:
            pass
    count = _git(ws, ["rev-list", "--count", "HEAD"])
    if count:
        data["commit_count"] = count

    # ร่องรอย Python 2 / API เก่า
    py2_hits = 0
    for full, rel in iter_files(ws, (".py",)):
        text = read_text(full)
        if not text:
            continue
        for rx, title in _PY2_MARKERS:
            m = rx.search(text)
            if m:
                py2_hits += 1
                findings.append(Finding("regression", "medium", title,
                                        location=f"{rel}:{line_of(text, m.start())}",
                                        confidence="medium"))
                break
        m = _DEPRECATED.search(text)
        if m:
            findings.append(Finding("regression", "low",
                                    f"ใช้โมดูลที่เลิกใช้/ถูกลบ: {m.group(1)}",
                                    location=f"{rel}:{line_of(text, m.start())}",
                                    confidence="medium"))
        if len(findings) >= 60:
            break
    data["python2_markers"] = py2_hits

    summary_bits = []
    if "age_days" in data:
        summary_bits.append(f"อัปเดตล่าสุด {data['age_days']} วันก่อน")
    if py2_hits:
        summary_bits.append(f"พบร่องรอยโค้ดยุคเก่า {py2_hits} ไฟล์")
    summary = " · ".join(summary_bits) if summary_bits else "ไม่พบสัญญาณความเก่าที่ชัดเจน"
    status = CapabilityStatus.OK.value if findings else CapabilityStatus.CLEAN.value
    return CapabilityResult("Regression / Staleness", status, summary,
                            findings=findings[:40], data=data)
