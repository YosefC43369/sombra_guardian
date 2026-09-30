# -*- coding: utf-8 -*-
"""
repo_intel.capabilities.opsec — #15 Operational Security (OpSec) Compliance Checker

สแกนหา "การส่งสัญญาณกลับ" ที่อาจฝังอยู่ในเครื่องมือของ repo: IP/โดเมนฝังตาย,
webhook (Discord/Telegram/Slack), endpoint เก็บ telemetry, การ POST ออกภายนอก —
สิ่งที่อาจทำให้ผู้ใช้เครื่องมือ "หลุด" ไปหาเจ้าของเดิมโดยไม่ตั้งใจ อ่านล้วน
"""

import re
import ipaddress
from typing import List

from ..model import CapabilityResult, CapabilityStatus, Finding
from ._common import iter_files, read_text, line_of

_IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_URL = re.compile(r"https?://([A-Za-z0-9.\-]+)(?:/[^\s'\"]*)?")
_WEBHOOK = re.compile(r"(discord\.com/api/webhooks|hooks\.slack\.com|api\.telegram\.org/bot)")
_PHONE_HOME = re.compile(r"(requests\.post|urllib\.request\.urlopen|fetch\(|axios\.post|"
                         r"socket\.(connect|sendto))", re.I)
_SOURCE_EXTS = (".py", ".js", ".ts", ".rb", ".php", ".go", ".java", ".sh", ".ps1")


def _is_public_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
        return ip.is_global and not ip.is_multicast
    except ValueError:
        return False


def run(ctx) -> CapabilityResult:
    findings: List[Finding] = []
    for full, rel in iter_files(ctx.workspace_path, _SOURCE_EXTS):
        text = read_text(full)
        if not text:
            continue
        for m in _WEBHOOK.finditer(text):
            findings.append(Finding("opsec", "high",
                                    "พบ webhook ภายนอกฝังในโค้ด (อาจส่งข้อมูลกลับเจ้าของเดิม)",
                                    detail=m.group(0), location=f"{rel}:{line_of(text, m.start())}",
                                    confidence="high"))
        for m in _IPV4.finditer(text):
            ip = m.group(1)
            if _is_public_ip(ip):
                findings.append(Finding("opsec", "medium",
                                        f"IP สาธารณะฝังตายในโค้ด: {ip}",
                                        location=f"{rel}:{line_of(text, m.start())}",
                                        confidence="medium"))
        # โดเมนภายนอก + มีพฤติกรรม phone-home ในไฟล์เดียวกัน = น่าสงสัยขึ้น
        if _PHONE_HOME.search(text):
            domains = {m.group(1) for m in _URL.finditer(text)
                       if not m.group(1).endswith(("localhost", "example.com"))}
            for d in list(domains)[:5]:
                findings.append(Finding("opsec", "low",
                                        f"มีการส่งข้อมูลออก + ปลายทางภายนอก: {d}",
                                        location=rel, confidence="low"))
        if len(findings) >= 120:
            break

    # ลดความซ้ำ
    seen = set()
    uniq = []
    for f in findings:
        key = (f.title, f.location)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    order = {"high": 0, "medium": 1, "low": 2}
    uniq.sort(key=lambda f: order.get(f.severity, 3))

    if not uniq:
        return CapabilityResult("OpSec Compliance Checker",
                                CapabilityStatus.CLEAN.value,
                                "ไม่พบสัญญาณส่งข้อมูลกลับ/beacon ที่ชัดเจน")
    high = sum(1 for f in uniq if f.severity == "high")
    return CapabilityResult("OpSec Compliance Checker", CapabilityStatus.OK.value,
                            f"พบจุดเสี่ยง OpSec {len(uniq)} จุด (สูง {high})",
                            findings=uniq[:40])
