# -*- coding: utf-8 -*-
"""
repo_intel.capabilities — ทะเบียนความสามารถวิเคราะห์ (ต่อยอดได้)

แต่ละ capability คือฟังก์ชัน ``run(ctx) -> CapabilityResult`` ทำงานอิสระ ล้มเหลว
ตัวหนึ่งไม่ทำให้ทั้งงานล่ม (orchestrator ครอบ try ให้) เพิ่มความสามารถใหม่ = เพิ่ม
ไฟล์หนึ่งไฟล์แล้วลงทะเบียนใน REGISTRY

หลักความซื่อสัตย์: ความสามารถที่ยังทำไม่ได้จริง (ต้องใช้เครื่องมือ/โครงสร้างพื้นฐาน
ภายนอก) ต้องคืนสถานะ NOT_IMPLEMENTED/UNAVAILABLE ตรง ๆ พร้อมบอกว่า "ต้องมีอะไร"
ห้ามปั้นผลลวงว่าทำได้

ไม่ import scope_policy และไม่อ้างอิงถึงมันในทุกไฟล์ของแพ็กเกจนี้
"""

import logging
from dataclasses import dataclass
from typing import Any, Callable, List

from ..model import Fingerprint, CapabilityResult, CapabilityStatus

logger = logging.getLogger("modbot.repo_intel.capabilities")


@dataclass
class AnalysisContext:
    repository_id: Any
    workspace_path: str
    fingerprint: Fingerprint


from . import supply_chain, opsec, vuln_scan, regression, yara_gen, disasm, multiarch, roadmap

# ลำดับการรัน — วิเคราะห์สถิตที่มีประโยชน์สูงก่อน แล้วตามด้วยตรวจเครื่องมือ/roadmap
REGISTRY: List[Callable[[AnalysisContext], CapabilityResult]] = [
    vuln_scan.run,       # #1  Vulnerability ID + PoC scaffold (สถิต)
    supply_chain.run,    # #9  Supply chain / dependency poisoning
    opsec.run,           # #15 OpSec / beacon-callback scan
    regression.run,      # #13 Regression / staleness / patch tracking
    yara_gen.run,        # #5  YARA rule generator (ส่วน generator; evasion loop = roadmap)
    disasm.run,          # #14 Headless disassembly (ถ้ามีเครื่องมือ)
    multiarch.run,       # #10 Multi-arch execution support (ตรวจ QEMU)
    roadmap.run,         # #2/#3/#4/#6/#7/#8/#11/#12/#16 — บอกสถานะตรง ๆ
]


def run_all(ctx: AnalysisContext) -> List[CapabilityResult]:
    results: List[CapabilityResult] = []
    for cap in REGISTRY:
        try:
            results.append(cap(ctx))
        except Exception as exc:  # capability พังตัวเดียว ไม่ล้มทั้งงาน
            logger.exception("capability %s ล้มเหลว", getattr(cap, "__module__", cap))
            results.append(CapabilityResult(
                name=getattr(cap, "__module__", "unknown"),
                status=CapabilityStatus.ERROR.value,
                summary=f"ทำงานผิดพลาด: {type(exc).__name__}: {exc}"))
    return results
