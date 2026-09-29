# -*- coding: utf-8 -*-
"""
repo_intel.capabilities.roadmap — ความสามารถที่ "ยังไม่ลงมือจริง" ประกาศตรง ๆ

กฎเหล็กของโมดูลนี้คือห้ามปั้นผลลวง ความสามารถขั้นสูงที่ต้องใช้โครงสร้างพื้นฐาน/
เครื่องมือภายนอกหนัก ๆ (หรือเป็นงานวิจัยหลายพันบรรทัดต่อชิ้น) ยังไม่ถูกลงมือในเวอร์ชันนี้
จึงประกาศเป็น NOT_IMPLEMENTED พร้อมระบุ "ต้องมีอะไรถึงทำได้" เพื่อให้รายงานซื่อสัตย์
และเป็น backlog ที่ชัดเจน แต่ละหัวข้อมี hook interface รออยู่ (เพิ่มไฟล์ capability
ใหม่แล้วลงทะเบียนใน REGISTRY เมื่อพร้อม)
"""

from ..model import CapabilityResult, CapabilityStatus

_ROADMAP = [
    ("#2 Auto-Patching & Code Modernization",
     "ให้ AI แก้โค้ดยุคเก่าอัตโนมัติแล้ว re-test ในแซนด์บ็อกซ์จนผ่าน",
     "ต่อ ai_router + probe เป็นลูป patch→test; ต้องมี git apply + rollback"),
    ("#3 Polymorphic Refactoring & Signature Evasion",
     "ปรับรูปโค้ดให้ผลเหมือนเดิมแต่ลายเซ็นต่าง",
     "AST rewriter + สมมูลเชิงพฤติกรรม + ชุดวัดความต่าง"),
    ("#4 Sandbox Evasion Detection & Bypass",
     "ตรวจ/ปลดเงื่อนไข anti-sandbox ในโค้ดก่อนรัน",
     "ต่อ vuln_scan (ตรวจ) + AST patch (ปลด) เข้ากับ probe"),
    ("#6 Dark Web & Threat Intel Integration",
     "เทียบว่า repo ถูกกลุ่มใดใช้/มีเวอร์ชันแก้ไข",
     "ต่อกับ osint/ + ฟีด threat intel + คีย์ API แหล่งเฉพาะ"),
    ("#7 Target-Specific Environment Emulation",
     "จำลองสภาพแวดล้อมเป้าหมาย (OS/เวอร์ชัน/โปรแกรม) แล้วเทส",
     "ต้องมี container/VM profile + probe ที่รับ target spec"),
    ("#8 C2 Framework Weaponization (BOF/Sliver/Cobalt Strike)",
     "แปลงสคริปต์เป็นโมดูลนำเข้า C2",
     "ต้องมี toolchain ของแต่ละเฟรมเวิร์ก + สเปกฟอร์แมต BOF"),
    ("#11 Exploit Chaining Synthesizer",
     "ต่อเครื่องมือหลาย repo เป็นสายทดสอบอัตโนมัติ",
     "ต้องมีคลังผลวิเคราะห์หลาย repo + ตัววางแผนสาย (planner)"),
    ("#12 Dynamic Memory Dump & Artifact Extraction",
     "ดัมป์หน่วยความจำโปรเซสตอนรันมาวิเคราะห์",
     "ต้องมีสิทธิ์ ptrace/gcore ในแซนด์บ็อกซ์ + ตัวแยกโครงสร้าง"),
    ("#16 Distributed Swarm Architecture",
     "กระจายงานวิเคราะห์ไปหลายหน่วยบนคลาวด์หลายเจ้า",
     "ต้องมีชั้นคิวงาน/ตัวประสาน + provisioning หลายคลาวด์"),
]


def run(ctx) -> CapabilityResult:
    items = [{"capability": name, "goal": goal, "requires": req}
             for name, goal, req in _ROADMAP]
    return CapabilityResult(
        name="Roadmap (ยังไม่ลงมือ — ประกาศตรง ๆ)",
        status=CapabilityStatus.NOT_IMPLEMENTED.value,
        summary=f"อีก {len(items)} ความสามารถขั้นสูงเป็น backlog ที่มี interface รอต่อ",
        data={"roadmap": items})
