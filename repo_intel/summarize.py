# -*- coding: utf-8 -*-
"""
repo_intel.summarize — ให้ AI "เรียบเรียง" ผลวิเคราะห์เป็นภาษาคนเข้าใจง่าย

AI ทำหน้าที่เดียว: อธิบายข้อเท็จจริงที่ให้ไปให้อ่านง่าย ไม่วิชาการเกิน ห้าม:
  - แต่ง/เดาข้อมูลที่ไม่มีในชุดข้อเท็จจริง
  - เปลี่ยนคำตัดสิน (verdict) — คำตัดสินถูกคำนวณจากผลรันจริงมาแล้ว
  - บอกว่า "เทสแล้ว" ถ้า verdict.tested เป็น false
ถ้าไม่มีผู้ให้บริการ AI → ใช้สรุปแบบเทมเพลตจากข้อเท็จจริง (ยังซื่อสัตย์เหมือนกัน)
"""

import json
import logging
from typing import Tuple

import ai_router

logger = logging.getLogger("modbot.repo_intel.summarize")

_MAX_WORDS = 1500   # เผื่อส่วนหัว/หลักฐานให้รวมทั้งข้อความไม่เกิน ~2000 คำ

_SYSTEM = (
    "คุณคือผู้ช่วยวิเคราะห์โค้ดของแล็บ red team ที่ซื่อสัตย์ที่สุด งานของคุณคือ"
    "'เรียบเรียง' ผลวิเคราะห์ repository ที่ให้มาเป็นภาษาไทยที่คนทั่วไปอ่านเข้าใจ "
    "ไม่วิชาการจนเกินไป กระชับ ตรงประเด็น\n"
    "กฎเหล็ก (ห้ามฝ่าฝืน):\n"
    "1) ใช้เฉพาะข้อเท็จจริงใน JSON ที่ให้มา ห้ามแต่งหรือเดาสิ่งที่ไม่มี\n"
    "2) ห้ามเปลี่ยนคำตัดสิน (verdict) — มันคำนวณจากผลรันจริงมาแล้ว อธิบายมันเฉย ๆ\n"
    "3) ถ้า verdict.tested=false ห้ามพูดว่า 'ทดสอบแล้ว/รันผ่าน' เด็ดขาด ให้บอกตามจริงว่า"
    "ยังไม่ได้รันเทสและเพราะอะไร\n"
    "4) ถ้ามี error จากการรันจริง ให้อธิบายว่าพังตรงไหนตามหลักฐาน ห้ามบอกว่าผ่าน\n"
    "อธิบายเป็นหัวข้อ: repo นี้ทำอะไร/ทำงานยังไง, ผลการทดสอบจริง, ประเด็นความปลอดภัย"
    "ที่พบ, และสรุปว่าปัจจุบันใช้งานได้แค่ไหน ความยาวไม่เกิน 1500 คำ"
)


def _clamp_words(text: str, limit: int = _MAX_WORDS) -> str:
    words = text.split()
    if len(words) <= limit:
        return text
    return " ".join(words[:limit]) + " …"


async def summarize(facts: dict) -> Tuple[str, str]:
    """คืน (ข้อความสรุป, ชื่อผู้ให้บริการ) — งานหนัก (เขียนเชิงวิเคราะห์) → task=heavy"""
    payload = json.dumps(facts, ensure_ascii=False, indent=2)
    prompt = ("นี่คือชุดข้อเท็จจริงจากการวิเคราะห์+ทดสอบ repository จริง "
              "(JSON) ช่วยเรียบเรียงตามกฎที่กำหนด:\n\n" + payload)
    if not ai_router.router_configured():
        return _fallback(facts), "template"
    result = await ai_router.route(prompt, system=_SYSTEM, task=ai_router.HEAVY,
                                   temperature=0.2)
    if not result.ok or not result.text.strip():
        logger.info("repo_intel summarize | router ล้มเหลว (%s) — ใช้เทมเพลต", result.reason)
        return _fallback(facts), "template"
    return _clamp_words(result.text.strip()), f"{result.provider}/{result.model}"


def _fallback(facts: dict) -> str:
    """สรุปแบบเทมเพลตจากข้อเท็จจริง — ใช้เมื่อไม่มี AI ยังต้องซื่อสัตย์เท่าเดิม"""
    fp = facts.get("fingerprint", {})
    v = facts.get("verdict") or {}
    lines = []
    lang = fp.get("primary_language") or "ไม่ทราบภาษา"
    pms = ", ".join(fp.get("package_managers", [])) or "-"
    lines.append(f"repo นี้เป็นโปรเจกต์ {lang} (ตัวจัดการแพ็กเกจ: {pms}) "
                 f"มีไฟล์ราว {fp.get('total_files', 0)} ไฟล์")
    if fp.get("entrypoints"):
        lines.append("จุดเริ่มรันที่พบ: " + ", ".join(fp["entrypoints"][:5]))
    tested = v.get("tested")
    if tested:
        lines.append("ผลการทดสอบจริง: " + "; ".join(v.get("reasons", [])))
    else:
        lines.append("ยังไม่ได้รันเทส: " + "; ".join(v.get("reasons", []))
                     + " (จึงยังยืนยันไม่ได้ว่าใช้งานได้จริงหรือไม่)")
    caps = facts.get("capabilities", [])
    hot = [c for c in caps if c.get("findings")]
    if hot:
        lines.append("ประเด็นที่ตรวจพบ:")
        for c in hot[:4]:
            lines.append(f"  - {c['name']}: {c.get('summary','')}")
    return "\n".join(lines)
