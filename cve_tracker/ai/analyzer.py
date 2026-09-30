"""
cve_tracker.ai.analyzer — deterministic, fact-derived analysis (no LLM).

This is the non-AI counterpart to the summarizer: it derives the recommendation
bullets and impact sentence purely from the structured facts. It serves two
roles — it seeds the deterministic fallback (rule §16, so the bot still publishes
useful guidance when AI is down), and it provides a baseline the AI's own
recommendations are merged with, so sensible standard actions (check inventory,
watch for a vendor patch) are never missing.

Everything here is generic defensive hygiene phrased in Thai; it makes no claim
that isn't supported by the facts.
"""

from __future__ import annotations

from typing import List

from ..enums import ExploitMaturity
from ..models import CVERecord
from ..intelligence.exposure import assess


def recommendations(record: CVERecord) -> List[str]:
    """Standard blue-team actions tailored to the record's facts."""
    recs: List[str] = []

    if record.products:
        vendor = record.vendors[0] if record.vendors else ""
        product = record.product_names[0] if record.product_names else "ผลิตภัณฑ์ที่เกี่ยวข้อง"
        who = f"{vendor} {product}".strip()
        recs.append(f"ตรวจสอบว่ามี {who} อยู่ในระบบหรือไม่ และเวอร์ชันใด")
    else:
        recs.append("ตรวจสอบว่ามีผลิตภัณฑ์ที่เกี่ยวข้องอยู่ในระบบหรือไม่")

    recs.append("ตรวจสอบเวอร์ชัน/แพตช์ปัจจุบันเทียบกับข้อมูลช่องโหว่")

    if record.in_kev:
        recs.append("⚠️ อยู่ใน CISA KEV — ควรเร่งแก้ไขตามกำหนดและติดตามคำแนะนำของ CISA")
        if record.kev.required_action:
            recs.append(f"การดำเนินการที่ CISA แนะนำ: {record.kev.required_action}")

    exposure = assess(record)
    if exposure.network_reachable:
        recs.append("จำกัดการเข้าถึงอุปกรณ์/บริการนี้จากเครือข่ายที่ไม่จำเป็น (network segmentation)")

    if record.exploit_maturity in (ExploitMaturity.CONFIRMED.value, ExploitMaturity.PUBLIC_POC.value):
        recs.append("มีการอ้างอิงถึง exploit/PoC สาธารณะ — เพิ่มการเฝ้าระวังและ log monitoring")

    recs.append("ติดตามคำแนะนำ/แพตช์อย่างเป็นทางการจากผู้ผลิต")

    # de-duplicate while preserving order, cap at 6
    seen = set()
    out = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out[:6]


def impact_sentence(record: CVERecord) -> str:
    """A single deterministic impact sentence from the CVSS impact metrics."""
    from ..enrichment.cvss import pick_primary
    primary = pick_primary(record.cvss_scores)
    if primary is None:
        return "ยังไม่มีข้อมูล CVSS เพียงพอที่จะประเมินผลกระทบโดยละเอียด"
    impacts = []
    if primary.confidentiality in ("High", "Low"):
        impacts.append("ความลับของข้อมูล")
    if primary.integrity in ("High", "Low"):
        impacts.append("ความถูกต้องของข้อมูล/ระบบ")
    if primary.availability in ("High", "Low"):
        impacts.append("ความพร้อมใช้งานของระบบ")
    if not impacts:
        return "ผลกระทบขึ้นอยู่กับสภาพแวดล้อมการใช้งาน โปรดดูรายละเอียดจากแหล่งอ้างอิง"
    return "หากถูกโจมตีสำเร็จ อาจกระทบต่อ " + " และ ".join(impacts)


def title_fallback(record: CVERecord) -> str:
    """A deterministic Thai-ish title when AI is unavailable: keep the original
    title (often English product+weakness), which is factual."""
    return record.title or record.cve_id


def merge_recommendations(ai_recs: List[str], record: CVERecord) -> List[str]:
    """Combine AI recommendations with the deterministic baseline, keeping AI's
    first, then adding any baseline action not already covered."""
    base = recommendations(record)
    out = list(ai_recs or [])
    have = " ".join(out).lower()
    for b in base:
        # add a baseline item only if its core keyword isn't already present
        key = b.split()[0].lower()
        if key not in have:
            out.append(b)
    return out[:6]
