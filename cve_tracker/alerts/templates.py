"""
cve_tracker.alerts.templates — the Thai message section builders.

Pure functions that turn a record (+ optional AI summary) into individual Thai
lines/sections, all HTML-escaped for ``ParseMode.HTML`` (the mode news.py uses).
The :mod:`formatter` assembles and splits them. Keeping each section a small
function makes the layout configurable (rule §14 'formatter must be
configurable') and unit-testable without a live bot.

Every value routes through :func:`esc`; unknown facts render as the shared
'ไม่พบข้อมูล' constant so AI output and deterministic output read identically.
"""

from __future__ import annotations

from typing import List, Optional

from ..constants import EMOJI, SEVERITY_EMOJI, TH_UNKNOWN
from ..models import AISummary, CVERecord
from ..utils import escape_html as esc, thai_date, truncate
from ..enrichment.cwe import format_cwe_label
from ..enrichment.cpe import format_product_label
from ..enrichment.exploit_status import exploit_line_thai
from ..enrichment.kev import kev_badge_thai
from ..intelligence.exposure import assess
from ..intelligence.prioritization import priority_label_thai


def severity_emoji(severity: str) -> str:
    return SEVERITY_EMOJI.get((severity or "UNKNOWN").upper(), EMOJI["unknown"])


def header(record: CVERecord, *, is_update: bool = False) -> str:
    if is_update:
        return f"{EMOJI['updated']} <b>CVE มีการอัปเดต: {esc(record.cve_id)}</b>"
    emoji = severity_emoji(record.severity)
    return f"{EMOJI['new']} <b>พบ CVE ใหม่: {esc(record.cve_id)}</b> {emoji}"


def title_line(record: CVERecord, ai: Optional[AISummary]) -> str:
    title = ""
    if ai and ai.title_th:
        title = ai.title_th
    title = title or record.title or record.cve_id
    return f"<b>{esc(truncate(title, 160))}</b>"


def id_line(record: CVERecord) -> str:
    return f"{EMOJI['id']} <b>CVE ID:</b> {esc(record.cve_id)}"


def published_line(record: CVERecord) -> str:
    d = thai_date(record.published_at) or TH_UNKNOWN
    return f"{EMOJI['published']} <b>เผยแพร่:</b> {esc(d)}"


def severity_line(record: CVERecord) -> str:
    sev = record.severity if record.severity and record.severity != "UNKNOWN" else TH_UNKNOWN
    emoji = severity_emoji(record.severity)
    if record.cvss_score is not None:
        ver = f" v{record.cvss_version}" if record.cvss_version else ""
        return (f"{EMOJI['severity']} <b>ระดับความรุนแรง:</b> {emoji} {esc(sev)} "
                f"— CVSS{esc(ver)} {record.cvss_score}")
    return f"{EMOJI['severity']} <b>ระดับความรุนแรง:</b> {emoji} {esc(sev)}"


def cvss_conflict_line(record: CVERecord) -> Optional[str]:
    """When sources disagree on the score, show each explicitly (rule §56)."""
    scored = [(s.source or "?", s.base_score, s.version)
              for s in record.cvss_scores if s.base_score is not None]
    distinct = {round(sc, 1) for _, sc, _ in scored}
    if len(distinct) <= 1 or len(scored) <= 1:
        return None
    parts = ", ".join(f"{esc(src)}: {sc} (v{ver})" for src, sc, ver in scored)
    return f"⚖️ <b>คะแนนต่างแหล่ง:</b> {parts}"


def cwe_line(record: CVERecord) -> Optional[str]:
    if not record.cwe_ids:
        return None
    labels = [esc(format_cwe_label(c)) for c in record.cwe_ids[:3]]
    return f"{EMOJI['cwe']} <b>CWE:</b> " + ", ".join(labels)


def vendor_line(record: CVERecord) -> Optional[str]:
    if not record.vendors:
        return None
    return f"{EMOJI['vendor']} <b>ผู้ผลิต:</b> " + esc(", ".join(record.vendors[:4]))


def product_line(record: CVERecord) -> Optional[str]:
    if not record.products:
        return None
    from ..enrichment.products import top_products
    labels = [esc(format_product_label(p)) for p in top_products(record.products, 4)]
    return f"{EMOJI['product']} <b>ผลิตภัณฑ์:</b> " + "; ".join(labels)


def kev_line(record: CVERecord) -> str:
    if record.in_kev:
        return f"{EMOJI['kev']} <b>{esc(kev_badge_thai(record))}</b>"
    return f"{EMOJI['kev']} CISA KEV: NO"


def exploit_line(record: CVERecord) -> str:
    return f"{EMOJI['exploit']} <b>Public Exploit / PoC:</b> {esc(exploit_line_thai(record))}"


def exposure_line(record: CVERecord) -> Optional[str]:
    prof = assess(record)
    if not prof.summary_th or prof.summary_th == "ไม่ระบุ":
        return None
    return f"{EMOJI['vector']} <b>ช่องทางการโจมตี:</b> {esc(prof.summary_th)}"


def epss_line(record: CVERecord) -> Optional[str]:
    from ..enrichment.epss import epss_line_thai
    text = epss_line_thai(record)
    if not text:
        return None
    return f"🔮 <b>EPSS:</b> {esc(text)}"


def priority_line(record: CVERecord) -> str:
    return f"{EMOJI['priority']} <b>ลำดับความสำคัญภายใน:</b> {esc(priority_label_thai(record))}"


def summary_block(record: CVERecord, ai: Optional[AISummary]) -> str:
    body = ""
    if ai and ai.summary_th:
        body = ai.summary_th
    else:
        body = record.description or TH_UNKNOWN
    tag = f" {EMOJI['ai']}" if (ai and ai.validated and not ai.fallback_used) else ""
    return f"{EMOJI['summary']} <b>สรุป{tag}:</b>\n{esc(truncate(body, 1200))}"


def impact_block(ai: Optional[AISummary]) -> Optional[str]:
    if ai and ai.impact_th:
        return f"{EMOJI['impact']} <b>ผลกระทบ:</b>\n{esc(truncate(ai.impact_th, 600))}"
    return None


def recommendation_block(ai: Optional[AISummary]) -> Optional[str]:
    if not ai or not ai.recommendation_th:
        return None
    items = [ln.strip() for ln in ai.recommendation_th.split("\n") if ln.strip()]
    if not items:
        return None
    bullets = "\n".join(f"• {esc(i)}" for i in items[:6])
    return f"{EMOJI['recommendation']} <b>แนวทางเบื้องต้น:</b>\n{bullets}"


def references_block(record: CVERecord, *, limit: int = 4) -> Optional[str]:
    if not record.references:
        return None
    lines = []
    for ref in record.references[:limit]:
        label = ref.ref_type.replace("_", " ")
        lines.append(f"• [{esc(label)}] {esc(ref.url)}")
    extra = len(record.references) - limit
    block = f"{EMOJI['references']} <b>References:</b>\n" + "\n".join(lines)
    if extra > 0:
        block += f"\n… และอีก {extra} รายการ"
    return block


def footer(ai: Optional[AISummary]) -> str:
    if ai and ai.validated and not ai.fallback_used:
        src = f" ({esc(ai.provider)})" if ai.provider else ""
        return f"{EMOJI['ai']} สรุปโดย AI{src}"
    return "ℹ️ สรุปจากข้อมูลที่ตรวจสอบ (AI ไม่พร้อมใช้งาน — แสดงข้อมูลข้อเท็จจริง)"


def change_block(change_set) -> Optional[str]:
    """For update alerts: render what changed (rule §39)."""
    if change_set is None or not change_set.changes:
        return None
    lines = []
    label = {
        "cvss": "CVSS", "severity": "ระดับความรุนแรง", "kev_status": "สถานะ CISA KEV",
        "exploit_status": "สถานะ exploit", "references": "References",
        "description": "คำอธิบาย", "cwe": "CWE", "products": "ผลิตภัณฑ์", "title": "ชื่อ",
    }
    for c in change_set.changes[:6]:
        name = label.get(c.kind, c.kind)
        note = c.note or (f"{c.before} → {c.after}")
        lines.append(f"• {esc(name)}: {esc(str(note))}")
    return f"{EMOJI['updated']} <b>การเปลี่ยนแปลง:</b>\n" + "\n".join(lines)
