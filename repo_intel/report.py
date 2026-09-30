# -*- coding: utf-8 -*-
"""
repo_intel.report — ประกอบข้อความผลลัพธ์ (ธีมแฮกเกอร์เรียบง่าย ใส่อิโมจิรายหัวข้อ)

โครง: หัว (verdict) → ลายนิ้วมือ repo → 🧪 หลักฐานการรันจริง (คำสั่ง+exit code) →
🧠 คำเรียบเรียงจาก AI → ประเด็นจาก capability → เชิงอรรถความซื่อสัตย์
บังคับความยาวรวมไม่เกิน ~2000 คำ
"""

from typing import List

from .model import RepoIntelReport, ProbeKind
from .verdict import verdict_banner

_WORD_CAP = 2000
_STATUS_ICON = {"ok": "🔎", "clean": "✅", "unavailable": "🚫",
                "not_implemented": "🗺️", "error": "⚠️"}
_SEV_ICON = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "⚪"}


def _evidence_block(report: RepoIntelReport) -> List[str]:
    lines = ["🧪 หลักฐานการรันจริง (สิ่งที่รันในแซนด์บ็อกซ์):"]
    any_ran = False
    for e in report.evidence:
        cmd = " ".join(e.command) if e.command else "-"
        if e.ran:
            any_ran = True
            if e.timed_out:
                verdict = "⏱️ timeout"
            elif e.passed is True:
                verdict = "✅ ผ่าน (exit 0)"
            elif e.passed is False:
                verdict = f"❌ ล้มเหลว (exit {e.returncode})"
            else:
                verdict = "• จบการรัน"
            dur = f" ~{e.duration_seconds:.0f}s" if e.duration_seconds else ""
            lines.append(f"  ▸ [{e.kind}] `{cmd[:80]}` → {verdict}{dur}")
        else:
            lines.append(f"  ▸ [{e.kind}] ไม่ได้รัน — {e.skipped_reason or 'n/a'}")
    if not any_ran:
        lines.append("  (ไม่มีขั้นตอนใดรันได้จริงในสภาพแวดล้อมนี้)")
    return lines


def _capability_block(report: RepoIntelReport) -> List[str]:
    lines = ["🧩 ผลวิเคราะห์เชิงลึก:"]
    for c in report.capabilities:
        icon = _STATUS_ICON.get(c.status, "•")
        head = f"  {icon} {c.name}: {c.summary}"
        lines.append(head)
        for f in c.findings[:4]:
            sev = _SEV_ICON.get(f.severity, "•")
            loc = f" ({f.location})" if f.location else ""
            lines.append(f"      {sev} {f.title}{loc}")
    return lines


def render(report: RepoIntelReport) -> str:
    v = report.verdict
    banner = verdict_banner(v.status) if v else "❔ สรุปไม่ได้"
    fp = report.fingerprint

    head = [
        "👾 รายงานวิเคราะห์ Repository",
        f"📦 {report.repo}",
        f"🎯 สถานะ: {banner}",
    ]
    if v and v.reasons:
        head.append("   เหตุผล: " + " | ".join(v.reasons[:3]))

    fp_line = [
        "🧬 ลายนิ้วมือ: "
        + f"{fp.primary_language or 'ไม่ทราบภาษา'} · "
        + f"{fp.total_files} ไฟล์ · "
        + (f"pm: {', '.join(fp.package_managers)}" if fp.package_managers else "ไม่มี manifest")
    ]
    if fp.entrypoints:
        fp_line.append("   ▸ entrypoint: " + ", ".join(fp.entrypoints[:4]))
    if fp.test_runner:
        fp_line.append(f"   ▸ test runner: {fp.test_runner}")

    body = ["", "🧠 สรุปโดย AI:" + (f" (via {report.ai_provider})" if report.ai_provider else ""),
            report.ai_summary or "(ไม่มีสรุป)"]

    evidence = [""] + _evidence_block(report)
    caps = [""] + _capability_block(report)

    footer = [
        "",
        "🔒 หมายเหตุความซื่อสัตย์:",
    ]
    if v and v.tested:
        footer.append("   • คำตัดสินอ้างอิงจากการรันจริงในแซนด์บ็อกซ์ (ดูบล็อกหลักฐาน)")
    else:
        footer.append("   • ยังไม่ได้รันเทสจริง — สถานะจึงเป็น 'ยังไม่ได้เทส' ไม่ใช่ 'ผ่าน/ไม่ผ่าน'")
    footer.append("   • การวิเคราะห์เชิงลึกบางส่วนเป็นสถิต (ไม่รันโค้ด) และบางความสามารถเป็น roadmap")

    sections = head + [""] + fp_line + body + evidence + caps + footer
    text = "\n".join(sections)
    return _clamp(text)


def _clamp(text: str) -> str:
    words = text.split()
    if len(words) <= _WORD_CAP:
        return text
    return " ".join(words[:_WORD_CAP]) + "\n… [ตัดให้อยู่ในขีดจำกัด ~2000 คำ]"
