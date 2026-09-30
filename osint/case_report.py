"""
osint.case_report — render an OSINT case for two very different audiences.

group_summary(): a REDACTED line-item summary safe to post in a shared group. It
shows only the target, the security level, and a SHA-256 digest of the sensitive
detail/risk text. SHA-256 is a one-way digest, so the group sees a stable
reference token, never the underlying detail; the full text lives only in the
stored case and is retrievable in private via /browse by an authorized admin.
The digest doubles as an integrity anchor — the same detail always hashes to the
same token, so a saved case can be tied back to what was announced.

full_report(): the complete, human-readable case for a private (DM) channel —
posture reasons, infrastructure, registration, exposure and tech stack. PII-ish
free text is passed through osint.mask_pii so even the private view does not spew
raw personal data into a chat transcript.
"""

import re
import hashlib
from typing import Any, Dict, List

# ตัวปกปิด PII แบบในตัว (ไม่พึ่ง osint.py ซึ่งถูกแพ็กเกจ osint/ บดบังอยู่ในสแนปช็อตนี้)
# ปกปิดอีเมลและเลขยาว ๆ ที่มักเป็นเบอร์โทร/เลขบัตร ในมุมมองส่วนตัวก่อนลงแชท
_EMAIL_MASK_RE = re.compile(r"([^@\s]{1,3})[^@\s]*(@[^\s]+)")
_LONGNUM_RE = re.compile(r"\b(\d{2})\d{5,}(\d{2})\b")


def _sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()


def _mask(text: str) -> str:
    """ปกปิด PII เบื้องต้น (อีเมล/เลขยาว) — self-contained ไม่พึ่งโมดูลภายนอก"""
    if not text:
        return text
    masked = _EMAIL_MASK_RE.sub(r"\1***\2", text)
    masked = _LONGNUM_RE.sub(r"\1****\2", masked)
    return masked


def _detail_text(case: Dict[str, Any]) -> str:
    """ข้อความ 'รายละเอียด' เต็ม (ก่อน hash) — สรุป profile ที่ค้นเจอ"""
    prof = case.get("profile", {})
    infra = prof.get("infrastructure", {})
    reg = prof.get("registration", {})
    parts = [f"target={case.get('target')}"]
    if infra.get("ips"):
        parts.append("ips=" + ",".join(infra["ips"][:8]))
    if infra.get("subdomains"):
        parts.append(f"subdomains={len(infra['subdomains'])}")
    if reg.get("registrar"):
        parts.append("registrar=" + reg["registrar"])
    tech = [t.get("value") for t in prof.get("technology", [])]
    if tech:
        parts.append("tech=" + ",".join(str(t) for t in tech[:8]))
    return " | ".join(parts)


def _risk_text(case: Dict[str, Any]) -> str:
    """ข้อความ 'ความเสี่ยงที่อาจเกิด' เต็ม (ก่อน hash) — เหตุผลจาก assessment"""
    a = case.get("assessment", {})
    reasons = [r.get("detail", "") for r in a.get("reasons", [])]
    exposure = case.get("profile", {}).get("exposure", {})
    if exposure.get("breach_count"):
        reasons.append(f"breaches={exposure['breach_count']}")
    return f"level={a.get('security_level')} score={a.get('score')} :: " + " ; ".join(reasons)


def group_summary(case: Dict[str, Any]) -> str:
    """สรุปแบบเข้ารหัส (SHA-256) สำหรับโพสต์ในกลุ่ม — ไม่เผยรายละเอียดจริง"""
    a = case.get("assessment", {})
    detail_hash = _sha256(_detail_text(case))
    risk_hash = _sha256(_risk_text(case))
    lines = [
        f"🤖 ผลการตรวจสอบเว็บไซต์: {case.get('target')}",
        f"ความปลอดภัย: {a.get('security_level', '-')}",
        f"รายละเอียด: {detail_hash} (Sha256)",
        f"ความเสี่ยงที่อาจเกิด: {risk_hash} (Sha256)",
        f"🆔 เคส: {case.get('case_id')}  (ดูฉบับเต็มแบบส่วนตัว: /browse {case.get('case_id')})",
    ]
    return "\n".join(lines)


def full_report(case: Dict[str, Any]) -> str:
    """รายงานฉบับเต็ม (สำหรับส่งเข้า DM ผู้มีสิทธิ์)"""
    a = case.get("assessment", {})
    prof = case.get("profile", {})
    infra = prof.get("infrastructure", {})
    reg = prof.get("registration", {})
    exposure = prof.get("exposure", {})
    tech = prof.get("technology", [])

    lines: List[str] = [
        f"🔎 OSINT Case: {case.get('case_id')}",
        f"🎯 เป้าหมาย: {case.get('target')} ({case.get('kind')})",
        f"🕐 เก็บเมื่อ: {case.get('created_at')}",
        "",
        f"🛡️ ระดับความปลอดภัย: {a.get('security_level')} "
        f"(คะแนน {a.get('score')}/100 · ความเสี่ยง {a.get('risk_level')})",
    ]
    if a.get("reasons"):
        lines.append("⚠️ เหตุผลที่หักคะแนน:")
        for r in a["reasons"][:20]:
            lines.append(f"   • {r.get('detail')} ({r.get('delta')})")
    if a.get("positives"):
        lines.append("✅ จุดที่ทำได้ดี: " + ", ".join(a["positives"][:12]))

    lines.append("")
    lines.append("🌐 โครงสร้างพื้นฐาน:")
    if infra.get("ips"):
        lines.append("   IP: " + ", ".join(infra["ips"][:12]))
    if infra.get("nameservers"):
        lines.append("   NS: " + ", ".join(infra["nameservers"][:8]))
    if infra.get("mx"):
        lines.append("   MX: " + ", ".join(infra["mx"][:8]))
    subs = infra.get("subdomains", [])
    if subs:
        lines.append(f"   ซับโดเมน ({len(subs)}): " + ", ".join(subs[:20]))
        if len(subs) > 20:
            lines.append(f"      … และอีก {len(subs) - 20} รายการ")
    if infra.get("asns"):
        lines.append("   ASN: " + ", ".join(infra["asns"][:8]))

    if reg.get("registrar") or reg.get("events"):
        lines.append("")
        lines.append("📇 การจดทะเบียน:")
        if reg.get("registrar"):
            lines.append("   Registrar: " + reg["registrar"])
        for k, v in (reg.get("events") or {}).items():
            lines.append(f"   {k}: {v}")
        if reg.get("abuse_emails"):
            lines.append("   Abuse: " + ", ".join(_mask(e) for e in reg["abuse_emails"][:5]))

    if tech:
        lines.append("")
        lines.append("🧩 เทคโนโลยีที่ตรวจพบ:")
        for t in tech[:20]:
            conf = t.get("confidence", 1)
            lines.append(f"   • {t.get('value')} (แหล่งยืนยัน {conf})")

    if exposure.get("breaches") or exposure.get("dork_hits"):
        lines.append("")
        lines.append("🕳️ การเปิดเผย/รั่วไหล:")
        for b in exposure.get("breaches", [])[:15]:
            pc = b.get("pwn_count")
            extra = f" ({pc:,} บัญชี)" if pc else ""
            lines.append(f"   • Breach: {b.get('name')}{extra}")
        for h in exposure.get("dork_hits", [])[:15]:
            lines.append(f"   • Dork: {_mask(h.get('url', ''))}")

    stats = case.get("stats", {})
    lines.append("")
    lines.append(
        f"📊 แหล่งที่รัน {stats.get('sources_run', 0)} "
        f"(สำเร็จ {stats.get('sources_ok', 0)}) · "
        f"ระเบียนรวม {stats.get('records_merged', 0)} · "
        f"ใช้เวลา {stats.get('elapsed_ms', 0)} ms")
    srcs = case.get("sources", [])
    degraded = [s for s in srcs if s.get("status") not in ("ok", "empty")]
    if degraded:
        lines.append("   แหล่งที่ไม่พร้อม: " + ", ".join(
            f"{s['source']}({s['status']})" for s in degraded))
    return "\n".join(lines)
