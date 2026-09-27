"""
integrity_report.py — Formatting layer for integrity_ledger.py (Tamper-Evident
Merkle Audit Ledger).

Mirrors debt_report.py's read-only reporting pattern: owns no tables, performs
no cryptography or arithmetic of its own, makes no network/LLM calls. Every
hash, size and verdict shown here was produced by integrity_ledger.py — this
module only turns that data into Thai-language, Telegram-ready text. Standard
library only, so it stays usable even if the AI provider is down.
"""

import time
from typing import List, Optional

_EVENT_TH = {
    "EVIDENCE_CREATED": "บันทึกหลักฐาน",
    "INCIDENT_CREATED": "เปิดเหตุการณ์",
    "INCIDENT_UPDATED": "อัปเดตเหตุการณ์",
    "ADMIN_ACTION": "การดำเนินการของผู้ดูแล",
    "DETECTION": "การตรวจจับ",
    "MANUAL_NOTE": "บันทึกด้วยมือ",
    "CHECKPOINT": "จุดตรวจ",
}

_DENY_TH = {
    "INVALID_EVENT_TYPE": "ชนิดเหตุการณ์ไม่ถูกต้อง",
    "PAYLOAD_TOO_LARGE": "ข้อมูลเหตุการณ์ใหญ่เกินกำหนด",
    "DB_ERROR": "เกิดข้อผิดพลาดกับฐานข้อมูล",
    "ENTRY_NOT_FOUND": "ไม่พบรายการตามลำดับที่ระบุ",
    "ENTRY_AFTER_TREE_SIZE": "รายการนี้ยังไม่ถูกครอบคลุมโดยจุดตรวจ (checkpoint) ล่าสุด",
    "INVALID_SIZES": "ช่วงขนาดที่ระบุไม่ถูกต้อง",
    "EMPTY": "ยังไม่มีรายการในสมุดตรวจสอบความถูกต้อง",
}


def deny_text(reason: str) -> str:
    return "❌ " + _DENY_TH.get(reason, reason or "ทำรายการไม่สำเร็จ")


def _event_th(event_type: str) -> str:
    return _EVENT_TH.get(event_type, event_type)


def _fmt_time(ts: Optional[int]) -> str:
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _short(h: Optional[str], n: int = 16) -> str:
    if not h:
        return "-"
    return h[:n] + "…" if len(h) > n else h


def format_status(entry_count: int, checkpoint: Optional[dict],
                  current_root: str) -> str:
    """The /integrity status card."""
    lines = [
        "🔐 สมุดตรวจสอบความถูกต้อง (Integrity Ledger)",
        "━━━━━━━━━━━━━━━━━━",
        f"จำนวนรายการทั้งหมด: {entry_count}",
        f"Merkle root ปัจจุบัน:\n  {current_root}",
    ]
    if checkpoint:
        lines += [
            "",
            f"จุดตรวจล่าสุด (checkpoint #{checkpoint['checkpoint_id']}):",
            f"  ครอบคลุม {checkpoint['tree_size']} รายการ",
            f"  root: {_short(checkpoint['merkle_root'], 24)}",
            f"  ลายเซ็น: {_short(checkpoint['signature'], 24)}",
            f"  เมื่อ: {_fmt_time(checkpoint['created_at'])}",
        ]
        if checkpoint["tree_size"] < entry_count:
            lines.append(
                f"  ⚠️ มี {entry_count - checkpoint['tree_size']} รายการใหม่หลังจุดตรวจ "
                f"— ใช้ /integrity checkpoint เพื่อผนึกเพิ่ม")
    else:
        lines += ["", "ยังไม่มีจุดตรวจ — ใช้ /integrity checkpoint เพื่อผนึกครั้งแรก"]
    lines += ["", "ตรวจความสมบูรณ์ทั้งหมดด้วย /integrity verify"]
    return "\n".join(lines)


def format_recorded(entry: dict, already: bool = False) -> str:
    tag = "🔁 มีอยู่แล้ว (idempotent)" if already else "✅ บันทึกลงสมุดแล้ว"
    return (
        f"{tag}\n"
        f"ลำดับที่ (seq): {entry['seq']}\n"
        f"ชนิด: {_event_th(entry['event_type'])}\n"
        f"entry_hash: {_short(entry['entry_hash'], 24)}\n"
        f"เชื่อมกับรายการก่อนหน้า (prev): {_short(entry['prev_hash'], 24)}"
    )


def format_checkpoint(checkpoint: dict, unchanged: bool = False) -> str:
    tag = ("ℹ️ ไม่มีรายการใหม่ตั้งแต่จุดตรวจก่อนหน้า"
           if unchanged else "✅ ผนึกจุดตรวจใหม่แล้ว")
    return (
        f"{tag}\n"
        f"checkpoint #{checkpoint['checkpoint_id']}\n"
        f"ครอบคลุม: {checkpoint['tree_size']} รายการ\n"
        f"Merkle root:\n  {checkpoint['merkle_root']}\n"
        f"ลายเซ็น (HMAC-SHA256):\n  {checkpoint['signature']}\n"
        f"เมื่อ: {_fmt_time(checkpoint['created_at'])}"
    )


def format_verify(result: dict) -> str:
    """Render verify_chain()'s structured result."""
    head = "✅ สมุดตรวจสอบความถูกต้องสมบูรณ์ (ไม่พบการแก้ไข)" if result["ok"] \
        else "🚨 พบความผิดปกติในสมุดตรวจสอบความถูกต้อง"
    lines = [
        head,
        "━━━━━━━━━━━━━━━━━━",
        f"รายการทั้งหมด: {result['entry_count']}",
        f"จุดตรวจทั้งหมด: {result['checkpoint_count']}",
        f"ห่วงโซ่แฮช (hash chain): {'ผ่าน ✓' if result['chain_ok'] else 'ล้มเหลว ✗'}",
        f"ลายเซ็นจุดตรวจ: {'ผ่าน ✓' if result['checkpoints_ok'] else 'ล้มเหลว ✗'}",
        f"ความเป็นภาคผนวกอย่างเดียว (append-only): "
        f"{'ผ่าน ✓' if result['consistency_ok'] else 'ล้มเหลว ✗'}",
        f"Merkle root ปัจจุบัน:\n  {result['current_root']}",
    ]
    if result["first_bad_seq"] is not None:
        lines.append(f"⚠️ จุดที่เสียหายจุดแรก: seq={result['first_bad_seq']}")
    if result["problems"]:
        lines.append("รายละเอียดปัญหา:")
        for p in result["problems"][:20]:
            lines.append(f"  • {p}")
    return "\n".join(lines)


def format_inclusion_proof(data: dict, verified: bool) -> str:
    lines = [
        "🧾 หลักฐานการรวมอยู่ (Merkle inclusion proof)",
        "━━━━━━━━━━━━━━━━━━",
        f"รายการลำดับที่: {data['leaf_index']}",
        f"ขนาดต้นไม้ (tree size): {data['tree_size']}",
        f"leaf hash: {_short(data['leaf_hash'], 24)}",
        f"จำนวนโหนดในเส้นทาง (audit path): {len(data['audit_path'])}",
        f"root ที่คำนวณได้: {_short(data['root'], 24)}",
        "",
        ("✅ ตรวจสอบแล้ว: รายการนี้ถูกผนึกอยู่ในต้นไม้จริง"
         if verified else "❌ ตรวจสอบไม่ผ่าน: หลักฐานไม่ตรงกับ root"),
    ]
    return "\n".join(lines)


def format_log(page_data: dict) -> str:
    items: List[dict] = page_data["items"]
    if not items:
        return "ยังไม่มีรายการในสมุดตรวจสอบความถูกต้อง"
    lines = [f"📒 สมุดตรวจสอบความถูกต้อง (หน้า {page_data['page']}/"
             f"{page_data['total_pages']}, ทั้งหมด {page_data['total_count']})",
             "━━━━━━━━━━━━━━━━━━"]
    for e in items:
        lines.append(
            f"#{e['seq']} · {_event_th(e['event_type'])} · {_fmt_time(e['created_at'])}\n"
            f"    {_short(e['entry_hash'], 20)}")
    return "\n".join(lines)


def format_checkpoints(items: List[dict]) -> str:
    if not items:
        return "ยังไม่มีจุดตรวจ — ใช้ /integrity checkpoint เพื่อผนึกครั้งแรก"
    lines = ["📌 จุดตรวจ (checkpoints)", "━━━━━━━━━━━━━━━━━━"]
    for c in items:
        lines.append(
            f"#{c['checkpoint_id']} · {c['tree_size']} รายการ · "
            f"{_fmt_time(c['created_at'])}\n    root {_short(c['merkle_root'], 20)}")
    return "\n".join(lines)
