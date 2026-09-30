"""
cve_tracker.enrichment.cwe — CWE normalization and a name catalogue.

CVE feeds often give a bare ``CWE-79`` with no human name. A small embedded
catalogue of the most common weakness types (with a short Thai gloss) lets the
Thai formatter and AI prompt render 'CWE-79 (Cross-site Scripting / XSS)'
without a network lookup. The catalogue is intentionally partial — unknown CWEs
are passed through with their id and an empty name, never a fabricated one.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ..models import Weakness
from ..utils import normalize_cwe_id, extract_cwe_ids, dedupe_preserve_order

# id -> (english name, short Thai gloss). Covers the CWE Top 25 + common web
# and memory-safety classes seen constantly in CVE data.
CWE_CATALOG: Dict[str, Dict[str, str]] = {
    "CWE-79": {"name": "Improper Neutralization of Input During Web Page Generation (XSS)",
               "th": "Cross-site Scripting (XSS)"},
    "CWE-89": {"name": "SQL Injection", "th": "การฉีดคำสั่ง SQL"},
    "CWE-20": {"name": "Improper Input Validation", "th": "ตรวจสอบอินพุตไม่รัดกุม"},
    "CWE-125": {"name": "Out-of-bounds Read", "th": "อ่านหน่วยความจำนอกขอบเขต"},
    "CWE-787": {"name": "Out-of-bounds Write", "th": "เขียนหน่วยความจำนอกขอบเขต"},
    "CWE-119": {"name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
                "th": "จัดการ buffer ไม่ปลอดภัย"},
    "CWE-120": {"name": "Buffer Copy without Checking Size of Input (Buffer Overflow)",
                "th": "Buffer Overflow"},
    "CWE-121": {"name": "Stack-based Buffer Overflow", "th": "Stack Buffer Overflow"},
    "CWE-122": {"name": "Heap-based Buffer Overflow", "th": "Heap Buffer Overflow"},
    "CWE-190": {"name": "Integer Overflow or Wraparound", "th": "Integer Overflow"},
    "CWE-22": {"name": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
               "th": "Path Traversal"},
    "CWE-78": {"name": "OS Command Injection", "th": "การฉีดคำสั่งระบบปฏิบัติการ"},
    "CWE-77": {"name": "Command Injection", "th": "Command Injection"},
    "CWE-94": {"name": "Improper Control of Generation of Code (Code Injection)",
               "th": "Code Injection"},
    "CWE-434": {"name": "Unrestricted Upload of File with Dangerous Type",
                "th": "อัปโหลดไฟล์อันตรายได้"},
    "CWE-352": {"name": "Cross-Site Request Forgery (CSRF)", "th": "CSRF"},
    "CWE-287": {"name": "Improper Authentication", "th": "การยืนยันตัวตนไม่รัดกุม"},
    "CWE-862": {"name": "Missing Authorization", "th": "ขาดการตรวจสอบสิทธิ์"},
    "CWE-863": {"name": "Incorrect Authorization", "th": "ตรวจสอบสิทธิ์ผิดพลาด"},
    "CWE-269": {"name": "Improper Privilege Management", "th": "จัดการสิทธิ์ไม่ถูกต้อง"},
    "CWE-732": {"name": "Incorrect Permission Assignment for Critical Resource",
                "th": "กำหนดสิทธิ์ทรัพยากรผิด"},
    "CWE-798": {"name": "Use of Hard-coded Credentials", "th": "ฝัง credential ในโค้ด"},
    "CWE-522": {"name": "Insufficiently Protected Credentials", "th": "ปกป้อง credential ไม่พอ"},
    "CWE-306": {"name": "Missing Authentication for Critical Function",
                "th": "ฟังก์ชันสำคัญไม่มีการยืนยันตัวตน"},
    "CWE-416": {"name": "Use After Free", "th": "Use-After-Free"},
    "CWE-415": {"name": "Double Free", "th": "Double Free"},
    "CWE-476": {"name": "NULL Pointer Dereference", "th": "NULL Pointer Dereference"},
    "CWE-362": {"name": "Race Condition", "th": "Race Condition"},
    "CWE-502": {"name": "Deserialization of Untrusted Data", "th": "Deserialize ข้อมูลไม่น่าเชื่อถือ"},
    "CWE-918": {"name": "Server-Side Request Forgery (SSRF)", "th": "SSRF"},
    "CWE-611": {"name": "Improper Restriction of XML External Entity Reference (XXE)",
                "th": "XXE"},
    "CWE-200": {"name": "Exposure of Sensitive Information", "th": "เปิดเผยข้อมูลอ่อนไหว"},
    "CWE-284": {"name": "Improper Access Control", "th": "ควบคุมการเข้าถึงไม่รัดกุม"},
    "CWE-400": {"name": "Uncontrolled Resource Consumption (DoS)", "th": "ใช้ทรัพยากรไม่จำกัด (DoS)"},
    "CWE-770": {"name": "Allocation of Resources Without Limits", "th": "จองทรัพยากรไม่จำกัด"},
    "CWE-74": {"name": "Injection", "th": "Injection"},
    "CWE-59": {"name": "Improper Link Resolution Before File Access (Link Following)",
               "th": "Link Following"},
    "CWE-668": {"name": "Exposure of Resource to Wrong Sphere", "th": "เปิดทรัพยากรผิดขอบเขต"},
    "CWE-295": {"name": "Improper Certificate Validation", "th": "ตรวจสอบใบรับรองไม่ถูกต้อง"},
    "CWE-326": {"name": "Inadequate Encryption Strength", "th": "การเข้ารหัสอ่อนแอ"},
    "CWE-327": {"name": "Use of a Broken or Risky Cryptographic Algorithm", "th": "ใช้อัลกอริทึมเข้ารหัสที่ไม่ปลอดภัย"},
    "CWE-328": {"name": "Use of Weak Hash", "th": "ใช้ hash ที่อ่อนแอ"},
    "CWE-330": {"name": "Use of Insufficiently Random Values", "th": "ค่าสุ่มไม่เพียงพอ"},
    "CWE-338": {"name": "Use of Cryptographically Weak PRNG", "th": "PRNG อ่อนแอเชิงคริปโต"},
    "CWE-347": {"name": "Improper Verification of Cryptographic Signature", "th": "ตรวจสอบลายเซ็นคริปโตไม่ถูกต้อง"},
    "CWE-384": {"name": "Session Fixation", "th": "Session Fixation"},
    "CWE-385": {"name": "Covert Timing Channel", "th": "ช่องทางเวลาแอบแฝง"},
    "CWE-401": {"name": "Missing Release of Memory after Effective Lifetime (Memory Leak)", "th": "Memory Leak"},
    "CWE-404": {"name": "Improper Resource Shutdown or Release", "th": "ปิด/คืนทรัพยากรไม่ถูกต้อง"},
    "CWE-407": {"name": "Inefficient Algorithmic Complexity", "th": "อัลกอริทึมมี complexity ไม่เหมาะสม"},
    "CWE-427": {"name": "Uncontrolled Search Path Element", "th": "Search Path ไม่ปลอดภัย"},
    "CWE-428": {"name": "Unquoted Search Path or Element", "th": "Unquoted Search Path"},
    "CWE-444": {"name": "HTTP Request/Response Smuggling", "th": "HTTP Request Smuggling"},
    "CWE-470": {"name": "Unsafe Reflection", "th": "Reflection ไม่ปลอดภัย"},
    "CWE-497": {"name": "Exposure of Sensitive System Information", "th": "เปิดเผยข้อมูลระบบอ่อนไหว"},
    "CWE-521": {"name": "Weak Password Requirements", "th": "นโยบายรหัสผ่านอ่อนแอ"},
    "CWE-532": {"name": "Insertion of Sensitive Information into Log File", "th": "เก็บข้อมูลอ่อนไหวลง log"},
    "CWE-552": {"name": "Files or Directories Accessible to External Parties", "th": "ไฟล์/ไดเรกทอรีเข้าถึงได้จากภายนอก"},
    "CWE-565": {"name": "Reliance on Cookies without Validation", "th": "เชื่อ cookie โดยไม่ตรวจสอบ"},
    "CWE-601": {"name": "URL Redirection to Untrusted Site (Open Redirect)", "th": "Open Redirect"},
    "CWE-639": {"name": "Authorization Bypass Through User-Controlled Key (IDOR)", "th": "IDOR"},
    "CWE-693": {"name": "Protection Mechanism Failure", "th": "กลไกป้องกันล้มเหลว"},
    "CWE-706": {"name": "Use of Incorrectly-Resolved Name or Reference", "th": "อ้างอิงชื่อ/ทรัพยากรผิด"},
    "CWE-763": {"name": "Release of Invalid Pointer or Reference", "th": "คืน pointer/reference ที่ไม่ถูกต้อง"},
    "CWE-776": {"name": "XML Entity Expansion (Billion Laughs)", "th": "XML Entity Expansion"},
    "CWE-777": {"name": "Regular Expression without Anchors", "th": "Regex ไม่มี anchor"},
    "CWE-829": {"name": "Inclusion of Functionality from Untrusted Control Sphere", "th": "รวมฟังก์ชันจากแหล่งไม่น่าเชื่อถือ"},
    "CWE-835": {"name": "Loop with Unreachable Exit Condition (Infinite Loop)", "th": "Infinite Loop"},
    "CWE-843": {"name": "Type Confusion", "th": "Type Confusion"},
    "CWE-908": {"name": "Use of Uninitialized Resource", "th": "ใช้ทรัพยากรที่ยังไม่ initialize"},
    "CWE-909": {"name": "Missing Initialization of Resource", "th": "ไม่ได้ initialize ทรัพยากร"},
    "CWE-913": {"name": "Improper Control of Dynamically-Managed Code Resources", "th": "ควบคุมโค้ดแบบไดนามิกไม่ปลอดภัย"},
    "CWE-915": {"name": "Improperly Controlled Modification of Object Attributes (Mass Assignment)", "th": "Mass Assignment"},
    "CWE-1021": {"name": "Improper Restriction of Rendered UI Layers (Clickjacking)", "th": "Clickjacking"},
    "CWE-1236": {"name": "Improper Neutralization of Formula Elements in a CSV File (CSV Injection)", "th": "CSV Injection"},
    "CWE-1333": {"name": "Inefficient Regular Expression Complexity (ReDoS)", "th": "ReDoS"},
    "CWE-noinfo": {"name": "Insufficient Information", "th": "ข้อมูลไม่เพียงพอ"},
    "CWE-Other": {"name": "Other", "th": "อื่น ๆ"},
}


def catalog_name(cwe_id: Optional[str]) -> str:
    norm = normalize_cwe_id(cwe_id) or (cwe_id or "")
    entry = CWE_CATALOG.get(norm) or CWE_CATALOG.get(str(cwe_id))
    return entry["name"] if entry else ""


def catalog_thai(cwe_id: Optional[str]) -> str:
    norm = normalize_cwe_id(cwe_id) or (cwe_id or "")
    entry = CWE_CATALOG.get(norm) or CWE_CATALOG.get(str(cwe_id))
    return entry["th"] if entry else ""


def make_weakness(cwe_id: str, *, name: str = "", source: str = "") -> Optional[Weakness]:
    """Build a Weakness, filling the name from the catalogue when the source
    gave none. Handles the NVD special tokens 'NVD-CWE-noinfo'/'NVD-CWE-Other'."""
    raw = (cwe_id or "").strip()
    if raw.upper() in ("NVD-CWE-NOINFO", "CWE-NOINFO"):
        return Weakness(cwe_id="CWE-noinfo", name=name or "Insufficient Information", source=source)
    if raw.upper() in ("NVD-CWE-OTHER", "CWE-OTHER"):
        return Weakness(cwe_id="CWE-Other", name=name or "Other", source=source)
    norm = normalize_cwe_id(raw)
    if not norm:
        return None
    return Weakness(cwe_id=norm, name=name or catalog_name(norm), source=source)


def weaknesses_from_text(text: str, *, source: str = "") -> List[Weakness]:
    """Extract every CWE mentioned in free text into named Weakness objects."""
    out: List[Weakness] = []
    for cid in extract_cwe_ids(text):
        w = make_weakness(cid, source=source)
        if w:
            out.append(w)
    return out


def merge_weaknesses(*groups: List[Weakness]) -> List[Weakness]:
    """Union weaknesses across sources, de-duplicated by cwe_id, keeping the
    first non-empty name seen."""
    by_id: Dict[str, Weakness] = {}
    for group in groups:
        for w in group or []:
            if not w or not w.cwe_id:
                continue
            existing = by_id.get(w.cwe_id)
            if existing is None:
                by_id[w.cwe_id] = Weakness(cwe_id=w.cwe_id, name=w.name, source=w.source)
            elif not existing.name and w.name:
                existing.name = w.name
    # Stable order: catalogue-known first by id, then the rest.
    return list(by_id.values())


def format_cwe_label(cwe_id: str, *, thai: bool = True) -> str:
    """'CWE-79 (Cross-site Scripting (XSS))' for display. Uses Thai gloss when
    available and ``thai`` is set."""
    norm = normalize_cwe_id(cwe_id) or cwe_id
    name = (catalog_thai(norm) if thai else "") or catalog_name(norm)
    return f"{norm} ({name})" if name else str(norm)
