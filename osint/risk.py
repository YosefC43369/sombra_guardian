"""
osint.risk — explainable web-security posture scoring from passive signals.

This turns the ``site_tech`` fingerprint (plus any breach signal) into a single
posture score and a Thai security level — สูงมาก / สูง / ปานกลาง / ต่ำ — with a
list of the concrete reasons behind it. The scoring is a transparent point
model, never a black box: the repository's stated principle is "report facts and
how many signals agree", so every deduction is named and attributable. This is a
*posture estimate from public data*, explicitly NOT an assertion that the target
is exploitable — it never probes, fuzzes, or attempts access.

Level semantics: the level describes SECURITY (higher = safer). ``risk_level`` is
its inverse for callers who prefer to phrase the finding as risk.
"""

import re
from typing import Any, Dict, List, Optional

# น้ำหนักการหักคะแนนเมื่อ "ไม่มี" security header แต่ละตัว
_HEADER_PENALTY = {
    "HSTS": 12,
    "CSP": 12,
    "X-Frame-Options": 6,
    "X-Content-Type-Options": 5,
    "Referrer-Policy": 4,
    "Permissions-Policy": 4,
}

# เวอร์ชัน "ต่ำกว่านี้ถือว่าเก่า/เสี่ยง" สำหรับผลิตภัณฑ์ยอดนิยม (heuristic เชิงอนุรักษ์)
_MIN_SAFE_MAJOR = {
    "WordPress": (6, 0),
    "jQuery": (3, 0),
    "Bootstrap": (4, 0),
    "PHP": (8, 0),
    "Apache": (2, 4),
    "nginx": (1, 20),
    "OpenSSL": (1, 1),
}

_VER_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")

LEVEL_VERY_HIGH = "สูงมาก"
LEVEL_HIGH = "สูง"
LEVEL_MEDIUM = "ปานกลาง"
LEVEL_LOW = "ต่ำ"


def _parse_version(value: Optional[str]):
    if not value:
        return None
    m = _VER_RE.search(value)
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2) or 0)
    return (major, minor)


def _is_outdated(product: str, version: Optional[str]) -> bool:
    floor = _MIN_SAFE_MAJOR.get(product)
    parsed = _parse_version(version)
    if not floor or not parsed:
        return False
    return parsed < floor


def _security_level(score: int) -> str:
    if score >= 85:
        return LEVEL_VERY_HIGH
    if score >= 70:
        return LEVEL_HIGH
    if score >= 50:
        return LEVEL_MEDIUM
    return LEVEL_LOW


def _risk_from_security(level: str) -> str:
    return {LEVEL_VERY_HIGH: LEVEL_LOW, LEVEL_HIGH: LEVEL_MEDIUM,
            LEVEL_MEDIUM: LEVEL_HIGH, LEVEL_LOW: LEVEL_VERY_HIGH}[level]


def assess(site_meta: Dict[str, Any], tech_records: List[Dict[str, Any]],
           breach_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """ประเมิน posture จาก meta ของ site_tech + ระเบียน tech + (ถ้ามี) breach

    คืน dict:
      {score, security_level, risk_level, reasons:[{code,detail,delta}], positives:[...]}
    """
    score = 100
    reasons: List[Dict[str, Any]] = []
    positives: List[str] = []

    def deduct(code: str, detail: str, delta: int):
        nonlocal score
        score -= delta
        reasons.append({"code": code, "detail": detail, "delta": -delta})

    site_meta = site_meta or {}

    # (1) HTTPS
    if site_meta.get("https") is False:
        deduct("no_https", "เว็บไซต์ไม่บังคับ HTTPS (เสี่ยงดักฟัง/แก้ไขข้อมูลกลางทาง)", 30)
    elif site_meta.get("https") is True:
        positives.append("บังคับ HTTPS")

    # (2) security headers ที่ขาด
    for label in site_meta.get("security_headers_missing", []) or []:
        deduct("missing_header", f"ขาด HTTP security header: {label}",
               _HEADER_PENALTY.get(label, 4))
    for label in site_meta.get("security_headers_present", []) or []:
        positives.append(f"มี {label}")

    # (3) การเปิดเผยเวอร์ชัน + เวอร์ชันเก่า
    for rec in tech_records or []:
        if rec.get("type") != "tech":
            continue
        product = rec.get("product") or rec.get("value")
        version = rec.get("version")
        if version:
            deduct("version_disclosure",
                   f"เปิดเผยเวอร์ชันซอฟต์แวร์: {product} {version}", 4)
        if _is_outdated(product, version):
            deduct("outdated_software",
                   f"ซอฟต์แวร์เวอร์ชันเก่ามีความเสี่ยง: {product} {version}", 12)

    # (4) cookie flags
    if site_meta.get("cookie_secure") is False:
        deduct("cookie_insecure", "คุกกี้ไม่มีแฟล็ก Secure", 5)
    if site_meta.get("cookie_httponly") is False:
        deduct("cookie_no_httponly", "คุกกี้ไม่มีแฟล็ก HttpOnly", 5)

    # (5) robots เปิดเผย path ที่อ่อนไหว
    disallow = site_meta.get("robots_disallow") or []
    sensitive = [p for p in disallow
                 if re.search(r"admin|login|backup|config|private|\.git", p, re.I)]
    if sensitive:
        deduct("robots_exposure",
               f"robots.txt ชี้ path อ่อนไหว: {', '.join(sensitive[:5])}", 5)

    # (6) breach association
    breach_meta = breach_meta or {}
    bc = int(breach_meta.get("breach_count") or 0)
    if bc:
        deduct("breach_history",
               f"โดเมนเกี่ยวข้องกับเหตุข้อมูลรั่วที่รู้จัก {bc} ครั้ง", min(20, 6 + bc * 2))

    score = max(0, min(100, score))
    level = _security_level(score)
    return {
        "score": score,
        "security_level": level,
        "risk_level": _risk_from_security(level),
        "reasons": reasons,
        "positives": positives,
    }
