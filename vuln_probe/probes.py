# -*- coding: utf-8 -*-
"""vuln_probe/probes.py — ตัววิเคราะห์ช่องโหว่แบบ "safe-validation" (pure logic)

ปรัชญา: ตรวจ *การมีอยู่ของ indicator* ด้วย marker ที่ไม่ทำลายข้อมูล — เหมือน DAST
detection ไม่ใช่การ exploit/ดึงข้อมูล/ยิงซ้ำรัว ๆ. ส่วน "ยิงจริง" อยู่ที่ engine และ
ยิงผ่านด่าน scope+SSRF ของ security_testing เสมอ; ที่นี่คือ "สมอง" ที่อ่านผลล้วน ๆ

ทุกฟังก์ชันรับ input แล้วคืน indicator หรือ None — เทสต์ได้ 100% โดยไม่ต้องต่อเน็ต
indicator: {category, severity, confidence, detail, evidence}  (severity: INFO/LOW/MEDIUM/HIGH)
"""

from __future__ import annotations

import re
import secrets
from typing import Any, Dict, List, Optional


def new_marker(prefix: str = "sombra") -> str:
    """marker สุ่มที่หา reflection ได้ง่ายและไม่ชนเนื้อหาเว็บจริง"""
    return f"{prefix}{secrets.token_hex(4)}"


def _ind(category: str, severity: str, confidence: float, detail: str,
         evidence: str = "") -> Dict[str, Any]:
    return {"category": category, "severity": severity, "confidence": round(confidence, 2),
            "detail": detail, "evidence": evidence[:200], "type": "informational_indicator"}


# ---------------------------------------------------------------------------
# Reflected XSS (marker reflection — ไม่ยิง payload ทำงานจริง)
# ---------------------------------------------------------------------------

def analyze_reflection(marker: str, body: str, content_type: str = "") -> Optional[Dict[str, Any]]:
    """marker ที่ส่งไปสะท้อนกลับมา "แบบไม่ถูก encode" ในบริบท HTML ไหม

    - สะท้อนแบบดิบใน HTML -> indicator (อาจ reflected XSS)
    - สะท้อนแต่ถูก HTML-encode -> ปลอดภัย (ไม่ออก indicator)
    - ไม่ใช่ HTML (เช่น application/json) -> ลดความรุนแรง
    """
    if not marker or marker not in body:
        return None
    # ถูก encode หรือไม่ (ถ้าเจอ marker ในรูป &...; แปลว่า sanitize)
    raw_ctx = re.search(re.escape(marker) + r"[^<]*", body)
    is_html = "html" in (content_type or "").lower() or "<html" in body.lower()
    # ตรวจว่า marker โผล่ "นอก" entity-encoding (มี < > " รอบ ๆ แบบ inject ได้)
    dangerous = bool(re.search(r"[<>\"']\s*" + re.escape(marker) + r"|" +
                               re.escape(marker) + r"\s*[<>\"']", body))
    if is_html and dangerous:
        return _ind("reflected_xss", "MEDIUM", 0.6,
                    "marker สะท้อนกลับแบบดิบในบริบท HTML (อาจเป็น reflected XSS — ต้องยืนยันด้วยมือ)",
                    (raw_ctx.group(0) if raw_ctx else marker))
    if is_html:
        return _ind("input_reflection", "LOW", 0.4,
                    "input สะท้อนกลับใน HTML (ยังไม่ชัดว่า exploit ได้)", marker)
    return _ind("input_reflection", "INFO", 0.3,
                "input สะท้อนกลับ (ไม่ใช่บริบท HTML)", marker)


# ---------------------------------------------------------------------------
# SQL injection (error-signature detection — ไม่ extract ข้อมูล)
# ---------------------------------------------------------------------------

_SQL_ERRORS = [
    (r"SQL syntax.*MySQL", "MySQL"),
    (r"valid MySQL result", "MySQL"),
    (r"PostgreSQL.*ERROR", "PostgreSQL"),
    (r"pg_query\(\):", "PostgreSQL"),
    (r"Unclosed quotation mark after the character string", "MSSQL"),
    (r"Microsoft SQL (Server|Native Client)", "MSSQL"),
    (r"ORA-\d{5}", "Oracle"),
    (r"SQLite/JDBCDriver|SQLite3::|sqlite3.OperationalError", "SQLite"),
    (r"com\.mysql\.jdbc", "MySQL/JDBC"),
    (r"You have an error in your SQL syntax", "MySQL"),
]


def analyze_sql_error(body_baseline: str, body_probe: str) -> Optional[Dict[str, Any]]:
    """ส่ง quote เดี่ยวแล้วเทียบ: error signature "โผล่ใหม่" หลังใส่ quote = สัญญาณ SQLi

    detection เท่านั้น — ไม่มี UNION/boolean/time-based extraction
    """
    for pat, engine_name in _SQL_ERRORS:
        in_probe = re.search(pat, body_probe, re.I)
        in_base = re.search(pat, body_baseline, re.I)
        if in_probe and not in_base:
            return _ind("sql_injection", "HIGH", 0.7,
                        f"พบ SQL error signature ({engine_name}) หลังใส่อักขระพิเศษ "
                        f"— อาจเป็น error-based SQLi (ต้องยืนยันด้วยมือ)",
                        in_probe.group(0))
    return None


# ---------------------------------------------------------------------------
# SSTI (server-side template injection — ส่งนิพจน์เลขคณิต, ดูผลคูณ)
# ---------------------------------------------------------------------------

def analyze_ssti(marker_prefix: str, expected: str, body: str) -> Optional[Dict[str, Any]]:
    """ถ้าส่ง '<prefix>{{7*N}}' แล้วเจอ '<prefix><expected>' = template ถูกประเมินฝั่ง server"""
    needle = f"{marker_prefix}{expected}"
    if needle in body:
        return _ind("ssti", "HIGH", 0.75,
                    "template expression ถูกประเมินฝั่ง server (อาจเป็น SSTI — ต้องยืนยัน)",
                    needle)
    return None


# ---------------------------------------------------------------------------
# Open redirect (ส่ง external marker host, ดู Location — ไม่ follow)
# ---------------------------------------------------------------------------

def analyze_open_redirect(status: int, location: str, injected_host: str
                          ) -> Optional[Dict[str, Any]]:
    if not location or status not in (301, 302, 303, 307, 308):
        return None
    loc = location.strip()
    # Location ชี้ออกไปโฮสต์ที่เรา inject (ภายนอก) = open redirect
    m = re.match(r"(?i)^(?:https?:)?//([^/\\?#]+)", loc) or \
        re.match(r"(?i)^https?://([^/\\?#]+)", loc)
    host = m.group(1).lower() if m else ""
    if injected_host.lower() in host:
        return _ind("open_redirect", "MEDIUM", 0.8,
                    f"พารามิเตอร์ redirect พาออกไปโฮสต์ภายนอกที่ควบคุมได้ ({host})", loc)
    return None


# ---------------------------------------------------------------------------
# CORS misconfiguration (ส่ง Origin ปลอม, ดู ACAO/ACAC)
# ---------------------------------------------------------------------------

def analyze_cors(sent_origin: str, acao: str, acac: str) -> Optional[Dict[str, Any]]:
    acao = (acao or "").strip()
    acac = (acac or "").strip().lower()
    if not acao:
        return None
    # สะท้อน origin ที่เราส่ง + อนุญาต credentials = อันตรายสุด
    if acao == sent_origin and acac == "true":
        return _ind("cors_misconfig", "HIGH", 0.85,
                    "ACAO สะท้อน Origin ที่ไม่น่าเชื่อถือ + Allow-Credentials=true "
                    "(อ่านข้อมูลข้าม origin ได้)", f"ACAO={acao}; ACAC={acac}")
    if acao == "*" and acac == "true":
        return _ind("cors_misconfig", "MEDIUM", 0.6,
                    "ACAO=* ร่วมกับ credentials (บราวเซอร์มักบล็อก แต่ตั้งค่าผิด)",
                    f"ACAO=*; ACAC={acac}")
    if acao == sent_origin:
        return _ind("cors_misconfig", "LOW", 0.5,
                    "ACAO สะท้อน Origin ที่ส่งไป (ควรตรวจ allowlist)", f"ACAO={acao}")
    return None


# ---------------------------------------------------------------------------
# Subdomain / service takeover (fingerprint ของบริการที่ dangling)
# ---------------------------------------------------------------------------

_TAKEOVER_FP = [
    ("GitHub Pages", r"There isn't a GitHub Pages site here|For root URLs.*must be configured"),
    ("AWS S3", r"NoSuchBucket|The specified bucket does not exist"),
    ("Heroku", r"No such app|herokucdn\.com/error-pages/no-such-app"),
    ("Shopify", r"Sorry, this shop is currently unavailable"),
    ("Fastly", r"Fastly error: unknown domain"),
    ("Azure", r"404 Web Site not found|This web app is stopped"),
    ("Readthedocs", r"unknown to Read the Docs"),
    ("Surge.sh", r"project not found"),
    ("Bitbucket", r"Repository not found"),
    ("Pantheon", r"The gods are wise, but do not know of the site"),
]


def analyze_takeover(status: int, body: str) -> Optional[Dict[str, Any]]:
    for service, pat in _TAKEOVER_FP:
        if re.search(pat, body, re.I):
            return _ind("subdomain_takeover", "HIGH", 0.8,
                        f"เจอ fingerprint ของบริการที่ชี้ค้าง ({service}) "
                        f"— อาจ takeover ได้ (ต้องยืนยันความเป็นเจ้าของ)",
                        service)
    return None


# ---------------------------------------------------------------------------
# รวม + จัดลำดับ
# ---------------------------------------------------------------------------

def highest(indicators: List[Dict[str, Any]]) -> str:
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    best = "INFO"
    for i in indicators:
        if order.get(i["severity"], 0) > order.get(best, 0):
            best = i["severity"]
    return best
