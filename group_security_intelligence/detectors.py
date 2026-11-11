# -*- coding: utf-8 -*-
"""group_security_intelligence/detectors.py — ตรวจจับข้อมูลลับ + social engineering

pure logic ล้วน (stdlib + urkit เท่านั้น) เทสต์ได้ ไม่แตะ telegram/ดิสก์/เครือข่าย

สองตัวตรวจ:
  scan_secrets(text)  -> รายการ finding ของข้อมูลลับ (ค่าถูก redact แล้วเสมอ)
  analyze_social_eng(text) -> finding การหลอกลวง พร้อม risk score/confidence/เหตุผล

หลักความปลอดภัย: ไม่คืน/ไม่เก็บค่า secret เต็มเด็ดขาด — คืนเฉพาะรูปแบบที่ redact แล้ว
และ fingerprint (hash) ไว้กันแจ้งซ้ำ
"""

from __future__ import annotations

import re
import hashlib
from typing import Any, Dict, List, Optional

try:
    import urlkit  # type: ignore
    _HAS_URLKIT = True
except Exception:  # pragma: no cover
    urlkit = None  # type: ignore
    _HAS_URLKIT = False


# ---------------------------------------------------------------------------
# การ redact
# ---------------------------------------------------------------------------

def redact(secret: str, keep: int = 4) -> str:
    """ย่อ secret ให้เหลือเบาะแสพอจำได้ แต่กู้ค่าเดิมไม่ได้

    'ghp_abcdef1234567890' -> 'ghp_…7890' (เก็บ prefix สั้น + ท้าย keep ตัว)
    ของสั้นมาก -> ปิดทั้งก้อน
    """
    s = (secret or "").strip()
    if len(s) <= keep + 2:
        return "•" * len(s)
    head = s[:min(4, len(s) - keep)]
    tail = s[-keep:]
    return f"{head}…{tail}"


def fingerprint(secret: str) -> str:
    """hash สั้นไว้กันแจ้งซ้ำ (ไม่ย้อนกลับเป็นค่าเดิม)"""
    return hashlib.sha256((secret or "").encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# กฎตรวจข้อมูลลับ (ชื่อ, ระดับ, regex, กลุ่มที่เป็นค่า secret)
# ---------------------------------------------------------------------------

class _Rule:
    __slots__ = ("name", "severity", "regex", "group")

    def __init__(self, name: str, severity: str, pattern: str, group: int = 0,
                 flags: int = 0):
        self.name = name
        self.severity = severity
        self.regex = re.compile(pattern, flags)
        self.group = group


# severity: LOW / MEDIUM / HIGH / CRITICAL
_SECRET_RULES: List[_Rule] = [
    _Rule("Private key block", "CRITICAL",
          r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    _Rule("Telegram bot token", "CRITICAL",
          r"\b\d{6,10}:[A-Za-z0-9_-]{30,40}\b"),
    _Rule("AWS access key id", "HIGH", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _Rule("AWS secret access key", "CRITICAL",
          r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
    _Rule("GitHub token", "HIGH", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    _Rule("Google API key", "HIGH", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    _Rule("Slack token", "HIGH", r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b"),
    _Rule("Stripe secret key", "CRITICAL", r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,99}\b"),
    _Rule("OpenAI key", "HIGH", r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"),
    _Rule("JWT", "MEDIUM", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    _Rule("DB connection string", "HIGH",
          r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
          r"[^\s:@/]+:([^\s:@/]+)@[^\s/]+"),
    _Rule("Password assignment", "MEDIUM",
          r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
          r"client[_-]?secret|private[_-]?key)\b\s*[=:]\s*['\"]?([^\s'\"]{6,})"),
    _Rule("Generic bearer token", "MEDIUM",
          r"(?i)\bbearer\s+([A-Za-z0-9._-]{20,})"),
    _Rule("Dotenv-style secret line", "MEDIUM",
          r"(?im)^[A-Z][A-Z0-9_]{2,}(?:KEY|TOKEN|SECRET|PASSWORD|PASS|PWD)\s*=\s*(\S{6,})$"),
]


def scan_secrets(text: str) -> List[Dict[str, Any]]:
    """ตรวจข้อมูลลับในข้อความ คืนรายการ finding (ค่า redact แล้ว)

    แต่ละ finding:
      {type, severity, redacted, fingerprint, span}
    ลด false-positive: ตัดซ้ำด้วย fingerprint, ข้ามค่าที่เป็น placeholder ทั่วไป
    """
    if not text:
        return []
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for rule in _SECRET_RULES:
        for m in rule.regex.finditer(text):
            value = m.group(rule.group) if rule.group else m.group(0)
            if not value:
                continue
            value = value.strip().strip("'\"")
            if _looks_placeholder(value):
                continue
            fp = fingerprint(value)
            if fp in seen:
                continue
            seen.add(fp)
            out.append({
                "type": rule.name,
                "severity": rule.severity,
                "redacted": redact(value),
                "fingerprint": fp,
                "span": [m.start(), m.end()],
            })
    return out


_PLACEHOLDERS = {
    "password", "changeme", "example", "yourpassword", "your_password",
    "xxxxxx", "xxxxxxxx", "placeholder", "secret", "token", "redacted",
    "none", "null", "true", "false", "<password>", "******", "********",
    "your_api_key", "your-token-here", "test", "123456", "password123",
}


def _looks_placeholder(value: str) -> bool:
    v = value.lower()
    if v in _PLACEHOLDERS:
        return True
    if re.fullmatch(r"[x*•.]{4,}", v):
        return True
    if re.fullmatch(r"<[^>]+>", v) or re.fullmatch(r"\{\{?[^}]+\}?\}", v):
        return True
    return False


def highest_severity(findings: List[Dict[str, Any]]) -> str:
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    best = "LOW"
    for f in findings:
        if order.get(f.get("severity", "LOW"), 0) > order.get(best, 0):
            best = f["severity"]
    return best


# ---------------------------------------------------------------------------
# Social engineering — วิเคราะห์เชิงบริบท (ไม่ใช่ keyword เดี่ยว ๆ)
# ---------------------------------------------------------------------------
# แต่ละสัญญาณ: (ชื่อ, น้ำหนัก, รายการ regex) — คะแนนรวมหลายสัญญาณพร้อมกันจึงจะสูง

_SE_SIGNALS = [
    ("otp_or_password_request", 35, [
        r"(?i)\b(?:otp|one[\s-]?time|รหัส\s*otp|รหัสผ่าน|password|passcode|pin|"
        r"รหัสยืนยัน|verification code|2fa|two[\s-]?factor)\b.{0,40}"
        r"(?:send|give|share|บอก|ส่ง|กรอก|แจ้ง|ขอ)",
        r"(?i)(?:send|share|บอก|ส่ง|กรอก|แจ้ง)\b.{0,30}\b(?:otp|รหัส|password|pin|code)\b",
    ]),
    ("admin_impersonation", 25, [
        r"(?i)\b(?:i am|this is|ผมคือ|ฉันคือ|นี่คือ|เป็น)\s*(?:the\s*)?(?:admin|administrator|"
        r"แอดมิน|ผู้ดูแล|owner|เจ้าของกลุ่ม|support|ทีมงาน|staff)\b",
        r"(?i)\bofficial\s+(?:admin|support|team|staff)\b",
    ]),
    ("account_verification_scam", 22, [
        r"(?i)\b(?:verify|confirm|ยืนยัน|re[\s-]?verify)\b.{0,40}"
        r"\b(?:account|บัญชี|identity|ตัวตน|wallet|กระเป๋า)\b",
        r"(?i)\b(?:account|บัญชี).{0,20}(?:suspend|ระงับ|ล็อก|lock|บล็อก|disabled)\b",
    ]),
    ("payment_instruction", 25, [
        r"(?i)\b(?:transfer|โอน|send money|ชำระ|จ่าย|เติมเงิน|pay now|โอนเงิน)\b.{0,40}"
        r"(?:usdt|btc|eth|bank|บัญชี|wallet|promptpay|พร้อมเพย์|account)",
        r"(?i)\b(?:wallet address|ที่อยู่กระเป๋า|เลขบัญชี|account number)\b",
    ]),
    ("fake_security_alert", 20, [
        r"(?i)\b(?:security alert|แจ้งเตือนความปลอดภัย|unusual activity|กิจกรรมผิดปกติ|"
        r"ตรวจพบการเข้าสู่ระบบ|unauthorized login|บัญชีถูกแฮก|hacked)\b",
    ]),
    ("urgency_pressure", 12, [
        r"(?i)\b(?:urgent|ด่วน|immediately|ทันที|right now|เดี๋ยวนี้|within \d+ (?:min|hour)|"
        r"ภายใน\s*\d+\s*(?:นาที|ชม|ชั่วโมง)|ก่อนที่จะสาย|จะถูกระงับ|จะถูกลบ)\b",
    ]),
    ("credential_access_request", 25, [
        r"(?i)\b(?:give|share|send|บอก|ส่ง|แชร์)\b.{0,30}"
        r"\b(?:seed|phrase|private key|recovery|กุญแจ|รหัสกู้คืน|login|รหัสเข้า)\b",
    ]),
    ("suspicious_external_action", 14, [
        r"(?i)\b(?:click|กด|คลิก|เข้าไปที่|go to|open)\b.{0,30}"
        r"(?:https?://|t\.me/|bit\.ly|tinyurl|คลิกลิงก์)",
        r"(?i)\b(?:claim|รับ|แจก)\b.{0,20}\b(?:reward|airdrop|ฟรี|free|รางวัล|โบนัส)\b",
    ]),
]

# คำที่บ่งชี้บริบท "ทางการ/เร่งด่วน" ขยายน้ำหนักเมื่อมาคู่สัญญาณอื่น
_AMPLIFIER_RE = re.compile(
    r"(?i)\b(?:dm me|ทักมา|inbox|ส่วนตัว|private|อย่าบอกใคร|keep secret|เก็บเป็นความลับ)\b")


def analyze_social_eng(text: str) -> Optional[Dict[str, Any]]:
    """วิเคราะห์ข้อความว่าเข้าข่าย social engineering ไหม (เชิงบริบท)

    คืน None ถ้าไม่เข้าข่าย, ไม่งั้นคืน:
      {category, risk_score(0-100), confidence(0-1), explanation,
       indicators:[...], recommended_action, has_external_link}
    คะแนนมาจาก "หลายสัญญาณพร้อมกัน" ไม่ใช่คำเดียว — ลด false positive
    """
    if not text or len(text) < 3:
        return None

    matched: List[str] = []
    score = 0
    for name, weight, patterns in _SE_SIGNALS:
        if any(re.search(p, text) for p in patterns):
            matched.append(name)
            score += weight

    if not matched:
        return None

    # ขยายคะแนนเมื่อมีหลายสัญญาณ หรือมีตัวกระตุ้น "คุยส่วนตัว/ปิดลับ"
    if len(matched) >= 2:
        score += 10 * (len(matched) - 1)
    if _AMPLIFIER_RE.search(text):
        score += 8

    has_link = False
    if _HAS_URLKIT:
        try:
            has_link = bool(urlkit.extract_urls(text))
        except Exception:
            has_link = False
    else:
        has_link = bool(re.search(r"https?://|t\.me/", text))
    if has_link and any(m in ("payment_instruction", "account_verification_scam",
                              "credential_access_request", "suspicious_external_action")
                        for m in matched):
        score += 10

    score = max(0, min(100, score))
    # ต้องถึงเกณฑ์ขั้นต่ำจึงรายงาน (คำเดี่ยวน้ำหนักน้อยจะไม่ผ่าน)
    if score < 25:
        return None

    # category = สัญญาณที่หนักสุด
    primary = max(matched, key=lambda n: dict((s[0], s[1]) for s in _SE_SIGNALS)[n])
    confidence = min(1.0, 0.4 + 0.15 * len(matched) + (0.1 if has_link else 0))

    return {
        "category": primary,
        "risk_score": score,
        "confidence": round(confidence, 2),
        "explanation": _se_explain(matched, has_link),
        "indicators": matched,
        "has_external_link": has_link,
        "recommended_action": _se_action(score),
    }


def _se_explain(matched: List[str], has_link: bool) -> str:
    th = {
        "otp_or_password_request": "ขอรหัส OTP/รหัสผ่าน",
        "admin_impersonation": "อ้างตัวเป็นแอดมิน/ทีมงาน",
        "account_verification_scam": "หลอกให้ยืนยันบัญชี",
        "payment_instruction": "สั่งให้โอนเงิน/คริปโต",
        "fake_security_alert": "แจ้งเตือนความปลอดภัยปลอม",
        "urgency_pressure": "กดดันให้รีบทำ",
        "credential_access_request": "ขอกุญแจ/seed/รหัสกู้คืน",
        "suspicious_external_action": "ชักจูงให้กดลิงก์/รับของฟรี",
    }
    parts = [th.get(m, m) for m in matched]
    tail = " และมีลิงก์ภายนอกประกอบ" if has_link else ""
    return "พบสัญญาณหลอกลวงหลายอย่างพร้อมกัน: " + ", ".join(parts) + tail


def _se_action(score: int) -> str:
    if score >= 70:
        return "แจ้งแอดมินทันที + พิจารณาเตือน/ลบข้อความ และเตือนสมาชิกอย่าทำตาม"
    if score >= 45:
        return "แจ้งแอดมินให้ตรวจสอบ และเฝ้าระวังผู้ส่ง"
    return "บันทึกไว้เพื่อตรวจทาน ยังไม่ต้องดำเนินการ"
