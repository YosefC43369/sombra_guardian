# -*- coding: utf-8 -*-
"""evidence_management/redact.py — redact ข้อมูลอ่อนไหวก่อนเก็บ/ส่ง (reuse ของเดิม)

reuse web_vulnerability_assessment.classify.sanitize / sanitize_headers (ชุด redaction
เดียวของแพลตฟอร์ม — ไม่ทำ regex ซ้ำคนละชุด) แล้วเสริมเฉพาะ: ตรวจว่า "มีการ redact เกิดขึ้น
จริงไหม" (เพื่อบันทึก redaction_applied/notes) และตัวช่วย redact request/response excerpt

หลัก: ห้ามเก็บ credential/cookie/token/PII เกินจำเป็น — ถ้าเก็บ raw ไม่ได้อย่างปลอดภัย ให้
เก็บรูปแบบที่ redact แล้ว และบันทึกว่า redaction เกิดขึ้น
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

try:
    from web_vulnerability_assessment.classify import sanitize as _sanitize, \
        sanitize_headers as _sanitize_headers
    _HAS_CLASSIFY = True
except Exception:  # pragma: no cover
    _HAS_CLASSIFY = False

    def _sanitize(text, limit=300):
        return (str(text) if text else "")[:limit]

    def _sanitize_headers(headers):
        return {k: ("[REDACTED]" if k.lower() in (
            "set-cookie", "cookie", "authorization", "proxy-authorization",
            "x-api-key", "x-auth-token") else str(v)[:200])
            for k, v in (headers or {}).items()}

# ตัวบ่งชี้ว่ามีการ redact (ใช้ตรวจ redaction_applied — ไม่ redact ซ้ำ)
_REDACT_MARKERS = ("[REDACTED]", "[EMAIL]", "[JWT-REDACTED]", "[CARD-REDACTED]")
_SENSITIVE_HINT = re.compile(
    r"(?i)(set-cookie|cookie|authorization|bearer\s|api[_-]?key|token|secret|password|"
    r"passwd|pwd|eyJ[A-Za-z0-9_\-]{6,}\.)")


def sanitize(text: Any, limit: int = 2000) -> str:
    return _sanitize(text, limit)


def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return _sanitize_headers(headers)


def redact_text(text: Any, limit: int = 2000) -> Tuple[str, bool]:
    """คืน (redacted_text, was_redacted) — was_redacted=True ถ้ามี marker หรือเจอ hint"""
    raw = str(text) if text else ""
    out = _sanitize(raw, limit)
    redacted = any(m in out for m in _REDACT_MARKERS) or bool(_SENSITIVE_HINT.search(raw))
    return out, redacted


def redact_http_excerpt(method: Optional[str], url: Optional[str],
                        headers: Optional[Dict[str, str]], body: Optional[str],
                        *, body_limit: int = 500) -> Tuple[Dict[str, Any], bool]:
    """สร้าง excerpt ของ request/response ที่ redact แล้ว + ธงว่ามีการ redact

    ไม่เก็บ body เต็มโดยไม่จำเป็น (ตัดที่ body_limit) · header อ่อนไหวถูก redact
    """
    redacted = False
    safe_headers = {}
    if headers:
        safe_headers = _sanitize_headers(headers)
        if any(v == "[REDACTED]" for v in safe_headers.values()):
            redacted = True
    safe_body = ""
    if body:
        safe_body, b_red = redact_text(body, body_limit)
        redacted = redacted or b_red or len(str(body)) > body_limit
    excerpt = {
        "method": (method or "").upper()[:10] or None,
        "url": _sanitize(url, 300) if url else None,
        "headers": safe_headers,
        "body_excerpt": safe_body,
        "body_truncated": bool(body and len(str(body)) > body_limit),
    }
    return excerpt, redacted


def redaction_note(was_redacted: bool, extra: str = "") -> str:
    if not was_redacted:
        return ""
    base = "ข้อมูลอ่อนไหว (credential/cookie/token/PII) ถูก redact ก่อนเก็บ"
    return f"{base}; {extra}" if extra else base
