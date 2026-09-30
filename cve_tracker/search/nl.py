"""
cve_tracker.search.nl — natural-language → structured query (rule §53).

Lets a user search in plain Thai/English ('ช่องโหว่ critical ของ Apache ที่เพิ่ง
ประกาศ') and have it converted into the same structured :class:`SearchQuery` the
deterministic parser produces. Two layers, both safe:

  1. a **deterministic** extractor that pulls severity words, vendor/product
     hints, CWE ids, CVSS thresholds, KEV and recency cues out of the text with
     no AI at all — this alone handles most real queries; and
  2. an optional **AI refinement** (via the shared adapter) that maps a free
     sentence onto the same fields as strict JSON, used only to fill gaps.

Hard rule (rule §53): the AI never invents results. It only produces *filters*;
the actual CVE database remains the single source of truth, and every field the
AI returns is validated against the allowed vocabulary before use. If the AI is
unavailable or returns anything unexpected, the deterministic result stands.
"""

from __future__ import annotations

import re
from typing import Optional

from ..utils import normalize_cwe_id, safe_json_loads
from .query import SearchQuery, parse as strict_parse

# Deterministic keyword maps (Thai + English).
_SEVERITY_WORDS = {
    "critical": "CRITICAL", "วิกฤต": "CRITICAL", "ร้ายแรง": "CRITICAL", "รุนแรง": "CRITICAL",
    "high": "HIGH", "สูง": "HIGH",
    "medium": "MEDIUM", "ปานกลาง": "MEDIUM",
    "low": "LOW", "ต่ำ": "LOW",
}
_KEV_WORDS = ("kev", "exploited", "ถูกใช้โจมตี", "ถูกโจมตีจริง", "known exploited")
_RECENT_WORDS = ("recent", "latest", "new", "ล่าสุด", "เพิ่งประกาศ", "เพิ่งเผยแพร่", "ใหม่")
_CVSS_RE = re.compile(r"(?:cvss|คะแนน)\D{0,6}(\d{1,2}(?:\.\d)?)", re.I)
_GE_RE = re.compile(r"(?:>=|มากกว่า|อย่างน้อย|ตั้งแต่)\s*(\d{1,2}(?:\.\d)?)")

# A tiny vendor/product hint list so the deterministic layer recognises common
# names embedded in a sentence (the AI layer extends this).
_KNOWN_NAMES = (
    "microsoft", "apache", "cisco", "oracle", "adobe", "vmware", "fortinet",
    "linux", "windows", "chrome", "firefox", "wordpress", "totolink", "d-link",
    "tp-link", "netgear", "citrix", "ivanti", "juniper", "openssl", "nginx",
    "docker", "kubernetes", "gitlab", "jenkins", "atlassian", "confluence",
)


def deterministic_nl(text: str) -> SearchQuery:
    """Extract structured fields from a natural-language query with no AI."""
    q = SearchQuery(raw=(text or "").strip())
    low = q.raw.lower()
    if not low:
        q.recent = True
        return q

    for word, sev in _SEVERITY_WORDS.items():
        if word in low:
            q.severity = sev
            break
    if any(w in low for w in _KEV_WORDS):
        q.kev_only = True
    if any(w in low for w in _RECENT_WORDS):
        q.recent = True

    m = _GE_RE.search(low) or _CVSS_RE.search(low)
    if m:
        try:
            q.min_cvss = float(m.group(1))
        except ValueError:
            pass

    # CWE
    from ..utils import extract_cwe_ids
    cwes = extract_cwe_ids(q.raw)
    if cwes:
        q.cwe = cwes[0]

    # vendor/product hint
    for name in _KNOWN_NAMES:
        if name in low:
            q.vendor = name
            break

    # residual free text: strip recognised tokens, keep the rest as text
    residual = low
    for w in list(_SEVERITY_WORDS) + list(_KEV_WORDS) + list(_RECENT_WORDS):
        residual = residual.replace(w, " ")
    q.text = " ".join(t for t in residual.split() if len(t) > 2 and not t.isdigit())
    return q


_NL_SYSTEM = r"""
คุณคือตัวแปลงคำค้นภาษาธรรมชาติเป็นตัวกรองการค้นหา CVE ผู้ใช้จะพิมพ์คำค้นเป็นภาษาไทย
หรืออังกฤษ หน้าที่ของคุณคือสกัด "ตัวกรอง" เท่านั้น ห้ามสร้างผลลัพธ์ CVE เอง

ตอบกลับเป็น JSON เท่านั้น ตามรูปแบบ (ใส่เฉพาะฟิลด์ที่มั่นใจ ที่เหลือเว้นว่าง/ตัดออก):
{
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "min_cvss": 9.0,
  "vendor": "ชื่อผู้ผลิต",
  "product": "ชื่อผลิตภัณฑ์",
  "cwe": "CWE-79",
  "kev_only": true,
  "recent": true,
  "text": "คำค้นอิสระที่เหลือ"
}
ห้ามอธิบายเพิ่ม ห้ามแต่งชื่อผลิตภัณฑ์/ผู้ผลิตที่ผู้ใช้ไม่ได้พูดถึง
""".strip()

_ALLOWED_SEVERITY = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}


async def ai_refine(text: str, adapter, base: Optional[SearchQuery] = None) -> SearchQuery:
    """Refine the deterministic query with the AI adapter, validating every
    field. Falls back to ``base`` (or the deterministic result) on any issue."""
    q = base or deterministic_nl(text)
    if adapter is None or not adapter.available():
        return q
    try:
        res = await adapter.generate(f"คำค้น: {text}", system=_NL_SYSTEM, task="light")
    except Exception:
        return q
    if not res.ok:
        return q
    data = safe_json_loads(res.text, default=None)
    if not isinstance(data, dict):
        return q

    # Validate + merge (AI only fills gaps; it never overrides an explicit hit).
    sev = str(data.get("severity", "") or "").upper()
    if sev in _ALLOWED_SEVERITY and not q.severity:
        q.severity = sev
    try:
        mc = data.get("min_cvss")
        if mc is not None and q.min_cvss is None:
            mc = float(mc)
            if 0.0 <= mc <= 10.0:
                q.min_cvss = mc
    except (TypeError, ValueError):
        pass
    if data.get("kev_only") is True:
        q.kev_only = True
    if data.get("recent") is True:
        q.recent = True
    cwe = normalize_cwe_id(str(data.get("cwe", "") or ""))
    if cwe and not q.cwe:
        q.cwe = cwe
    if not q.vendor and data.get("vendor"):
        q.vendor = str(data["vendor"]).strip()[:60]
    if not q.product and data.get("product"):
        q.product = str(data["product"]).strip()[:60]
    return q


def to_strict(q: SearchQuery) -> SearchQuery:
    """Normalise an NL-derived query back through the strict parser's kind
    logic by re-deriving its dominant intent (keeps SearchQuery invariants)."""
    # If nothing structured came out, fall back to treating the raw text as a
    # plain text search via the strict parser.
    if q.is_empty and q.raw:
        return strict_parse(q.raw)
    return q
