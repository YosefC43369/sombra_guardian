# -*- coding: utf-8 -*-
"""api_security_assessment/analyzers.py — ตัววิเคราะห์ความปลอดภัย API (pure logic)

detection ล้วน ไม่ bypass/forge/brute — อ่านผลที่เก็บมาแล้วตัดสิน
reuse: web_vulnerability_assessment.detectors (CORS/verbose-error/headers),
vuln_probe.probes ผ่าน WVA bridge (SQLi/XSS)

observation: {category, rule, severity_hint, state, confidence, detail, evidence, recommendation}
state: CONFIRMED / POTENTIAL / INFORMATIONAL / NOT_REPRODUCIBLE
"""

from __future__ import annotations

import re
import json
import base64
from typing import Any, Dict, List, Optional

try:
    from web_vulnerability_assessment import detectors as wva_det
    _HAS_WVA = True
except Exception:  # pragma: no cover
    _HAS_WVA = False


def obs(category, rule, severity_hint, state, confidence, detail, evidence="",
        recommendation="") -> Dict[str, Any]:
    return {"category": category, "rule": rule, "severity_hint": severity_hint,
            "state": state, "confidence": round(confidence, 2), "detail": detail,
            "evidence": (evidence or "")[:200], "recommendation": recommendation}


# ---------------------------------------------------------------------------
# JWT — อ่าน header/claims เท่านั้น (ไม่ verify/ไม่ forge)
# ---------------------------------------------------------------------------

def _b64url(seg: str) -> Optional[dict]:
    try:
        pad = "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + pad))
    except Exception:
        return None


def inspect_jwt(token: str) -> Optional[Dict[str, Any]]:
    """อ่าน JWT header+payload (ไม่ตรวจลายเซ็น) คืนข้อมูล + สัญญาณเสี่ยงเชิง config"""
    t = (token or "").strip()
    t = re.sub(r"(?i)^bearer\s+", "", t)
    parts = t.split(".")
    if len(parts) < 2:
        return None
    header = _b64url(parts[0])
    payload = _b64url(parts[1])
    if not header or not payload:
        return None
    alg = str(header.get("alg", "")).upper()
    issues = []
    if alg in ("NONE", ""):
        issues.append("alg=none (ไม่มีลายเซ็น)")
    if alg == "HS256" and not payload.get("exp"):
        issues.append("ไม่มี exp (token ไม่หมดอายุ)")
    if "exp" not in payload:
        issues.append("ไม่มี exp claim")
    if "aud" not in payload:
        issues.append("ไม่มี aud claim")
    if "iss" not in payload:
        issues.append("ไม่มี iss claim")
    return {"alg": alg, "typ": header.get("typ"),
            "claims": sorted(payload.keys()),
            "has_exp": "exp" in payload, "has_aud": "aud" in payload,
            "has_iss": "iss" in payload, "issues": issues}


def jwt_observation(info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not info or not info.get("issues"):
        return None
    critical = any("alg=none" in i for i in info["issues"])
    sev = "HIGH" if critical else "LOW"
    state = "CONFIRMED" if critical else "INFORMATIONAL"
    return obs("authentication", "jwt_inspect", sev, state, 0.6 if critical else 0.4,
               "JWT config indicator: " + ", ".join(info["issues"]),
               f"alg={info.get('alg')} claims={info.get('claims')}",
               "ตั้ง alg ที่ปลอดภัย (RS256/ES256), บังคับ exp/aud/iss และตรวจลายเซ็นฝั่ง server")


# ---------------------------------------------------------------------------
# Auth enforcement — endpoint ที่ควรต้อง auth แต่ตอบ 200 โดยไม่มี token
# ---------------------------------------------------------------------------

def auth_enforcement(endpoint: Dict[str, Any], status_no_auth: int,
                     body_no_auth: str) -> Optional[Dict[str, Any]]:
    doc_auth = endpoint.get("auth_required")
    sensitive = endpoint.get("sensitive") or endpoint.get("admin")
    accessible = status_no_auth == 200 and len(body_no_auth or "") > 0
    if accessible and (doc_auth is True or sensitive):
        sev = "HIGH" if endpoint.get("admin") else "MEDIUM"
        return obs("authentication", "missing_auth", sev, "POTENTIAL", 0.65,
                   f"endpoint ที่ควรต้องยืนยันตัวตนตอบ 200 โดยไม่มี token "
                   f"({endpoint['method']} {endpoint['path']})",
                   f"status={status_no_auth}",
                   "บังคับ authentication ฝั่ง server ทุก endpoint ที่เข้าถึงข้อมูล/การกระทำที่ปกป้อง")
    return None


# ---------------------------------------------------------------------------
# Authorization — BOLA/BFLA/tenant (เทียบพฤติกรรม 2 บัญชีทดสอบ)
# ---------------------------------------------------------------------------

def authz_compare(endpoint_path: str, method: str,
                  owner_status: int, owner_body: str,
                  other_status: int, other_body: str,
                  kind: str = "BOLA") -> Optional[Dict[str, Any]]:
    """เทียบการเข้าถึง object/function ของ 'บัญชีเจ้าของ' vs 'บัญชีอื่น' (ทดสอบ)

    ถ้าบัญชีอื่นเข้าถึงได้ (200) และเนื้อหาคล้ายของเจ้าของ = สัญญาณ BOLA/BFLA
    detection เท่านั้น — ใช้ได้กับ test account + synthetic resource ที่ operator ให้มา
    """
    other_granted = other_status == 200 and len(other_body or "") > 0
    owner_granted = owner_status == 200
    if not other_granted:
        return None
    # เนื้อหาเหมือนกันมาก = บัญชีอื่นเห็นข้อมูลของเจ้าของ
    similar = owner_granted and _similar(owner_body, other_body)
    cat = "authorization"
    rule = "bola" if kind == "BOLA" else ("bfla" if kind == "BFLA" else "tenant_isolation")
    if similar:
        return obs(cat, rule, "HIGH", "POTENTIAL", 0.7,
                   f"{kind}: บัญชีทดสอบอื่นเข้าถึงทรัพยากร/ฟังก์ชันของบัญชีเจ้าของได้ "
                   f"({method} {endpoint_path})",
                   f"owner={owner_status} other={other_status} (เนื้อหาใกล้เคียง)",
                   "บังคับตรวจความเป็นเจ้าของ/บทบาทฝั่ง server ทุกการเข้าถึง object/function")
    return obs(cat, rule, "MEDIUM", "POTENTIAL", 0.5,
               f"{kind}: บัญชีทดสอบอื่นได้รับ 200 (ตรวจยืนยันว่าเห็นข้อมูลจริงไหม)",
               f"owner={owner_status} other={other_status}",
               "ตรวจ authorization ฝั่ง server + ยืนยันขอบเขตข้อมูลที่คืน")


def _similar(a: str, b: str) -> bool:
    a, b = (a or "")[:2000], (b or "")[:2000]
    if not a or not b:
        return False
    if a == b:
        return True
    # Jaccard หยาบ ๆ บน token
    ta, tb = set(re.findall(r"\w+", a)), set(re.findall(r"\w+", b))
    if not ta or not tb:
        return False
    return len(ta & tb) / len(ta | tb) >= 0.6


# ---------------------------------------------------------------------------
# GraphQL
# ---------------------------------------------------------------------------

def graphql_introspection(resp_json: Any) -> Optional[Dict[str, Any]]:
    try:
        data = resp_json.get("data") if isinstance(resp_json, dict) else None
        schema = (data or {}).get("__schema") if isinstance(data, dict) else None
    except Exception:
        schema = None
    if schema and isinstance(schema, dict) and schema.get("types"):
        n = len(schema.get("types", []))
        return obs("graphql", "introspection", "MEDIUM", "CONFIRMED", 0.85,
                   f"GraphQL introspection เปิดอยู่ (เปิดเผย schema {n} types)",
                   f"types={n}",
                   "ปิด introspection ใน production, จำกัด query depth/complexity")
    return None


def graphql_error_disclosure(resp_text: str) -> Optional[Dict[str, Any]]:
    if re.search(r'(?i)"errors"\s*:\s*\[', resp_text or "") and \
       re.search(r"(?i)(stack|trace|at \w+\.|exception|debug|syntax error)", resp_text or ""):
        return obs("graphql", "error_disclosure", "LOW", "INFORMATIONAL", 0.5,
                   "GraphQL error เปิดเผยรายละเอียดภายใน", "errors[] + trace",
                   "ปิด debug error, คืน error กลาง ๆ")
    return None


# ---------------------------------------------------------------------------
# Config / misconfig (reuse WVA detectors)
# ---------------------------------------------------------------------------

def cors(sent_origin: str, acao: str, acac: str) -> Optional[Dict[str, Any]]:
    if not _HAS_WVA:
        return None
    o = wva_det.vp_cors(sent_origin, acao, acac)
    if o:
        o = dict(o); o["category"] = "cors"
    return o


def verbose_error(body: str) -> Optional[Dict[str, Any]]:
    if not _HAS_WVA:
        return None
    o = wva_det.analyze_verbose_error(body)
    if o:
        o = dict(o); o["category"] = "info_disclosure"
    return o


def security_headers(headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
    if not _HAS_WVA:
        return None
    o = wva_det.analyze_headers(headers)
    if o:
        o = dict(o); o["category"] = "misconfiguration"
    return o


def server_disclosure(headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    tells = []
    for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if h.get(hdr):
            tells.append(f"{hdr}: {h[hdr]}")
    if tells:
        return obs("info_disclosure", "server_banner", "LOW", "INFORMATIONAL", 0.5,
                   "เปิดเผยข้อมูลเซิร์ฟเวอร์/เฟรมเวิร์กผ่าน header", "; ".join(tells)[:160],
                   "ลบ/ปิด header ที่เปิดเผยเวอร์ชันซอฟต์แวร์")
    return None


# ---------------------------------------------------------------------------
# Rate limiting (อ่าน header เท่านั้น — ไม่ stress test)
# ---------------------------------------------------------------------------

def rate_limit_headers(headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    has_rl = any(k.startswith("x-ratelimit") or k in ("ratelimit-limit", "retry-after",
                 "ratelimit-remaining") for k in h)
    if not has_rl:
        return obs("misconfiguration", "rate_limit", "LOW", "INFORMATIONAL", 0.4,
                   "ไม่พบ rate-limit header (อาจไม่มีการจำกัดอัตรา — ตรวจเพิ่มเติม)", "",
                   "ใส่ rate limiting + ตอบ 429 พร้อม Retry-After")
    return None


# ---------------------------------------------------------------------------
# Input validation / mass assignment / excessive data
# ---------------------------------------------------------------------------

def sql_input(baseline_body: str, probe_body: str) -> Optional[Dict[str, Any]]:
    if not _HAS_WVA:
        return None
    o = wva_det.vp_sql(baseline_body, probe_body)
    if o:
        o = dict(o); o["category"] = "sqli"
    return o


def xss_input(marker: str, body: str, content_type: str = "") -> Optional[Dict[str, Any]]:
    if not _HAS_WVA:
        return None
    o = wva_det.vp_reflection(marker, body, content_type)
    if o:
        o = dict(o); o["category"] = "xss"
    return o


_MASS_ASSIGN_FIELDS = re.compile(
    r"(?i)^(is_?admin|role|roles|is_?superuser|is_?staff|verified|is_?verified|"
    r"account_?type|permission|permissions|owner_?id|user_?id|balance|credit|price|"
    r"approved|active|enabled|group)$")


def mass_assignment_static(request_fields: List[str]) -> Optional[Dict[str, Any]]:
    """วิเคราะห์ schema แบบ static — field ที่ไวต่อ privilege ถ้ารับจาก input = เสี่ยง mass assignment"""
    risky = [f for f in (request_fields or []) if _MASS_ASSIGN_FIELDS.match(str(f))]
    if risky:
        return obs("input_validation", "mass_assignment", "MEDIUM", "INFORMATIONAL", 0.45,
                   f"schema รับ field ที่ควบคุมสิทธิ์/สถานะ: {', '.join(risky)} "
                   "(อาจ mass assignment — ตรวจ allowlist ฝั่ง server)",
                   ", ".join(risky),
                   "ใช้ allowlist ของ field ที่แก้ได้ (bind เฉพาะที่อนุญาต) ไม่ bind ทั้ง object")
    return None


def excessive_data(response_fields: List[str]) -> Optional[Dict[str, Any]]:
    sensitive = [f for f in (response_fields or [])
                 if re.search(r"(?i)(password|passwd|secret|token|ssn|credit|card|"
                              r"api_?key|private|hash|salt)", str(f))]
    if sensitive:
        return obs("info_disclosure", "excessive_data", "MEDIUM", "POTENTIAL", 0.5,
                   f"response schema มี field อ่อนไหว: {', '.join(sensitive)}",
                   ", ".join(sensitive),
                   "ไม่คืน field ลับใน response, ใช้ DTO/serializer จำกัด field")
    return None
