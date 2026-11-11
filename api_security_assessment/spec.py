# -*- coding: utf-8 -*-
"""api_security_assessment/spec.py — แปลงสเปค API เป็นรายการ endpoint มาตรฐาน (pure)

รองรับ: OpenAPI v2(Swagger)/v3 (JSON หรือ YAML), Postman Collection (JSON),
base URL เปล่า ๆ, และรายการ endpoint จากโมดูล recon เดิม (list ของ dict)

endpoint มาตรฐาน:
  {path, method, parameters:[{name,in,required,type}], auth_required(bool|None),
   request_fields:[...], response_fields:[...], tags:[...], deprecated(bool),
   version, sensitive(bool), admin(bool), source}

ไม่ยิงเน็ต/ไม่เดา endpoint ที่ไม่มีในสเปค (ไม่ brute-force) — แปลงจากที่ให้มาเท่านั้น
"""

from __future__ import annotations

import re
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("modbot.api.spec")

try:
    import yaml
    _HAS_YAML = True
except Exception:  # pragma: no cover
    _HAS_YAML = False

_METHODS = ("get", "post", "put", "patch", "delete", "options", "head")

_SENSITIVE_RE = re.compile(
    r"(?i)\b(admin|internal|debug|token|password|passwd|secret|api[_-]?key|"
    r"cred|user|account|payment|billing|invoice|order|card|ssn|private|export|"
    r"delete|config|setting|role|permission)\b")
_ADMIN_RE = re.compile(r"(?i)(admin|administrator|superuser|root|manage|internal|backoffice)")


def _flags(path: str, tags: List[str]) -> Dict[str, bool]:
    blob = path + " " + " ".join(tags or [])
    return {"sensitive": bool(_SENSITIVE_RE.search(blob)),
            "admin": bool(_ADMIN_RE.search(blob))}


def _version_of(path: str) -> Optional[str]:
    m = re.search(r"/v(\d+)(?:[./]|$)", path)
    return f"v{m.group(1)}" if m else None


def parse_text(text: str) -> Optional[Dict[str, Any]]:
    """รับข้อความ JSON หรือ YAML -> dict (None ถ้า parse ไม่ได้)"""
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    if _HAS_YAML:
        try:
            d = yaml.safe_load(text)
            return d if isinstance(d, dict) else None
        except Exception:
            return None
    return None


def detect_kind(doc: Dict[str, Any]) -> str:
    if not isinstance(doc, dict):
        return "unknown"
    if "swagger" in doc:
        return "openapi2"
    if "openapi" in doc:
        return "openapi3"
    if "info" in doc and ("item" in doc or (isinstance(doc.get("info"), dict)
                                            and "_postman_id" in doc.get("info", {}))):
        return "postman"
    if "item" in doc:
        return "postman"
    return "unknown"


# ---------------------------------------------------------------------------
# OpenAPI (v2 + v3)
# ---------------------------------------------------------------------------

def _schema_fields(schema: Dict[str, Any], depth: int = 0) -> List[str]:
    if not isinstance(schema, dict) or depth > 4:
        return []
    out = []
    props = schema.get("properties")
    if isinstance(props, dict):
        out.extend(props.keys())
    return out


def _openapi_endpoints(doc: Dict[str, Any], version_kind: str) -> List[Dict[str, Any]]:
    endpoints = []
    api_version = (doc.get("info", {}) or {}).get("version")
    paths = doc.get("paths", {}) or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared_params = item.get("parameters", []) or []
        for method, op in item.items():
            if method.lower() not in _METHODS or not isinstance(op, dict):
                continue
            params = []
            for p in (shared_params + (op.get("parameters", []) or [])):
                if isinstance(p, dict) and p.get("name"):
                    params.append({"name": p["name"], "in": p.get("in", "query"),
                                   "required": bool(p.get("required")),
                                   "type": (p.get("schema", {}) or {}).get("type") or p.get("type")})
            # auth: security ที่ระดับ op (v2/v3) หรือ global
            sec = op.get("security", doc.get("security"))
            auth_required = None if sec is None else bool(sec)
            # request/response fields
            req_fields = []
            if version_kind == "openapi3":
                body = ((op.get("requestBody", {}) or {}).get("content", {}) or {})
                for ct, media in body.items():
                    req_fields.extend(_schema_fields(media.get("schema", {}) or {}))
            else:
                for p in (op.get("parameters", []) or []):
                    if p.get("in") == "body":
                        req_fields.extend(_schema_fields(p.get("schema", {}) or {}))
            resp_fields = []
            responses = op.get("responses", {}) or {}
            ok = responses.get("200") or responses.get(200) or {}
            if isinstance(ok, dict):
                if version_kind == "openapi3":
                    for ct, media in (ok.get("content", {}) or {}).items():
                        resp_fields.extend(_schema_fields(media.get("schema", {}) or {}))
                else:
                    resp_fields.extend(_schema_fields(ok.get("schema", {}) or {}))
            tags = op.get("tags", []) or []
            fl = _flags(path, tags)
            endpoints.append({
                "path": path, "method": method.upper(), "parameters": params,
                "auth_required": auth_required, "request_fields": sorted(set(req_fields)),
                "response_fields": sorted(set(resp_fields)), "tags": tags,
                "deprecated": bool(op.get("deprecated")),
                "version": _version_of(path) or api_version,
                "sensitive": fl["sensitive"], "admin": fl["admin"], "source": version_kind,
            })
    return endpoints


# ---------------------------------------------------------------------------
# Postman Collection
# ---------------------------------------------------------------------------

def _postman_endpoints(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    def _walk(items):
        for it in (items or []):
            if not isinstance(it, dict):
                continue
            if "item" in it:
                _walk(it["item"])
                continue
            req = it.get("request")
            if not isinstance(req, dict):
                continue
            method = str(req.get("method", "GET")).upper()
            url = req.get("url")
            if isinstance(url, dict):
                raw = url.get("raw") or ""
                path = "/" + "/".join(url.get("path", [])) if url.get("path") else _path_of(raw)
            else:
                path = _path_of(str(url or ""))
            auth = req.get("auth")
            headers = req.get("header", []) or []
            has_auth_header = any(isinstance(h, dict) and h.get("key", "").lower() == "authorization"
                                  for h in headers)
            auth_required = True if (auth or has_auth_header) else None
            body = req.get("body", {}) or {}
            req_fields = []
            if body.get("mode") == "raw":
                parsed = parse_text(body.get("raw", ""))
                if isinstance(parsed, dict):
                    req_fields = list(parsed.keys())
            fl = _flags(path, [])
            out.append({
                "path": path, "method": method, "parameters": [],
                "auth_required": auth_required, "request_fields": sorted(set(req_fields)),
                "response_fields": [], "tags": [], "deprecated": False,
                "version": _version_of(path), "sensitive": fl["sensitive"],
                "admin": fl["admin"], "source": "postman",
            })

    _walk(doc.get("item", []))
    return out


def _path_of(raw: str) -> str:
    raw = re.sub(r"\{\{[^}]+\}\}", "", raw or "")
    m = re.search(r"https?://[^/]+(/[^?#]*)", raw)
    if m:
        return m.group(1) or "/"
    m2 = re.match(r"^(/[^?#]*)", raw)
    return m2.group(1) if m2 else (raw or "/")


# ---------------------------------------------------------------------------
# entry
# ---------------------------------------------------------------------------

def from_spec(text: str) -> Dict[str, Any]:
    """parse ข้อความสเปค -> {ok, kind, endpoints, api_info, reason}"""
    doc = parse_text(text)
    if doc is None:
        return {"ok": False, "reason": "parse ไม่ได้ (ต้องเป็น JSON/YAML)", "endpoints": []}
    kind = detect_kind(doc)
    if kind in ("openapi2", "openapi3"):
        eps = _openapi_endpoints(doc, kind)
        info = doc.get("info", {})
    elif kind == "postman":
        eps = _postman_endpoints(doc)
        info = doc.get("info", {})
    else:
        return {"ok": False, "reason": "ไม่รู้จักชนิดสเปค (OpenAPI/Swagger/Postman)", "endpoints": []}
    return {"ok": True, "kind": kind, "endpoints": dedupe(eps),
            "api_info": {"title": info.get("title"), "version": info.get("version")}}


def from_endpoint_list(items: List[Dict[str, Any]], source: str = "recon") -> List[Dict[str, Any]]:
    """รับ endpoint จากโมดูล recon เดิม (list ของ {path/url, method?})"""
    out = []
    for it in (items or []):
        path = it.get("path") or _path_of(it.get("url", "")) or it.get("value", "")
        if not path:
            continue
        fl = _flags(path, [])
        out.append({"path": path, "method": str(it.get("method", "GET")).upper(),
                    "parameters": [], "auth_required": None, "request_fields": [],
                    "response_fields": [], "tags": [], "deprecated": False,
                    "version": _version_of(path), "sensitive": fl["sensitive"],
                    "admin": fl["admin"], "source": source})
    return dedupe(out)


def dedupe(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for e in endpoints:
        key = (e["method"], e["path"])
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def classify_endpoints(endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "total": len(endpoints),
        "by_method": _count(endpoints, "method"),
        "sensitive": [f"{e['method']} {e['path']}" for e in endpoints if e["sensitive"]][:50],
        "admin": [f"{e['method']} {e['path']}" for e in endpoints if e["admin"]][:50],
        "deprecated": [f"{e['method']} {e['path']}" for e in endpoints if e["deprecated"]][:50],
        "no_auth_documented": [f"{e['method']} {e['path']}" for e in endpoints
                               if e["auth_required"] is False][:50],
        "with_object_id": [f"{e['method']} {e['path']}" for e in endpoints
                           if re.search(r"\{[^}]+\}|/:\w+|/\d+(?:/|$)", e["path"])][:50],
    }


def _count(items, key):
    out = {}
    for i in items:
        out[i[key]] = out.get(i[key], 0) + 1
    return out
