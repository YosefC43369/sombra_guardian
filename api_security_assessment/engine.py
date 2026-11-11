# -*- coding: utf-8 -*-
"""api_security_assessment/engine.py — ตัวรันการประเมิน API (async, gated)

reuse ด่าน + SSRF จาก security_testing/scope_policy เหมือนทุกโมดูลออฟเฟนซ์ในโปรเจกต์:
  scope_policy.evaluate_target / normalize_target  ด่านอนุญาต
  security_testing._endpoint_from_target / _validate_destination / constants
ต่าง fetch จากของเดิมตรงที่รองรับ method/header/json (API ต้องใช้) แต่ "ทุกคำขอผ่าน
_validate_destination ก่อนเสมอ" (scope+public-IP+port) — ด่านเดียวกัน

detection เท่านั้น: ไม่ bypass auth, ไม่ forge token, ไม่ brute, ไม่ stress/DoS,
ไม่เข้าถึงข้อมูลบุคคลที่สาม — authz ใช้เฉพาะ test account + synthetic id ที่ operator ให้
PUT/PATCH/DELETE ปิดโดยดีฟอลต์ (เปิดได้เฉพาะ staging + disposable ผ่าน policy)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

from . import store, spec, analyzers

logger = logging.getLogger("modbot.api.engine")

try:
    from scope_policy import evaluate_target, normalize_target, TargetType
    from security_testing import (_endpoint_from_target, _validate_destination,
                                  _endpoint_url, REQUEST_TIMEOUT_SECONDS,
                                  MAX_RESPONSE_BYTES, USER_AGENT)
    from web_vulnerability_assessment import classify
    _HAS_DEPS = True
except Exception:  # pragma: no cover
    _HAS_DEPS = False

try:
    import httpx
    _HAS_HTTPX = True
except Exception:  # pragma: no cover
    _HAS_HTTPX = False

ProgressCb = Optional[Callable[[str], Awaitable[None]]]
NotifyCb = Optional[Callable[[Dict[str, Any], Dict[str, Any]], Awaitable[None]]]

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_POST_OK = {"POST"}                       # ใช้สำหรับ GraphQL/auth probe (bounded)
_STATE_CHANGING = {"PUT", "PATCH", "DELETE"}


async def _progress(cb, msg):
    if cb is not None:
        try:
            await cb(msg)
        except Exception:
            pass


def _now():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# API gated fetch (ผ่าน _validate_destination ทุกครั้ง)
# ---------------------------------------------------------------------------

async def _api_fetch(program_id, base_endpoint, host, ttype, path, *, method="GET",
                     headers=None, json_body=None, allow_state_changing=False):
    method = method.upper()
    if method in _STATE_CHANGING and not allow_state_changing:
        return None, "STATE_CHANGING_DISABLED"
    if method not in (_SAFE_METHODS | _POST_OK | _STATE_CHANGING):
        return None, "METHOD_NOT_ALLOWED"
    if not _HAS_HTTPX:
        return None, "HTTP_CLIENT_UNAVAILABLE"
    ep = dict(base_endpoint)
    ep["path"] = path or "/"
    reason = await _validate_destination(program_id, ep, host, ttype)
    if reason:
        return None, reason
    url = _endpoint_url(ep)
    hdr = {"User-Agent": USER_AGENT, "Accept": "application/json, */*"}
    if headers:
        hdr.update(headers)
    try:
        async with httpx.AsyncClient(follow_redirects=False,
                                     timeout=httpx.Timeout(REQUEST_TIMEOUT_SECONDS),
                                     max_redirects=0) as client:
            resp = await client.request(method, url, headers=hdr, json=json_body)
            body = resp.content[:MAX_RESPONSE_BYTES].decode(resp.encoding or "utf-8",
                                                            errors="replace")
            jb = None
            ct = resp.headers.get("content-type", "")
            if "json" in ct.lower():
                try:
                    jb = resp.json()
                except Exception:
                    jb = None
            return {"status": resp.status_code, "headers": dict(resp.headers),
                    "body": body, "json": jb, "location": resp.headers.get("location", "")}, None
    except Exception as e:
        return None, f"transport: {type(e).__name__}"


# ---------------------------------------------------------------------------
# finding assembly
# ---------------------------------------------------------------------------

def _finding(o, target, endpoint_path, method, test_case_id, req, resp, status):
    cls = classify.classify(o)
    return {"id": None, "category": o["category"], "rule": o["rule"],
            "test_case_id": test_case_id, "severity": cls["severity"],
            "state": o["state"], "confidence": cls["confidence"], "target": target,
            "endpoint": endpoint_path, "method": method, "param": o.get("param", "-"),
            "detail": o["detail"], "evidence": classify.sanitize(o.get("evidence", "")),
            "request": classify.sanitize(req, 160), "response_status": status,
            "response_excerpt": classify.sanitize(resp, 200),
            "recommendation": o.get("recommendation", ""), "timestamp": _now(),
            "ai_explanation": None}


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

async def run_assessment(program_id: int, target: str, actor: int, *,
                         spec_text: Optional[str] = None,
                         endpoints: Optional[List[Dict[str, Any]]] = None,
                         options: Optional[Dict[str, Any]] = None,
                         categories: Optional[List[str]] = None,
                         progress: ProgressCb = None, notify: NotifyCb = None,
                         path: Optional[str] = None) -> Dict[str, Any]:
    options = options or {}
    policy = store.get_policy(path)
    cats = [c for c in (categories or policy.get("categories", []))]
    rec = store.create_assessment(program_id, target, actor, cats, path)
    aid = rec["id"]

    if not policy.get("enabled", True):
        return _finish(aid, "failed", "API_ASSESS_DISABLED", path)
    if not _HAS_DEPS:
        return _finish(aid, "failed", "DEPENDENCIES_UNAVAILABLE", path)

    store.update_assessment(aid, lambda r: r.__setitem__("status", "running"), path)

    # ---- GATE ----
    await _progress(progress, f"🔐 ตรวจสิทธิ์: {target}")
    decision = evaluate_target(program_id, target)
    if not decision.allowed:
        return _finish(aid, "denied", f"SCOPE_DENY:{decision.reason}", path)
    normalized = normalize_target(target)
    if normalized is None:
        return _finish(aid, "denied", "TARGET_INVALID", path)
    base_ep, err = _endpoint_from_target(normalized)
    if err:
        return _finish(aid, "denied", err, path)
    host = base_ep["host"]
    ttype = normalized.target_type
    base_path = base_ep["path"].rstrip("/")

    # ---- รวบ endpoints ----
    eps: List[Dict[str, Any]] = []
    api_info = {}
    if spec_text:
        parsed = spec.from_spec(spec_text)
        if parsed.get("ok"):
            eps = parsed["endpoints"]
            api_info = parsed.get("api_info", {})
    if not eps and endpoints:
        eps = spec.dedupe(endpoints)
    if not eps:
        stored = store.get_spec(host, path)
        if stored:
            eps = stored["endpoints"]
            api_info = stored.get("api_info", {})
    if not eps:
        eps = [{"path": base_path or "/", "method": "GET", "parameters": [],
                "auth_required": None, "request_fields": [], "response_fields": [],
                "tags": [], "deprecated": False, "version": None,
                "sensitive": False, "admin": False, "source": "base"}]
    eps = eps[: int(policy.get("max_endpoints", 80))]

    findings: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    made = [0]
    checks = [0]
    max_req = int(policy.get("max_requests", 60))
    allow_sc = bool(policy.get("allow_state_changing", False))

    async def fetch(path_, method="GET", headers=None, json_body=None):
        if made[0] >= max_req:
            return None
        made[0] += 1
        resp, reason = await _api_fetch(program_id, base_ep, host, ttype, path_,
                                        method=method, headers=headers, json_body=json_body,
                                        allow_state_changing=allow_sc)
        if reason:
            errors.append({"path": (path_ or "")[:80], "reason": reason})
            return None
        return resp

    async def emit(o, ep_path, method, tc_id, req, resp, status):
        f = _finding(o, target, ep_path, method, tc_id, req, resp, status)
        f["id"] = len(findings) + 1
        if policy.get("use_ai") and f["severity"] in ("HIGH", "CRITICAL"):
            f["ai_explanation"] = await _ai_explain(f)
        findings.append(f)
        if notify is not None and _sev_ge(f["severity"], policy.get("notify_min_severity", "HIGH")):
            try:
                await notify(f, rec)
            except Exception:
                logger.exception("API immediate notify failed")

    def _cancelled():
        return store.is_cancelled(aid, path)

    # ---- STATIC analysis (ไม่ยิงเน็ต) ----
    for e in eps:
        if "input_validation" in cats:
            o = analyzers.mass_assignment_static(e.get("request_fields", []))
            if o:
                await emit(o, e["path"], e["method"], "API-INPUT-MASS", "static schema", "", 0)
        if "info_disclosure" in cats:
            o = analyzers.excessive_data(e.get("response_fields", []))
            if o:
                await emit(o, e["path"], e["method"], "API-INFO-EXCESS", "static schema", "", 0)

    # ---- BASE-level config checks ----
    checks[0] += 1
    base = await fetch(base_path or "/")
    if base:
        if "misconfiguration" in cats:
            for o in (analyzers.security_headers(base["headers"]),
                      analyzers.rate_limit_headers(base["headers"])):
                if o:
                    await emit(o, base_path or "/", "GET", "API-MISC", "GET", "", base["status"])
        if "info_disclosure" in cats:
            for o in (analyzers.server_disclosure(base["headers"]),
                      analyzers.verbose_error(base["body"])):
                if o:
                    await emit(o, base_path or "/", "GET", "API-INFO", "GET", base["body"], base["status"])
        if "cors" in cats:
            origin = options.get("origin", "https://evil.api-probe.invalid")
            rc = await fetch(base_path or "/", headers={"Origin": origin})
            if rc:
                o = analyzers.cors(origin, rc["headers"].get("access-control-allow-origin", ""),
                                   rc["headers"].get("access-control-allow-credentials", ""))
                if o:
                    await emit(o, base_path or "/", "GET", "API-CORS-001", "Origin: <forged>",
                               "", rc["status"])

    # ---- JWT inspection (ถ้า operator ให้ token มา) ----
    if "authentication" in cats and options.get("token"):
        info = analyzers.inspect_jwt(options["token"])
        o = analyzers.jwt_observation(info) if info else None
        if o:
            await emit(o, base_path or "/", "-", "API-AUTH-JWT", "jwt inspect", "", 0)

    # ---- ENDPOINT-level checks ----
    for e in eps:
        if _cancelled():
            return _finish(aid, "cancelled", "operator cancelled", path,
                           findings=findings, errors=errors, made=made[0], checks=checks[0],
                           endpoints=len(eps), api_info=api_info)
        full = _join(base_path, _concretize(e["path"], options.get("synthetic_id", "1")))
        checks[0] += 1

        # auth enforcement: GET โดยไม่มี token
        if "authentication" in cats and e["method"] in ("GET", "HEAD"):
            r = await fetch(full, method="GET")
            if r:
                o = analyzers.auth_enforcement(e, r["status"], r["body"])
                if o:
                    await emit(o, e["path"], e["method"], "API-AUTH-001", "GET (no token)",
                               r["body"], r["status"])

        # input validation (SQLi/XSS marker บน param แรก)
        if e.get("parameters") and ("sqli" in cats or "xss" in cats or "input_validation" in cats):
            pname = next((p["name"] for p in e["parameters"] if p.get("in") in ("query", None)),
                         policy.get("param_name", "q"))
            if "sqli" in cats:
                clean = await fetch(_q(full, f"{pname}=apitest1"))
                quote = await fetch(_q(full, f"{pname}=apitest1%27"))
                if clean and quote:
                    o = analyzers.sql_input(clean["body"], quote["body"])
                    if o:
                        o["param"] = pname
                        await emit(o, e["path"], e["method"], "API-SQLI-001",
                                   f"{pname}=apitest1'", quote["body"], quote["status"])
            if "xss" in cats:
                marker = "apiXSS777"
                r = await fetch(_q(full, f"{pname}={marker}"))
                if r:
                    o = analyzers.xss_input(marker, r["body"], r["headers"].get("content-type", ""))
                    if o:
                        o["param"] = pname
                        await emit(o, e["path"], e["method"], "API-XSS-001",
                                   f"{pname}={marker}", r["body"], r["status"])

        # GraphQL
        if "graphql" in cats and _graphqlish(e["path"]):
            q = {"query": "query{__schema{types{name}}}"}
            r = await fetch(full, method="POST", json_body=q)
            if r:
                o = analyzers.graphql_introspection(r.get("json"))
                if o:
                    await emit(o, e["path"], "POST", "API-GQL-001",
                               "introspection query", "", r["status"])
                oe = analyzers.graphql_error_disclosure(r.get("body", ""))
                if oe:
                    await emit(oe, e["path"], "POST", "API-GQL-002", "introspection query",
                               r["body"], r["status"])

    # ---- Authorization (BOLA/BFLA) — เฉพาะเมื่อมี 2 test token + object endpoint ----
    if "authorization" in cats and options.get("token_a") and options.get("token_b") \
            and options.get("object_endpoint"):
        await _run_authz(fetch, emit, base_path, options)

    return _finish(aid, "completed", None, path, findings=findings, errors=errors,
                   made=made[0], checks=checks[0], endpoints=len(eps), api_info=api_info)


async def _run_authz(fetch, emit, base_path, options):
    """BOLA/BFLA: owner token เข้าถึง object ของตัวเอง, other token เข้าถึง object เดียวกัน"""
    obj = options["object_endpoint"]            # เช่น /api/v1/orders/{id}
    sid = str(options.get("synthetic_id", "1"))
    full = _join(base_path, _concretize(obj, sid))
    ha = {"Authorization": f"Bearer {options['token_a']}"}
    hb = {"Authorization": f"Bearer {options['token_b']}"}
    ra = await fetch(full, method="GET", headers=ha)
    rb = await fetch(full, method="GET", headers=hb)
    if ra and rb:
        o = analyzers.authz_compare(obj, "GET", ra["status"], ra["body"],
                                    rb["status"], rb["body"], kind="BOLA")
        if o:
            await emit(o, obj, "GET", "API-AUTHZ-001",
                       "two test accounts compared", "", rb["status"])


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

import re as _re


def _graphqlish(path: str) -> bool:
    return bool(_re.search(r"(?i)graphql|/gql\b", path or ""))


def _concretize(path: str, sid: str) -> str:
    return _re.sub(r"\{[^}]+\}|/:(\w+)", lambda m: "/" + sid if m.group(0).startswith("/:")
                   else sid, path or "")


def _join(base: str, path: str) -> str:
    base = (base or "").rstrip("/")
    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return (base + path) or "/"


def _q(path, extra):
    return f"{path}{'&' if '?' in path else '?'}{extra}"


def _sev_ge(a, b):
    order = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return order.get(a, 0) >= order.get(b, 0)


async def _ai_explain(finding):
    try:
        import gemini
    except Exception:
        return None
    prompt = ("อธิบายสั้น ๆ (ไทย) ว่า API finding นี้คืออะไร ทำไมระดับนี้ และวิธีแก้ "
              "ห้ามอ้างว่า exploit สำเร็จถ้าเป็นแค่ indicator:\n"
              f"category={finding['category']} severity={finding['severity']} "
              f"state={finding['state']} detail={finding['detail']} evidence={finding['evidence']}")
    try:
        ok, text = await gemini.ask_gemini(prompt)
        return text[:600] if ok else None
    except Exception:
        return None


def _finish(aid, status, reason, path, findings=None, errors=None, made=0, checks=0,
            endpoints=0, api_info=None):
    counts = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL",
                             "CONFIRMED", "POTENTIAL", "NOT_REPRODUCIBLE")}
    for f in (findings or []):
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        counts[f["state"]] = counts.get(f["state"], 0) + 1

    def _mut(r):
        r.update({"status": status, "denied_reason": reason, "finished_iso": store.iso()})
        if findings is not None:
            r["findings"] = findings
            r["errors"] = errors or []
            r["requests_made"] = made
            r["checks_executed"] = checks
            r["endpoints_analyzed"] = endpoints
            r["counts"] = counts
            if api_info:
                r["api_info"] = api_info
    store.update_assessment(aid, _mut, path)
    return store.get_assessment(aid, path)
