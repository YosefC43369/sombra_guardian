# -*- coding: utf-8 -*-
"""vuln_probe/engine.py — ยิง safe-validation probe ผ่านด่าน scope+SSRF ของ security_testing

reuse ส่วนที่เป็น "ความปลอดภัยสำคัญ" จาก security_testing ทั้งหมด:
  evaluate_target / normalize_target / _endpoint_from_target /
  resolve_and_validate / _validate_destination / constants (timeout/UA/limit)
engine มีเพียง fetch บาง ๆ ที่รับ custom query/header (ที่ engine passive ไม่ต้องใช้)
แต่ทุก request "ต้องผ่าน _validate_destination ก่อนเสมอ" — ด่านเดียวกับของเดิม

ทุก probe: ไม่ทำลายข้อมูล, คำขอจำกัดจำนวน, detection ล้วน (ไม่ extract/ไม่ยิงซ้ำรัว)
ผลเป็น "indicator เชิงข้อมูล" สำหรับยกเข้า observation → review gate ของ redteam
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from . import store, probes

logger = logging.getLogger("modbot.vuln_probe.engine")

# reuse ด่าน + ไพรมิทีฟจาก security_testing / scope_policy
try:
    from scope_policy import evaluate_target, normalize_target, get_program, TargetType
    from security_testing import (resolve_and_validate, _endpoint_from_target,
                                  _validate_destination, _endpoint_url,
                                  REQUEST_TIMEOUT_SECONDS, MAX_RESPONSE_BYTES, USER_AGENT)
    _HAS_DEPS = True
except Exception:  # pragma: no cover
    _HAS_DEPS = False

try:
    import httpx
    _HAS_HTTPX = True
except Exception:  # pragma: no cover
    _HAS_HTTPX = False

ProgressCb = Optional[Callable[[str], Awaitable[None]]]


async def _progress(cb: ProgressCb, msg: str):
    if cb is not None:
        try:
            await cb(msg)
        except Exception:
            pass


async def _fetch(program_id: int, endpoint: Dict[str, Any], original_host: str,
                 target_type: str, extra_headers: Optional[Dict[str, str]] = None
                 ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """ยิงหนึ่งคำขอ (GET, ไม่ follow redirect) หลัง _validate_destination ผ่าน

    คืน ({status, headers, body, location}, None) หรือ (None, reason)
    """
    reason = await _validate_destination(program_id, endpoint, original_host, target_type)
    if reason:
        return None, reason
    if not _HAS_HTTPX:
        return None, "HTTP_CLIENT_UNAVAILABLE"
    url = _endpoint_url(endpoint)
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if extra_headers:
        headers.update(extra_headers)
    try:
        async with httpx.AsyncClient(follow_redirects=False,
                                     timeout=httpx.Timeout(REQUEST_TIMEOUT_SECONDS),
                                     max_redirects=0) as client:
            resp = await client.get(url, headers=headers)
            body = resp.content[:MAX_RESPONSE_BYTES].decode(resp.encoding or "utf-8",
                                                            errors="replace")
            return ({"status": resp.status_code, "headers": dict(resp.headers),
                     "body": body, "location": resp.headers.get("location", "")}, None)
    except Exception as e:
        return None, f"transport: {type(e).__name__}"


def _with_query(base_path: str, extra: str) -> str:
    sep = "&" if "?" in base_path else "?"
    return f"{base_path}{sep}{extra}"


async def run_probe(program_id: int, target: str, actor: int,
                    checks: Optional[List[str]] = None, progress: ProgressCb = None,
                    path: Optional[str] = None) -> Dict[str, Any]:
    """รัน safe-validation หนึ่งเป้าหมาย — gate ก่อนทุกอย่าง, คืน run record"""
    policy = store.get_policy(path)
    rec = store.create_run(program_id, target, actor, path)
    rid = rec["id"]

    if not policy.get("enabled", True):
        store.update_run(rid, lambda r: r.update(
            {"status": "failed", "denied_reason": "VULN_PROBE_DISABLED",
             "finished_iso": store.iso()}), path)
        return store.get_run(rid, path)
    if not _HAS_DEPS:
        store.update_run(rid, lambda r: r.update(
            {"status": "failed", "denied_reason": "DEPENDENCIES_UNAVAILABLE",
             "finished_iso": store.iso()}), path)
        return store.get_run(rid, path)

    selected = [c for c in (checks or policy.get("checks", [])) if c in
                ("reflection", "sqli", "ssti", "open_redirect", "cors", "takeover")]
    store.update_run(rid, lambda r: r.__setitem__("status", "running"), path)

    # ---- THE GATE (ไม่มีอะไรแตะเน็ตก่อนบรรทัดนี้) ----
    await _progress(progress, f"🔐 ตรวจสิทธิ์: {target}")
    decision = evaluate_target(program_id, target)
    if not decision.allowed:
        store.update_run(rid, lambda r: r.update(
            {"status": "denied", "denied_reason": f"SCOPE_DENY:{decision.reason}",
             "finished_iso": store.iso()}), path)
        await _progress(progress, f"⛔ ปฏิเสธ: {decision.reason}")
        return store.get_run(rid, path)

    normalized = normalize_target(target)
    if normalized is None:
        store.update_run(rid, lambda r: r.update(
            {"status": "denied", "denied_reason": "TARGET_INVALID",
             "finished_iso": store.iso()}), path)
        return store.get_run(rid, path)
    endpoint, err = _endpoint_from_target(normalized)
    if err:
        store.update_run(rid, lambda r: r.update(
            {"status": "denied", "denied_reason": err,
             "finished_iso": store.iso()}), path)
        return store.get_run(rid, path)

    host = endpoint["host"]
    ttype = normalized.target_type
    base_path = endpoint["path"]
    max_req = int(policy.get("max_requests", 12))
    param = policy.get("param_name", "q")

    indicators: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    made = [0]

    async def _do(ep_path: str, headers=None) -> Optional[Dict[str, Any]]:
        if made[0] >= max_req:
            return None
        made[0] += 1
        ep = dict(endpoint)
        ep["path"] = ep_path
        resp, reason = await _fetch(program_id, ep, host, ttype, headers)
        if reason:
            errors.append({"path": ep_path[:80], "reason": reason})
            return None
        return resp

    # baseline
    await _progress(progress, "🧪 baseline + probes…")
    base = await _do(base_path)
    base_body = base["body"] if base else ""

    if "takeover" in selected and base:
        ind = probes.analyze_takeover(base["status"], base_body)
        if ind:
            indicators.append(ind)

    if "reflection" in selected:
        marker = probes.new_marker()
        r = await _do(_with_query(base_path, f"{param}={marker}"))
        if r:
            ind = probes.analyze_reflection(marker, r["body"], r["headers"].get("content-type", ""))
            if ind:
                indicators.append(ind)

    if "sqli" in selected:
        marker = probes.new_marker("s")
        clean = await _do(_with_query(base_path, f"{param}={marker}"))
        quote = await _do(_with_query(base_path, f"{param}={marker}%27"))
        if clean and quote:
            ind = probes.analyze_sql_error(clean["body"], quote["body"])
            if ind:
                indicators.append(ind)

    if "ssti" in selected:
        prefix = probes.new_marker("t")
        r = await _do(_with_query(base_path, f"{param}={prefix}%7b%7b7*7%7d%7d"))  # {{7*7}}
        if r:
            ind = probes.analyze_ssti(prefix, "49", r["body"])
            if ind:
                indicators.append(ind)

    if "open_redirect" in selected:
        injected = policy.get("injected_host", "oob.sombra-probe.invalid")
        for rp in policy.get("redirect_params", [])[:4]:
            if made[0] >= max_req:
                break
            r = await _do(_with_query(base_path, f"{rp}=https://{injected}/"))
            if r:
                ind = probes.analyze_open_redirect(r["status"], r["location"], injected)
                if ind:
                    indicators.append(ind)
                    break

    if "cors" in selected:
        sent = "https://evil.sombra-probe.invalid"
        r = await _do(base_path, headers={"Origin": sent})
        if r:
            ind = probes.analyze_cors(sent, r["headers"].get("access-control-allow-origin", ""),
                                      r["headers"].get("access-control-allow-credentials", ""))
            if ind:
                indicators.append(ind)

    status = "completed"
    store.update_run(rid, lambda r: r.update(
        {"status": status, "indicators": indicators, "requests_made": made[0],
         "errors": errors, "finished_iso": store.iso(),
         "worst_severity": probes.highest(indicators) if indicators else "NONE"}), path)
    await _progress(progress, f"✅ เสร็จ: {len(indicators)} indicator / {made[0]} คำขอ")
    return store.get_run(rid, path)
