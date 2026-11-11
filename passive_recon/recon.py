# -*- coding: utf-8 -*-
"""passive_recon/recon.py — เวิร์กโฟลว์หลักของ passive reconnaissance

ประสาน collector ทั้งหมดเป็นรายงานเดียว:
  normalize -> เก็บข้อมูล (ขนานที่เป็นอิสระ) -> correlate -> dedupe -> confidence -> report

เปิด AsyncHTTPClient ของโปรเจกต์ (reuse) ครั้งเดียวต่อเป้าหมาย และส่งต่อให้ทุก collector
เพื่อให้ rate-limit/retry รวมศูนย์ ไม่ยิงถี่จนโดนบล็อก
"""

from __future__ import annotations

import time
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

from . import parse, collectors, safehttp

logger = logging.getLogger("modbot.passive_recon.recon")

try:
    from osint.utils.async_http import AsyncHTTPClient
    _HAS_CLIENT = True
except Exception:  # pragma: no cover
    AsyncHTTPClient = None  # type: ignore
    _HAS_CLIENT = False

# เพดานเพื่อความสุภาพต่อแหล่งข้อมูลสาธารณะ
HTTP_RATE = 4.0

ProgressCb = Optional[Callable[[str], Awaitable[None]]]


async def _progress(cb: ProgressCb, msg: str) -> None:
    if cb is not None:
        try:
            await cb(msg)
        except Exception:
            pass


def _strip_internal(cat: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in cat.items() if not k.startswith("_")}


async def run_recon(raw_target: str, progress: ProgressCb = None) -> Dict[str, Any]:
    """รัน passive recon หนึ่งเป้าหมาย คืน report dict (พร้อม render ต่อได้)"""
    started = time.monotonic()
    norm = parse.normalize_target(raw_target)
    if norm is None:
        return {"ok": False, "input": raw_target,
                "error": "เป้าหมายไม่ถูกต้อง (ต้องเป็น URL/โดเมนสาธารณะ)",
                "collected_at": datetime.now(timezone.utc).isoformat()}

    domain = norm["domain"]
    if not _HAS_CLIENT:
        return {"ok": False, "input": raw_target,
                "error": "OSINT HTTP client ไม่พร้อม (ต้องมี httpx)",
                "target": norm}

    await _progress(progress, f"🔎 เริ่ม passive recon: {domain}")

    categories: Dict[str, Dict[str, Any]] = {}
    errors: List[Dict[str, str]] = []

    async with AsyncHTTPClient(rate=HTTP_RATE) as client:
        # เฟส 1: หมวดที่เป็นอิสระต่อกัน — รันขนาน
        await _progress(progress, "📡 เก็บ DNS / WHOIS-RDAP / subdomains / TLS / HTTP…")
        domain_t = collectors.collect_domain(client, domain, norm["registered"])
        dns_t = collectors.collect_dns(client, domain)
        subs_t = collectors.collect_subdomains(client, domain, norm["registered"])
        tls_t = collectors.collect_tls(domain)
        httptech_t = collectors.collect_http_and_tech(domain, norm["url"])

        domain_c, dns_c, subs_c, tls_c, httptech_c = await asyncio.gather(
            domain_t, dns_t, subs_t, tls_t, httptech_t, return_exceptions=True)

        categories["domain"] = _coerce(domain_c, "domain", errors)
        dns_c = _coerce(dns_c, "dns", errors)
        categories["dns"] = dns_c
        categories["subdomains"] = _coerce(subs_c, "subdomains", errors)
        categories["tls"] = _coerce(tls_c, "tls", errors)

        httptech_c = httptech_c if isinstance(httptech_c, dict) else {}
        http_c = httptech_c.get("http") or collectors._cat("http", "error", reason="ยิงไม่สำเร็จ")
        tech_c = httptech_c.get("technology") or collectors._cat("technology", "empty")
        categories["http"] = http_c
        categories["technology"] = tech_c

        # เฟส 2: infrastructure (ต้องรู้ IP จาก DNS ก่อน; ถ้าไม่มี resolve ตรง)
        await _progress(progress, "🌐 วิเคราะห์โครงสร้างพื้นฐาน (ASN/ISP/geo)…")
        ips = dns_c.get("_ips") or []
        if not ips:
            safety = await safehttp.host_safety(domain)
            ips = safety.get("ips", [])
        infra_c = await collectors.collect_infrastructure(client, ips)
        categories["infrastructure"] = _coerce(infra_c, "infrastructure", errors)

    # เฟส 3: correlate -> security exposure (เชิงข้อมูล)
    sec_c = collectors.collect_security(categories["http"], categories["technology"],
                                        dns_c, categories["tls"])
    categories["security"] = sec_c

    # เก็บ error ของหมวดที่ล้มเหลว
    for name, cat in categories.items():
        if cat.get("status") == "error":
            errors.append({"category": name, "reason": cat.get("reason", "ไม่ทราบ")})

    report = {
        "ok": True,
        "input": raw_target,
        "target": norm,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "confidence": {k: v.get("confidence", 0.0) for k, v in categories.items()},
        "categories": {k: _strip_internal(v) for k, v in categories.items()},
        "errors": errors,
        "notes": ("passive-only · ไม่มีการสแกน port/brute-force/exploit · "
                  "SSRF-guarded · ข้อมูล security เป็นตัวชี้วัดเชิงข้อมูล ไม่ใช่ช่องโหว่ยืนยัน"),
    }
    await _progress(progress, f"✅ เสร็จ ({report['duration_ms']}ms)")
    return report


def _coerce(result, category: str, errors: List[Dict[str, str]]) -> Dict[str, Any]:
    """ถ้า collector โยน exception (จาก gather return_exceptions) -> ทำเป็น error cat"""
    if isinstance(result, dict):
        return result
    reason = f"{type(result).__name__}: {result}" if isinstance(result, BaseException) else "unknown"
    logger.warning("passive_recon collector %s failed: %s", category, reason)
    errors.append({"category": category, "reason": reason})
    return collectors._cat(category, "error", reason=reason)


# ---------------------------------------------------------------------------
# render (ส่งต่อไปยัง parse)
# ---------------------------------------------------------------------------

def render(report: Dict[str, Any], fmt: str = "markdown") -> str:
    if not report.get("ok"):
        return f"❌ {report.get('error','ล้มเหลว')} (input: {report.get('input')})"
    fmt = (fmt or "markdown").lower()
    if fmt == "json":
        return parse.render_json(report)
    if fmt in ("txt", "text"):
        return parse.render_txt(report)
    return parse.render_markdown(report)


def summary_line(report: Dict[str, Any]) -> str:
    """สรุปสั้นหนึ่งบรรทัดสำหรับตอบในแชต"""
    if not report.get("ok"):
        return f"❌ {report.get('error')}"
    c = report["categories"]
    subs = len(c.get("subdomains", {}).get("records", []))
    tech = len(c.get("technology", {}).get("records", []))
    dns = len(c.get("dns", {}).get("records", []))
    sx = len(c.get("security", {}).get("records", []))
    dom = report["target"]["domain"]
    return (f"🛰 {dom}: DNS {dns} · subdomains {subs} · tech {tech} · "
            f"security indicators {sx} · {report['duration_ms']}ms")
