# -*- coding: utf-8 -*-
"""active_scan/engine.py — ประสานการสแกน active หนึ่งงานแบบครบวงจร

ลำดับงาน (ทุกขั้นหลัง guard ผ่านแล้วเท่านั้น):
  1) guard.authorize_and_resolve  — scope gate + resolve + public-IP filter
  2) เพดานงาน (hosts * ports <= max_total_connects)
  3) scanner.scan_host ต่อ host (concurrency/rate ตาม policy)
  4) (เป้าหมายโดเมน) ลอง DNS AXFR ต่อ nameserver — best-effort, ปลอดภัยถ้าถูกปฏิเสธ
  5) สรุปผล + บันทึกลง store

ไม่มีขั้นใดยิงเป้าหมายก่อน guard ผ่าน; ทุกขั้นห่อ error เพื่อไม่ให้สแกนล้มทั้งงาน
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional

from . import store, guard, scanner

logger = logging.getLogger("modbot.active_scan.engine")

ProgressCb = Optional[Callable[[str], Awaitable[None]]]


async def _progress(cb: ProgressCb, msg: str) -> None:
    if cb is not None:
        try:
            await cb(msg)
        except Exception:
            pass


def resolve_profile(profile: str) -> List[int]:
    return scanner.PROFILES.get(profile, scanner.PROFILES["quick"])


async def run_scan(program_id: int, target: str, actor: int, profile: str = "quick",
                   progress: ProgressCb = None, path: Optional[str] = None
                   ) -> Dict[str, Any]:
    """รันสแกน active หนึ่งงาน คืน scan record (บันทึกลง store แล้ว)"""
    policy = store.get_policy(path)
    if not policy.get("enabled", True):
        rec = store.create_scan(program_id, target, profile, actor, path)
        store.update_scan(rec["id"], lambda r: r.update(
            {"status": "failed", "denied_reason": "ACTIVE_SCAN_DISABLED",
             "finished_iso": store.iso()}), path)
        return store.get_scan(rec["id"], path)

    if profile not in scanner.PROFILES:
        profile = "quick"
    ports = resolve_profile(profile)

    rec = store.create_scan(program_id, target, profile, actor, path)
    sid = rec["id"]
    store.update_scan(sid, lambda r: r.__setitem__("status", "running"), path)

    # ---- ด่าน: scope + resolve + public-IP ----
    await _progress(progress, f"🔐 ตรวจสิทธิ์ + resolve: {target}")
    auth = await guard.authorize_and_resolve(program_id, target,
                                             int(policy.get("max_hosts_per_scan", 256)))
    if not auth["ok"]:
        store.update_scan(sid, lambda r: r.update(
            {"status": "denied", "denied_reason": auth["reason"],
             "finished_iso": store.iso()}), path)
        await _progress(progress, f"⛔ ปฏิเสธ: {auth['reason']}")
        return store.get_scan(sid, path)

    hosts = auth["hosts"]
    total = len(hosts) * len(ports)
    cap = int(policy.get("max_total_connects", 65536))
    if total > cap:
        store.update_scan(sid, lambda r: r.update(
            {"status": "failed", "denied_reason": f"TOO_MANY_CONNECTS ({total}>{cap})",
             "finished_iso": store.iso()}), path)
        return store.get_scan(sid, path)

    # ---- สแกนพอร์ตราย host ----
    host_results: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    for i, h in enumerate(hosts, 1):
        # ด่าน IP ซ้ำก่อน connect จริง (fail closed)
        bad = guard.revalidate_ip(h["ip"])
        if bad:
            errors.append({"host": h["ip"], "reason": bad})
            continue
        await _progress(progress, f"🛰 [{i}/{len(hosts)}] สแกน {h['hostname']} ({h['ip']}) "
                                  f"· {len(ports)} พอร์ต")
        try:
            res = await scanner.scan_host(h["ip"], h["hostname"], ports, policy=policy)
            host_results.append(res)
        except Exception as e:
            logger.exception("ASCAN host failed | %s", h["ip"])
            errors.append({"host": h["ip"], "reason": str(e)})

    # ---- DNS AXFR (เฉพาะเป้าหมายโดเมน, best-effort) ----
    dns_info: Dict[str, Any] = {}
    if (auth["target_type"] in ("DOMAIN", "URL") and policy.get("dns_axfr", True)
            and auth["normalized_domain"]):
        dns_info = await _attempt_axfr(auth["normalized_domain"], progress)

    # ---- สรุป + บันทึก ----
    open_count = sum(len(h["ports"]) for h in host_results)
    up_count = sum(1 for h in host_results if h["up"])
    summary = {
        "hosts_scanned": len(host_results),
        "hosts_up": up_count,
        "open_ports_total": open_count,
        "ports_per_host": len(ports),
        "services": sorted({p["service"] for h in host_results for p in h["ports"]}),
    }
    store.update_scan(sid, lambda r: r.update(
        {"status": "completed", "hosts": host_results, "summary": summary,
         "dns": dns_info, "errors": errors, "finished_iso": store.iso()}), path)
    await _progress(progress, f"✅ เสร็จ: open {open_count} พอร์ต / {up_count} host")
    return store.get_scan(sid, path)


async def _attempt_axfr(domain: str, progress: ProgressCb) -> Dict[str, Any]:
    """ค้น NS (ผ่าน DoH ที่ reuse จาก passive_recon ถ้ามี) แล้วลอง AXFR แต่ละตัว"""
    try:
        from passive_recon import safehttp as pr_safehttp
        from osint.utils.async_http import AsyncHTTPClient
    except Exception:
        return {"axfr": "skipped", "reason": "DoH/NS lookup ไม่พร้อม"}

    await _progress(progress, "🧭 ลอง DNS zone transfer (AXFR)…")
    nameservers: List[str] = []
    try:
        async with AsyncHTTPClient(rate=4) as client:
            ans = await pr_safehttp.doh_query(client, domain, "NS")
        for a in (ans.get("Answer") or []):
            if a.get("type") == 2 and a.get("data"):
                nameservers.append(a["data"].rstrip("."))
    except Exception as e:
        return {"axfr": "skipped", "reason": f"NS lookup error: {e}"}

    results = []
    for ns in nameservers[:5]:
        safety = await _resolve_ns_public(ns)
        if not safety:
            results.append({"nameserver": ns, "status": "ns-not-public/unresolved"})
            continue
        axfr = await scanner.try_zone_transfer(domain, safety)
        if axfr.get("refused"):
            results.append({"nameserver": ns, "status": "refused (ตั้งค่าถูกต้อง)"})
        elif axfr.get("records"):
            results.append({"nameserver": ns, "status": "TRANSFER_ALLOWED (misconfig!)",
                            "record_count": len(axfr["records"]),
                            "sample": axfr["records"][:30]})
        else:
            results.append({"nameserver": ns, "status": axfr.get("reason", "no data")})
    return {"axfr": "attempted", "nameservers": nameservers, "results": results}


async def _resolve_ns_public(ns: str) -> Optional[str]:
    ips, err = await guard._resolve_public(ns)
    return ips[0] if ips and not err else None
