# -*- coding: utf-8 -*-
"""passive_recon/safehttp.py — การยิงเน็ตแบบ "ปลอดภัยต่อ SSRF" + DoH + TLS

หน้าที่:
  * safe_resolve / host_safety   ตรวจว่าโดเมน resolve ไปยัง IP สาธารณะล้วนไหม
                                 (บล็อก localhost/private/link-local/metadata)
  * guarded_fetch                GET/HEAD เป้าหมายที่ผู้ใช้ส่งมา โดย:
                                 - ปิด auto-redirect แล้ว revalidate ทุก hop
                                 - จำกัดเฉพาะ GET/HEAD, มี timeout + เพดานขนาด
  * doh_query                    ถาม DNS ผ่าน HTTPS (ไม่ต้องมี resolver/ไลบรารี DNS)
  * fetch_tls_cert               ดึง cert + เวอร์ชัน TLS จาก handshake (passive read)

reuse: osint.utils.validators.is_public_ip (เกณฑ์ IP สาธารณะเดียวกับทั้งโปรเจกต์)
httpx ถูก import แบบ guarded เหมือน osint/utils/async_http.py (รันเทสต์ logic ได้โดยไม่มี httpx)
"""

from __future__ import annotations

import ssl
import socket
import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("modbot.passive_recon.safehttp")

try:
    import httpx
    _HAS_HTTPX = True
except Exception:  # pragma: no cover
    httpx = None  # type: ignore
    _HAS_HTTPX = False

try:
    from osint.utils import validators as _v
except Exception:  # pragma: no cover
    _v = None

USER_AGENT = "SombraGuardian-PassiveRecon/1.0 (+authorized-assessment)"
HTTP_TIMEOUT = 15.0
MAX_BYTES = 512 * 1024          # อ่าน body ไม่เกิน 512KB (fingerprint พอ)
MAX_REDIRECTS = 3
TLS_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------

def _is_public(ip: str) -> bool:
    if _v is not None:
        return _v.is_public_ip(ip)
    import ipaddress  # fallback ถ้า osint ไม่พร้อม
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global and not a.is_multicast
    except ValueError:
        return False


def _resolve_sync(domain: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    ips = []
    for info in infos:
        ip = info[4][0]
        if ip and ip not in ips:
            ips.append(ip)
    return ips


async def safe_resolve(domain: str) -> List[str]:
    """resolve A/AAAA (ผ่าน getaddrinfo ใน thread) — คืนรายการ IP"""
    return await asyncio.to_thread(_resolve_sync, domain)


async def host_safety(domain: str) -> Dict[str, Any]:
    """ตรวจว่าโดเมนนี้ยิงได้อย่างปลอดภัยไหม

    คืน {safe, ips, reason}. safe=False ถ้า resolve ไม่ได้ หรือมี IP ที่ไม่ใช่สาธารณะ
    (บล็อก SSRF ไป private/loopback/link-local/metadata 169.254.169.254 ฯลฯ)
    """
    ips = await safe_resolve(domain)
    if not ips:
        return {"safe": False, "ips": [], "reason": "resolve ไม่ได้"}
    bad = [ip for ip in ips if not _is_public(ip)]
    if bad:
        return {"safe": False, "ips": ips,
                "reason": f"ชี้ไปยัง IP ที่ไม่ใช่สาธารณะ: {', '.join(bad)}"}
    return {"safe": True, "ips": ips, "reason": ""}


# ---------------------------------------------------------------------------
# guarded fetch (GET/HEAD เท่านั้น, revalidate redirect ทุก hop)
# ---------------------------------------------------------------------------

def _host_of(url: str) -> Optional[str]:
    try:
        return httpx.URL(url).host
    except Exception:
        return None


async def guarded_fetch(url: str, method: str = "GET") -> Dict[str, Any]:
    """ยิง GET/HEAD แบบปลอด SSRF

    คืน {ok, status, url, headers, text, cookies, redirects, reason}
    - method บังคับเป็น GET/HEAD เท่านั้น
    - ปิด follow_redirects: ตาม Location เองทีละ hop พร้อม revalidate host ทุกครั้ง
    - จำกัดขนาด body + timeout
    """
    method = method.upper()
    if method not in ("GET", "HEAD"):
        return {"ok": False, "reason": "อนุญาตเฉพาะ GET/HEAD"}
    if not _HAS_HTTPX:
        return {"ok": False, "reason": "httpx ไม่พร้อมใช้งาน"}

    redirects: List[str] = []
    cur = url
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=False,
                                     headers={"User-Agent": USER_AGENT}) as client:
            for hop in range(MAX_REDIRECTS + 1):
                host = _host_of(cur)
                if not host:
                    return {"ok": False, "reason": f"URL ไม่ถูกต้อง: {cur}"}
                safety = await host_safety(host)
                if not safety["safe"]:
                    return {"ok": False, "reason": f"ปฏิเสธด้วยเหตุผลความปลอดภัย: {safety['reason']}",
                            "blocked": True}
                resp = await client.request(method, cur)
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("location")
                    if not loc or hop >= MAX_REDIRECTS:
                        return _result(resp, redirects, truncated=False)
                    cur = str(httpx.URL(cur).join(loc))
                    redirects.append(cur)
                    continue
                # อ่าน body แบบจำกัดขนาด (เฉพาะ GET)
                text = ""
                truncated = False
                if method == "GET":
                    raw = resp.content[:MAX_BYTES]
                    truncated = len(resp.content) > MAX_BYTES
                    try:
                        text = raw.decode(resp.encoding or "utf-8", errors="replace")
                    except Exception:
                        text = raw.decode("utf-8", errors="replace")
                return _result(resp, redirects, text=text, truncated=truncated)
    except Exception as exc:
        return {"ok": False, "reason": f"transport error: {type(exc).__name__}: {exc}"}
    return {"ok": False, "reason": "redirect เกินกำหนด"}


def _result(resp, redirects, text: str = "", truncated: bool = False) -> Dict[str, Any]:
    cookies = []
    for k, v in resp.headers.multi_items() if hasattr(resp.headers, "multi_items") else resp.headers.items():
        if k.lower() == "set-cookie":
            cookies.append(v)
    return {
        "ok": 200 <= resp.status_code < 400,
        "status": resp.status_code,
        "url": str(resp.url),
        "headers": dict(resp.headers),
        "text": text,
        "cookies": cookies,
        "redirects": redirects,
        "truncated": truncated,
        "reason": "" if resp.status_code < 400 else f"HTTP {resp.status_code}",
    }


# ---------------------------------------------------------------------------
# DoH
# ---------------------------------------------------------------------------

DOH_ENDPOINTS = ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")


async def doh_query(client, domain: str, rtype: str) -> Dict[str, Any]:
    """ถาม DNS ผ่าน HTTPS (reuse AsyncHTTPClient ที่ส่งเข้ามา) — คืน JSON RFC 8484

    ลอง dns.google ก่อน แล้ว fallback cloudflare; คืน {} ถ้าพลาดทั้งคู่
    """
    for ep in DOH_ENDPOINTS:
        res = await client.get(ep, params={"name": domain, "type": rtype},
                               headers={"accept": "application/dns-json"})
        if res.ok:
            try:
                return res.json()
            except Exception:
                continue
    return {}


# ---------------------------------------------------------------------------
# TLS cert (handshake = passive read; ยังคงตรวจ SSRF ก่อน)
# ---------------------------------------------------------------------------

def _fetch_cert_sync(domain: str, ip: str) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, 443), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                return {"cert": ssock.getpeercert(), "version": ssock.version(),
                        "cipher": ssock.cipher()}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


async def fetch_tls_cert(domain: str) -> Dict[str, Any]:
    """ดึง cert + เวอร์ชัน TLS จากการ handshake กับ :443 (ตรวจ SSRF ก่อนเสมอ)

    คืน {ok, cert, version, cipher, reason}
    """
    safety = await host_safety(domain)
    if not safety["safe"]:
        return {"ok": False, "reason": f"ปฏิเสธด้วยเหตุผลความปลอดภัย: {safety['reason']}"}
    ip = safety["ips"][0]
    res = await asyncio.to_thread(_fetch_cert_sync, domain, ip)
    if "error" in res:
        return {"ok": False, "reason": res["error"]}
    return {"ok": True, "cert": res["cert"], "version": res["version"],
            "cipher": res["cipher"]}
