# -*- coding: utf-8 -*-
"""passive_recon/collectors.py — ตัวเก็บข้อมูลรายหมวด (async)

แต่ละ collector คืน dict มาตรฐานเดียวกัน:
  {category, status(ok|empty|error), records|data, sources, collected_at, reason, confidence}

reuse ของเดิม:
  * osint.utils.async_http.AsyncHTTPClient  — HTTP client (rate-limit/retry) สำหรับ API สาธารณะ
  * osint.sources.crtsh.fetch_subdomains    — Certificate Transparency (subdomain + SSL CT)
  * osint.sources.bgpview.BGPViewIPSource   — ASN/prefix (infrastructure)
ส่วนที่ "ใหม่" คือ: RDAP, DNS(DoH), tech fingerprint, HTTP metadata, TLS, geolocation, exposure
ทั้งหมด passive + ผ่าน SSRF guard (safehttp) เมื่อแตะเป้าหมายที่ผู้ใช้ส่งมา
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import parse, safehttp

logger = logging.getLogger("modbot.passive_recon.collectors")

try:
    from osint.sources.crtsh import fetch_subdomains as _crtsh_fetch
except Exception:  # pragma: no cover
    _crtsh_fetch = None
try:
    from osint.sources.bgpview import BGPViewIPSource
except Exception:  # pragma: no cover
    BGPViewIPSource = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cat(category: str, status: str, *, records=None, data=None,
         sources=None, reason: str = "") -> Dict[str, Any]:
    rec = records or []
    count = len(rec) if records is not None else (1 if data else 0)
    return {
        "category": category,
        "status": status,
        "records": rec,
        "data": data or {},
        "sources": sources or [],
        "collected_at": _now(),
        "reason": reason,
        "confidence": parse.confidence_for(category, status, count),
    }


# ---------------------------------------------------------------------------
# A. Domain / WHOIS-RDAP
# ---------------------------------------------------------------------------

async def collect_domain(client, domain: str, registered: str) -> Dict[str, Any]:
    """RDAP (มาตรฐานแทน WHOIS) ผ่าน rdap.org — registrar/วันที่/nameservers/status"""
    res = await client.get_json(f"https://rdap.org/domain/{registered}")
    if not res.ok:
        return _cat("domain", "error", reason=f"RDAP: {res.reason}",
                    sources=["rdap.org"])
    try:
        d = res.json()
    except Exception as e:
        return _cat("domain", "error", reason=f"RDAP parse: {e}", sources=["rdap.org"])

    events = {e.get("eventAction"): e.get("eventDate")
              for e in (d.get("events") or [])}
    registrar = None
    for ent in (d.get("entities") or []):
        if "registrar" in (ent.get("roles") or []):
            for v in (ent.get("vcardArray", [None, []])[1] or []):
                if v and v[0] == "fn":
                    registrar = v[3]
    nameservers = [ns.get("ldhName", "").lower() for ns in (d.get("nameservers") or [])]
    data = {
        "handle": d.get("handle"),
        "registrar": registrar,
        "created": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "status": d.get("status") or [],
        "nameservers": [n for n in nameservers if n],
    }
    return _cat("domain", "ok", data=data, sources=["rdap.org (RDAP)"])


# ---------------------------------------------------------------------------
# DNS (DoH) + SPF/DMARC/DKIM
# ---------------------------------------------------------------------------

async def collect_dns(client, domain: str) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    txt_values: List[str] = []
    for rtype in ("A", "AAAA", "MX", "NS", "SOA", "TXT", "CAA"):
        ans = await safehttp.doh_query(client, domain, rtype)
        rs = parse.parse_doh(ans, rtype)
        records.extend(rs)
        if rtype == "TXT":
            txt_values = [r["value"] for r in rs]

    # DMARC อยู่ที่ _dmarc.<domain>
    dmarc_ans = await safehttp.doh_query(client, f"_dmarc.{domain}", "TXT")
    dmarc_txt = [r["value"] for r in parse.parse_doh(dmarc_ans, "TXT")]

    spf = parse.analyze_spf(txt_values)
    dmarc = parse.analyze_dmarc(dmarc_txt)
    email_auth = {"spf": spf, "dmarc": dmarc, "dkim_txt_present": parse.dkim_presence(txt_values)}
    status = "ok" if records else "empty"
    out = _cat("dns", status, records=records,
               data={"email_auth": email_auth}, sources=["dns.google/cloudflare (DoH)"])
    # ส่ง spf/dmarc ออกไปให้หมวด security ใช้ต่อ
    out["_spf"] = spf
    out["_dmarc"] = dmarc
    out["_ips"] = [r["value"] for r in records if r["type"] in ("A", "AAAA")]
    return out


# ---------------------------------------------------------------------------
# B. Subdomains (reuse crt.sh CT) + DNS validation ของตัวอย่าง
# ---------------------------------------------------------------------------

async def collect_subdomains(client, domain: str, registered: str,
                             validate: int = 15) -> Dict[str, Any]:
    if _crtsh_fetch is None:
        return _cat("subdomains", "error", reason="crt.sh source ไม่พร้อม")
    sr = await _crtsh_fetch(client, registered)
    names = []
    for rec in sr.records:
        v = rec.get("value") or rec.get("name") or rec.get("hostname")
        if v:
            names.append(v)
    names = parse.dedupe_hostnames(names, registered)

    # validate ด้วย DNS (DoH) แบบจำกัดจำนวน ชี้ตัวที่ "อาจถูกทิ้งร้าง" (ไม่ resolve)
    records = []
    checked = 0
    for n in names:
        rec = {"value": n, "source": "crt.sh (CT log)"}
        if checked < validate:
            ans = await safehttp.doh_query(client, n, "A")
            a = parse.parse_doh(ans, "A")
            rec["resolves"] = bool(a)
            rec["validated"] = True
            if not a:
                rec["note"] = "ไม่ resolve (อาจถูกทิ้งร้าง/inactive)"
            checked += 1
        records.append(rec)
    status = "ok" if records else "empty"
    return _cat("subdomains", status, records=records,
                sources=["crt.sh (CT log)", "DoH validation"],
                reason=sr.reason if not records else "")


# ---------------------------------------------------------------------------
# C+E. HTTP metadata + Technology fingerprint (SSRF-guarded)
# ---------------------------------------------------------------------------

async def collect_http_and_tech(domain: str, url: str) -> Dict[str, Dict[str, Any]]:
    """ยิง GET root (ปลอด SSRF) + robots + sitemap, แล้วแยกเป็น http กับ technology"""
    main = await safehttp.guarded_fetch(url, method="GET")
    if not main.get("ok") and main.get("blocked"):
        err = _cat("http", "error", reason=main.get("reason"))
        return {"http": err, "technology": _cat("technology", "error",
                                                 reason=main.get("reason"))}
    if not main.get("ok") and not main.get("status"):
        err = _cat("http", "error", reason=main.get("reason", "ยิงไม่สำเร็จ"))
        return {"http": err, "technology": _cat("technology", "empty")}

    headers = main.get("headers", {})
    html = main.get("text", "")
    cookies = main.get("cookies", [])
    meta = parse.http_metadata(main.get("status", 0), headers, html)
    meta["final_url"] = main.get("url")
    meta["redirects"] = main.get("redirects", [])

    # robots.txt + sitemap.xml (HEAD/GET เบา ๆ)
    robots = await safehttp.guarded_fetch(url.rstrip("/") + "/robots.txt", method="GET")
    if robots.get("ok"):
        meta["robots"] = parse.parse_robots(robots.get("text", ""))
    sm = await safehttp.guarded_fetch(url.rstrip("/") + "/sitemap.xml", method="HEAD")
    meta["sitemap_present"] = bool(sm.get("ok"))

    http_cat = _cat("http", "ok", data=meta, sources=[meta.get("final_url") or url])

    tech = parse.fingerprint_tech(headers, html, cookies)
    tech_cat = _cat("technology", "ok" if tech else "empty", records=tech,
                    sources=["HTTP headers", "HTML body", "cookies"])
    # ส่งต่อให้ security/correlation
    http_cat["_html_meta"] = meta
    tech_cat["_tech"] = tech
    return {"http": http_cat, "technology": tech_cat}


# ---------------------------------------------------------------------------
# D. TLS
# ---------------------------------------------------------------------------

async def collect_tls(domain: str) -> Dict[str, Any]:
    res = await safehttp.fetch_tls_cert(domain)
    if not res.get("ok"):
        return _cat("tls", "error", reason=res.get("reason", "handshake ไม่สำเร็จ"))
    info = parse.parse_certificate(res.get("cert") or {})
    info["tls_version"] = res.get("version")
    info["cipher"] = (res.get("cipher") or [None])[0]
    out = _cat("tls", "ok", data=info, sources=[f"TLS handshake {domain}:443"])
    out["_cert"] = info
    return out


# ---------------------------------------------------------------------------
# F. Infrastructure (reuse BGPView + geolocation)
# ---------------------------------------------------------------------------

async def collect_infrastructure(client, ips: List[str]) -> Dict[str, Any]:
    if not ips:
        return _cat("infrastructure", "empty", reason="ไม่มี IP ให้ตรวจ")
    records: List[Dict[str, Any]] = []
    sources = []
    # IPv4/IPv6 records
    for ip in ips:
        records.append({"type": "ip", "value": ip, "source": "DNS"})

    primary = ips[0]
    # ASN/prefix (reuse BGPView)
    if BGPViewIPSource is not None:
        try:
            sr = await BGPViewIPSource().run(client, primary)
            for r in sr.records:
                records.append(r)
            if sr.records:
                sources.append("bgpview.io")
        except Exception:
            logger.exception("passive_recon: BGPView failed")

    # geolocation + ISP (ipwho.is — https, ไม่ต้องใช้ key)
    geo = await client.get_json(f"https://ipwho.is/{primary}")
    if geo.ok:
        try:
            g = geo.json()
            if g.get("success", True):
                records.append({"type": "geo", "value":
                                f"{g.get('city','?')}, {g.get('country','?')}",
                                "source": "ipwho.is"})
                if g.get("connection", {}).get("isp"):
                    records.append({"type": "isp",
                                    "value": g["connection"]["isp"],
                                    "name": g["connection"].get("org"),
                                    "source": "ipwho.is"})
                sources.append("ipwho.is")
        except Exception:
            pass
    status = "ok" if records else "empty"
    return _cat("infrastructure", status, records=records, sources=sources or ["DNS"])


# ---------------------------------------------------------------------------
# G. Security exposure (รวมจากหมวดอื่น — เชิงข้อมูลล้วน)
# ---------------------------------------------------------------------------

def collect_security(http_cat: Dict, tech_cat: Dict, dns_cat: Dict,
                     tls_cat: Dict) -> Dict[str, Any]:
    meta = http_cat.get("_html_meta") or http_cat.get("data") or {}
    tech = tech_cat.get("_tech") or tech_cat.get("records") or []
    spf = dns_cat.get("_spf")
    dmarc = dns_cat.get("_dmarc")
    cert = tls_cat.get("_cert") or (tls_cat.get("data") if tls_cat.get("status") == "ok" else None)
    indicators = parse.security_exposure(meta, tech, spf, dmarc, cert)
    status = "ok" if indicators else "empty"
    return _cat("security", status, records=indicators,
                sources=["derived from observed metadata"])
