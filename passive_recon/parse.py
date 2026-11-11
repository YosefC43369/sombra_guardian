# -*- coding: utf-8 -*-
"""passive_recon/parse.py — ตรรกะวิเคราะห์ล้วน (ไม่แตะเครือข่าย เทสต์ได้ 100%)

แยกส่วน "คิด" ออกจากส่วน "ยิงเน็ต" ทั้งหมด: การ normalize, แปลงผล DoH/RDAP,
วิเคราะห์ SPF/DMARC, fingerprint เทคโนโลยี, อ่าน cert, ประเมิน exposure,
ตัดซ้ำ, คิด confidence และ render รายงาน — อยู่ที่นี่หมด

ใช้เฉพาะ stdlib + urlkit (มีในโปรเจกต์) จึงรันและเทสต์ได้โดยไม่ต้องมี httpx/เครือข่าย
"""

from __future__ import annotations

import re
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import urlkit  # type: ignore
    _HAS_URLKIT = True
except Exception:  # pragma: no cover
    urlkit = None  # type: ignore
    _HAS_URLKIT = False


# ---------------------------------------------------------------------------
# normalize เป้าหมาย
# ---------------------------------------------------------------------------

_SCHEME_RE = re.compile(r"(?i)^[a-z][a-z0-9+.\-]*://")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})*\.[a-z]{2,63}$")


def normalize_target(raw: str) -> Optional[Dict[str, str]]:
    """แปลง input (URL/โดเมน) -> {scheme, domain, url, registered}

    - เติม https:// ถ้าไม่มี scheme
    - ตัด path/port/credentials, lower-case, IDNA
    - คืน None ถ้าไม่ใช่โดเมนที่ใช้งานได้ (กันขยะ/กัน SSRF ด้วย host เพี้ยน)
    """
    if not raw:
        return None
    s = raw.strip()
    if not s:
        return None
    scheme = "https"
    m = _SCHEME_RE.match(s)
    if m:
        scheme = m.group(0)[:-3].lower()
        if scheme not in ("http", "https"):
            return None
    host_part = _SCHEME_RE.sub("", s)
    host_part = host_part.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in host_part:            # ปฏิเสธ user:pass@host (กัน SSRF/ขยะ)
        return None
    host_part = host_part.split(":", 1)[0].rstrip(".").lower()
    if host_part.startswith("*."):
        host_part = host_part[2:]
    if not host_part:
        return None
    try:
        host_part = host_part.encode("idna").decode("ascii")
    except Exception:
        pass
    if not _DOMAIN_RE.match(host_part):
        return None
    registered = host_part
    if _HAS_URLKIT:
        try:
            registered = urlkit.etld1(host_part) or host_part
        except Exception:
            registered = host_part
    return {"scheme": scheme, "domain": host_part,
            "url": f"{scheme}://{host_part}", "registered": registered}


# ---------------------------------------------------------------------------
# DoH (DNS over HTTPS) — แปลงผล JSON ของ dns.google / cloudflare
# ---------------------------------------------------------------------------

_DOH_TYPE = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT", 2: "NS", 6: "SOA",
             5: "CNAME", 257: "CAA"}


def parse_doh(answer_json: Dict[str, Any], want: str) -> List[Dict[str, str]]:
    """ดึง record ชนิด want จากผลลัพธ์ DoH (รูปแบบ RFC 8484 JSON)"""
    out: List[Dict[str, str]] = []
    for ans in (answer_json.get("Answer") or []):
        t = _DOH_TYPE.get(ans.get("type"), str(ans.get("type")))
        if t != want:
            continue
        data = (ans.get("data") or "").strip()
        if want == "TXT":
            data = data.strip('"').replace('" "', "")
        elif want == "MX":
            data = data  # "10 mail.example.com."
        out.append({"type": t, "value": data.rstrip("."),
                    "ttl": ans.get("TTL"), "source": "doh"})
    return out


# ---------------------------------------------------------------------------
# SPF / DMARC / DKIM จาก TXT
# ---------------------------------------------------------------------------

def analyze_spf(txt_values: List[str]) -> Optional[Dict[str, Any]]:
    for v in txt_values:
        if v.lower().startswith("v=spf1"):
            all_m = re.search(r"([~\-+?])all\b", v)
            qualifier = all_m.group(1) if all_m else None
            weak = qualifier in ("+", "?")  # +all/?all = อ่อน
            return {"record": v, "all_qualifier": qualifier, "weak": weak,
                    "includes": re.findall(r"include:(\S+)", v)}
    return None


def analyze_dmarc(txt_values: List[str]) -> Optional[Dict[str, Any]]:
    for v in txt_values:
        if v.lower().startswith("v=dmarc1"):
            p = re.search(r"\bp=(\w+)", v)
            policy = p.group(1).lower() if p else "none"
            return {"record": v, "policy": policy,
                    "weak": policy == "none",
                    "rua": re.findall(r"rua=([^;]+)", v)}
    return None


def dkim_presence(txt_values: List[str]) -> bool:
    return any("v=dkim1" in v.lower() or "k=rsa" in v.lower() for v in txt_values)


# ---------------------------------------------------------------------------
# Technology fingerprint — แยก "ยืนยัน" (header ชัด) vs "อนุมาน" (จาก HTML/cookie)
# ---------------------------------------------------------------------------

# (ชื่อ, หมวด, แหล่ง header, regex ค่า) — ยืนยันจาก header
_HEADER_SIGNS = [
    ("nginx", "web-server", "server", r"(?i)nginx"),
    ("Apache", "web-server", "server", r"(?i)apache"),
    ("Microsoft-IIS", "web-server", "server", r"(?i)iis"),
    ("LiteSpeed", "web-server", "server", r"(?i)litespeed"),
    ("Caddy", "web-server", "server", r"(?i)caddy"),
    ("PHP", "language", "x-powered-by", r"(?i)php"),
    ("ASP.NET", "framework", "x-powered-by", r"(?i)asp\.net"),
    ("Express", "framework", "x-powered-by", r"(?i)express"),
    ("Cloudflare", "cdn", "server", r"(?i)cloudflare"),
    ("Cloudflare", "cdn", "cf-ray", r".+"),
    ("Fastly", "cdn", "x-served-by", r"(?i)fastly|cache-"),
    ("Amazon CloudFront", "cdn", "x-amz-cf-id", r".+"),
    ("Varnish", "reverse-proxy", "via", r"(?i)varnish"),
    ("Akamai", "cdn", "x-akamai-transformed", r".+"),
    ("Vercel", "hosting", "server", r"(?i)vercel"),
    ("Netlify", "hosting", "server", r"(?i)netlify"),
]

# WAF จาก header/cookie
_WAF_SIGNS = [
    ("Cloudflare WAF", "cf-mitigated", r".+"),
    ("Sucuri", "x-sucuri-id", r".+"),
    ("Imperva/Incapsula", "x-iinfo", r".+"),
    ("AWS WAF", "x-amzn-waf", r".+"),
]

# (ชื่อ, หมวด, regex ใน HTML) — อนุมาน
_HTML_SIGNS = [
    ("WordPress", "cms", r"(?i)/wp-(content|includes)/|<meta name=\"generator\" content=\"WordPress"),
    ("Joomla", "cms", r"(?i)/media/jui/|content=\"Joomla"),
    ("Drupal", "cms", r"(?i)Drupal\.settings|/sites/default/files"),
    ("React", "js-framework", r"(?i)__REACT_DEVTOOLS|data-reactroot|react(?:\.production)?\.min\.js"),
    ("Vue.js", "js-framework", r"(?i)vue(?:\.runtime)?\.min\.js|data-v-[0-9a-f]{8}"),
    ("Angular", "js-framework", r"(?i)ng-version=|angular(?:\.min)?\.js"),
    ("Next.js", "framework", r"(?i)/_next/static/|__NEXT_DATA__"),
    ("Nuxt", "framework", r"(?i)/_nuxt/|__NUXT__"),
    ("jQuery", "js-library", r"(?i)jquery(?:-\d|\.min)?\.js"),
    ("Bootstrap", "frontend", r"(?i)bootstrap(?:\.min)?\.(?:css|js)"),
    ("Shopify", "ecommerce", r"(?i)cdn\.shopify\.com|Shopify\.theme"),
]

_COOKIE_SIGNS = [
    ("PHP", "language", r"(?i)PHPSESSID"),
    ("ASP.NET", "framework", r"(?i)ASP\.NET_SessionId|\.AspNetCore"),
    ("Java", "language", r"(?i)JSESSIONID"),
    ("Laravel", "framework", r"(?i)laravel_session"),
    ("WordPress", "cms", r"(?i)wordpress_|wp-settings"),
]

_VERSION_RE = re.compile(r"(?i)([a-z][a-z0-9.\-]*?)[/ ]([0-9]+(?:\.[0-9]+){1,3})")


def fingerprint_tech(headers: Dict[str, str], html: str = "",
                     cookies: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """รวม fingerprint เทคโนโลยี แยก confirmed (header) / inferred (HTML/cookie)

    แต่ละตัว: {tech, category, confidence, confirmed, evidence, version?}
    """
    h = {k.lower(): v for k, v in (headers or {}).items()}
    found: Dict[str, Dict[str, Any]] = {}

    def _add(tech, cat, conf, confirmed, evidence, version=None):
        key = tech.lower()
        if key in found:
            if conf > found[key]["confidence"]:
                found[key].update({"confidence": conf, "confirmed": confirmed,
                                   "evidence": evidence})
            return
        rec = {"tech": tech, "category": cat, "confidence": conf,
               "confirmed": confirmed, "evidence": evidence}
        if version:
            rec["version"] = version
        found[key] = rec

    for tech, cat, hdr, pat in _HEADER_SIGNS:
        val = h.get(hdr)
        if val and re.search(pat, val):
            ver = None
            vm = _VERSION_RE.search(val)
            if vm and tech.lower().startswith(vm.group(1).lower()[:4]):
                ver = vm.group(2)
            _add(tech, cat, 0.95, True, f"header {hdr}: {val[:80]}", ver)

    for tech, hdr, pat in _WAF_SIGNS:
        if h.get(hdr) and re.search(pat, h.get(hdr, "")):
            _add(tech, "waf", 0.9, True, f"header {hdr}")

    for tech, cat, pat in _HTML_SIGNS:
        if html and re.search(pat, html):
            _add(tech, cat, 0.6, False, "HTML pattern")

    for c in (cookies or []):
        for tech, cat, pat in _COOKIE_SIGNS:
            if re.search(pat, c):
                _add(tech, cat, 0.7, False, f"cookie {c.split('=')[0][:40]}")

    # meta generator (ยืนยันปานกลาง)
    gm = re.search(r'(?i)<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html or "")
    if gm:
        _add(gm.group(1).split()[0], "cms", 0.75, False, f"meta generator: {gm.group(1)[:60]}")

    return sorted(found.values(), key=lambda r: (-r["confidence"], r["tech"]))


# ---------------------------------------------------------------------------
# cert
# ---------------------------------------------------------------------------

def parse_certificate(cert: Dict[str, Any]) -> Dict[str, Any]:
    """อ่าน dict cert จาก ssl.getpeercert() -> สรุปที่อ่านง่าย"""
    def _name(seq):
        out = {}
        for rdn in (seq or []):
            for k, v in rdn:
                out[k] = v
        return out

    subject = _name(cert.get("subject"))
    issuer = _name(cert.get("issuer"))
    san = [v for (t, v) in (cert.get("subjectAltName") or []) if t == "DNS"]
    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    days_left = None
    expired = None
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = int((exp - datetime.now(timezone.utc)).total_seconds() // 86400)
            expired = days_left < 0
        except Exception:
            pass
    return {
        "subject_cn": subject.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "issuer_org": issuer.get("organizationName"),
        "san": sorted(set(san)),
        "not_before": not_before,
        "not_after": not_after,
        "days_left": days_left,
        "expired": expired,
    }


# ---------------------------------------------------------------------------
# HTTP metadata helpers
# ---------------------------------------------------------------------------

_SECURITY_HEADERS = ("strict-transport-security", "content-security-policy",
                     "x-frame-options", "x-content-type-options",
                     "referrer-policy", "permissions-policy")


def http_metadata(status: int, headers: Dict[str, str], html: str = "") -> Dict[str, Any]:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    missing = [s for s in _SECURITY_HEADERS if s not in h]
    title = None
    tm = re.search(r"(?is)<title[^>]*>(.*?)</title>", html or "")
    if tm:
        title = re.sub(r"\s+", " ", tm.group(1)).strip()[:200]
    canonical = None
    cm = re.search(r'(?i)<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)', html or "")
    if cm:
        canonical = cm.group(1)[:300]
    return {
        "status": status,
        "server": h.get("server"),
        "content_type": h.get("content-type"),
        "security_headers_present": [s for s in _SECURITY_HEADERS if s in h],
        "security_headers_missing": missing,
        "title": title,
        "canonical": canonical,
    }


def parse_robots(text: str) -> Dict[str, Any]:
    disallow = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", text or "")
    sitemaps = re.findall(r"(?im)^\s*Sitemap:\s*(\S+)", text or "")
    return {"disallow_count": len(disallow),
            "disallow_sample": disallow[:20],
            "sitemaps": sitemaps[:10]}


# ---------------------------------------------------------------------------
# Security exposure (เป็น "ตัวชี้วัดเชิงข้อมูล" เท่านั้น ไม่ใช่ช่องโหว่ยืนยัน)
# ---------------------------------------------------------------------------

def security_exposure(http_meta: Dict[str, Any], tech: List[Dict[str, Any]],
                      spf: Optional[Dict], dmarc: Optional[Dict],
                      cert: Optional[Dict]) -> List[Dict[str, Any]]:
    """รวมตัวชี้วัดเชิงข้อมูลจากสิ่งที่ "สังเกตได้" (ไม่ทดสอบ/ไม่ยืนยัน exploit)"""
    out: List[Dict[str, Any]] = []

    def _ind(sev, title, detail):
        out.append({"severity": sev, "indicator": title, "detail": detail,
                    "type": "informational"})

    for s in http_meta.get("security_headers_missing", []):
        _ind("low", f"ไม่มี security header: {s}",
             "ลดการป้องกันฝั่ง client (ไม่ใช่ช่องโหว่โดยตรง)")

    # เวอร์ชันซอฟต์แวร์ที่เปิดเผยทาง banner
    for t in tech:
        if t.get("version"):
            _ind("low", f"เปิดเผยเวอร์ชัน {t['tech']} {t['version']}",
                 "เวอร์ชันที่โชว์ออกมาช่วยให้ค้นหา CVE ที่เกี่ยวข้องได้ — "
                 "ควรตรวจ advisory ของเวอร์ชันนี้ (ยังไม่ยืนยันว่าเปราะบาง)")

    if spf and spf.get("weak"):
        _ind("medium", "SPF อ่อน (+all/?all)",
             "เปิดช่องปลอมอีเมลจากโดเมนนี้ได้ง่ายขึ้น")
    if spf is None:
        _ind("low", "ไม่มี SPF record", "เพิ่มโอกาสถูกปลอมอีเมล")
    if dmarc and dmarc.get("weak"):
        _ind("medium", "DMARC p=none",
             "ตรวจพบการปลอมแต่ไม่บังคับใช้ (monitor only)")
    if dmarc is None:
        _ind("low", "ไม่มี DMARC record", "ไม่มีนโยบายจัดการอีเมลปลอม")

    if cert:
        if cert.get("expired"):
            _ind("high", "ใบรับรอง TLS หมดอายุ", f"หมดเมื่อ {cert.get('not_after')}")
        elif isinstance(cert.get("days_left"), int) and cert["days_left"] <= 14:
            _ind("medium", "ใบรับรอง TLS ใกล้หมดอายุ",
                 f"เหลือ {cert['days_left']} วัน")
    return out


# ---------------------------------------------------------------------------
# dedupe + confidence
# ---------------------------------------------------------------------------

def dedupe_hostnames(names: List[str], within_domain: str) -> List[str]:
    seen = set()
    out = []
    dom = within_domain.lower().lstrip(".")
    for n in names:
        nn = (n or "").strip().lower().rstrip(".").lstrip("*.")
        if not nn or nn in seen:
            continue
        if not (nn == dom or nn.endswith("." + dom)):
            continue
        seen.add(nn)
        out.append(nn)
    return sorted(out)


def confidence_for(category: str, status: str, record_count: int) -> float:
    """ความเชื่อมั่นของหมวดข้อมูล: มาจากหลายแหล่ง/มีข้อมูล = สูง"""
    if status in ("error", "invalid_target"):
        return 0.0
    if status == "empty" or record_count == 0:
        return 0.3
    base = {"dns": 0.95, "subdomains": 0.8, "tls": 0.95, "http": 0.9,
            "whois": 0.9, "infrastructure": 0.85, "technology": 0.7,
            "security": 0.6}.get(category, 0.7)
    return round(min(1.0, base + min(0.1, record_count / 100.0)), 2)


# ---------------------------------------------------------------------------
# render รายงาน
# ---------------------------------------------------------------------------

def render_json(report: Dict[str, Any], indent: int = 2) -> str:
    return json.dumps(report, ensure_ascii=False, indent=indent, default=str)


def render_markdown(report: Dict[str, Any]) -> str:
    t = report.get("target", {})
    L = [f"# Passive Recon — {t.get('domain','?')}",
         f"- target: `{t.get('url','')}`  ·  registered: `{t.get('registered','')}`",
         f"- collected: {report.get('collected_at','')}  ·  duration: {report.get('duration_ms','?')}ms",
         ""]
    cats = report.get("categories", {})

    def sec(title, body_lines):
        L.append(f"## {title}")
        L.extend(body_lines or ["_ไม่มีข้อมูล_"])
        L.append("")

    dom = cats.get("domain", {})
    sec("Domain / WHOIS-RDAP", [f"- {k}: {v}" for k, v in (dom.get("data") or {}).items()] or None)
    dns = cats.get("dns", {})
    sec("DNS", [f"- {r['type']}: {r['value']}" for r in (dns.get("records") or [])][:40] or None)
    subs = cats.get("subdomains", {})
    sec(f"Subdomains ({len(subs.get('records', []))})",
        [f"- {r['value']}" for r in (subs.get("records") or [])][:60] or None)
    tech = cats.get("technology", {})
    sec("Technology", [f"- {'✅' if r.get('confirmed') else '≈'} {r['tech']} "
                       f"({r['category']}, conf {r['confidence']})"
                       + (f" v{r['version']}" if r.get('version') else "")
                       for r in (tech.get("records") or [])] or None)
    tls = cats.get("tls", {})
    td = tls.get("data") or {}
    sec("TLS", [f"- issuer: {td.get('issuer_cn')} ({td.get('issuer_org')})",
                f"- valid: {td.get('not_before')} → {td.get('not_after')} "
                f"(เหลือ {td.get('days_left')} วัน)",
                f"- SAN: {', '.join(td.get('san', [])[:15])}"] if td else None)
    http = cats.get("http", {})
    hd = http.get("data") or {}
    sec("HTTP", [f"- status: {hd.get('status')}  server: {hd.get('server')}",
                 f"- title: {hd.get('title')}",
                 f"- missing security headers: {', '.join(hd.get('security_headers_missing', []))}"]
        if hd else None)
    infra = cats.get("infrastructure", {})
    sec("Infrastructure", [f"- {r['type']}: {r['value']}" + (f" ({r.get('name')})" if r.get('name') else "")
                           for r in (infra.get("records") or [])][:30] or None)
    sx = cats.get("security", {})
    sec("Security exposure (informational)",
        [f"- [{r['severity']}] {r['indicator']} — {r['detail']}" for r in (sx.get("records") or [])] or None)

    errs = report.get("errors") or []
    if errs:
        sec("Collection errors / unavailable",
            [f"- {e.get('category')}: {e.get('reason')}" for e in errs])
    L.append("---")
    L.append("_passive-only · ตัวชี้วัดเชิงข้อมูล ไม่ใช่ช่องโหว่ที่ยืนยัน · "
             "แหล่งและเวลาเก็บแนบในแต่ละรายการ (ไฟล์ JSON)_")
    return "\n".join(L)


def render_txt(report: Dict[str, Any]) -> str:
    # txt = markdown ที่ตัดสัญลักษณ์ออก อ่านง่ายในเทอร์มินัล/ไฟล์
    md = render_markdown(report)
    return re.sub(r"[#`*]", "", md)
