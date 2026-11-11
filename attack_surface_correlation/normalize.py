# -*- coding: utf-8 -*-
"""attack_surface_correlation/normalize.py — ตรรกะ normalize/dedupe assets ล้วน

แยกส่วน "คิด" ออกจากส่วน I/O ทั้งหมด (เหมือน passive_recon/parse.py) — รับ output ดิบ
ของโมดูลเดิม (passive_recon report, wva/api assessment, active_scan, unified findings)
แล้วแปลงเป็น "normalized asset" ชุดเดียว พร้อมตัดซ้ำและคงแหล่งที่มาไว้ครบ

ใช้ stdlib (+ urlkit ที่มีในโปรเจกต์) เท่านั้น จึงเทสต์ได้ 100% โดยไม่ต้องต่อเน็ต

normalized asset:
  {asset_id, asset_type, value, parent_domain, ip_addresses, technologies,
   source_modules, first_seen, last_seen, confidence, observations, metadata}

asset_type ที่รองรับ: root_domain · subdomain · ip · hostname · website ·
  http_service · api_endpoint · dns_record · certificate · network_service ·
  technology · finding

หลักสำคัญ (ตามสเปค):
  * ทุก asset คง source_modules + observations (traceability กลับไปที่โมดูลต้นทาง)
  * ไม่ลบประวัติ — merge แล้วเก็บ first_seen/last_seen และ observation refs ไว้
  * ไม่รวม asset เพียงเพราะใช้ IP/โครงสร้างพื้นฐานร่วมกัน (ทำที่ relate.py)
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

try:
    import urlkit  # type: ignore
    _HAS_URLKIT = True
except Exception:  # pragma: no cover
    urlkit = None  # type: ignore
    _HAS_URLKIT = False

# asset types (ค่าเดียวที่อนุญาต)
ASSET_TYPES = (
    "root_domain", "subdomain", "ip", "hostname", "website", "http_service",
    "api_endpoint", "dns_record", "certificate", "network_service",
    "technology", "finding",
)

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9_-]{1,63}(?:\.[a-z0-9_-]{1,63})*\.[a-z]{2,63}$")
_SCHEME_RE = re.compile(r"(?i)^[a-z][a-z0-9+.\-]*://")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# primitive normalizers (เทสต์ได้ตรง ๆ)
# ---------------------------------------------------------------------------

def normalize_hostname(name: Optional[str]) -> Optional[str]:
    """lower-case, ตัด trailing dot, ตัด wildcard, ตัด scheme/path/port ออก

    คืน None ถ้าไม่ใช่ hostname ที่ใช้งานได้ (กันขยะเข้า pipeline)
    """
    if not name or not isinstance(name, str):
        return None
    s = name.strip()
    s = _SCHEME_RE.sub("", s)
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[-1]
    s = s.split(":", 1)[0]          # ตัด port
    s = s.strip().lower().rstrip(".")
    if s.startswith("*."):
        s = s[2:]
    if not s:
        return None
    try:
        s = s.encode("idna").decode("ascii")
    except Exception:
        pass
    if not _HOST_RE.match(s):
        return None
    return s


def is_ip(value: Optional[str]) -> bool:
    if not value or not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def normalize_ip(value: Optional[str]) -> Optional[str]:
    """คืนรูปแบบ canonical ของ IP (บีบ IPv6, ตัด zero-pad) หรือ None"""
    if not value or not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def registered_domain(host: str) -> str:
    """eTLD+1 (reuse urlkit ของโปรเจกต์ ถ้ามี) — fallback: สองป้ายท้าย"""
    h = (host or "").lower().rstrip(".")
    if _HAS_URLKIT:
        try:
            r = urlkit.etld1(h)
            if r:
                return r
        except Exception:
            pass
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def normalize_url(url: Optional[str]) -> Optional[str]:
    """normalize URL: lower-case host, ตัด fragment, ตัด trailing slash ของ path ว่าง

    คง scheme/path/query (path/query มีความหมายต่อ endpoint) — คืน None ถ้า host เพี้ยน
    """
    if not url or not isinstance(url, str):
        return None
    s = url.strip()
    m = _SCHEME_RE.match(s)
    scheme = (m.group(0)[:-3].lower() if m else "https")
    rest = _SCHEME_RE.sub("", s)
    host_part, _, tail = rest.partition("/")
    host_part = host_part.split("@")[-1]
    port = ""
    if ":" in host_part:
        host_part, _, port = host_part.partition(":")
    host = normalize_hostname(host_part)
    if host is None:
        return None
    path = "/" + tail if tail else "/"
    path = path.split("#", 1)[0]
    netloc = host + (f":{port}" if port and port.isdigit() else "")
    if path == "/":
        return f"{scheme}://{netloc}/"
    return f"{scheme}://{netloc}{path}"


def endpoint_key(host: Optional[str], method: Optional[str], path: Optional[str]) -> Optional[str]:
    """คีย์ canonical ของ API endpoint: METHOD host/path (ตัด query, lower host)"""
    h = normalize_hostname(host) if host else None
    p = (path or "/").split("?", 1)[0].split("#", 1)[0]
    if not p.startswith("/"):
        p = "/" + p
    m = (method or "GET").upper().strip()
    base = f"{h}{p}" if h else p
    return f"{m} {base}"


# ---------------------------------------------------------------------------
# AssetBuilder — รวบรวม + dedupe asset พร้อม traceability
# ---------------------------------------------------------------------------

class AssetBuilder:
    """สะสม asset โดยตัดซ้ำตาม (asset_type, normalized value) และคง observation ทุกแหล่ง

    ไม่ลบประวัติ: การเจอซ้ำ = เพิ่ม observation + ขยาย source_modules + อัปเดต
    first_seen(เก่าสุด)/last_seen(ใหม่สุด) + เลือก confidence สูงสุด
    """

    def __init__(self, max_assets: int = 10000):
        self._assets: Dict[str, Dict[str, Any]] = {}   # key -> asset
        self._order: List[str] = []
        self._seq = 0
        self.max_assets = max(1, int(max_assets))
        self.dropped = 0

    @staticmethod
    def _key(asset_type: str, value: str) -> str:
        return f"{asset_type}\x1f{value}"

    def add(self, asset_type: str, value: str, *, source_module: str,
            confidence: float = 0.5, parent_domain: str = "",
            ip_addresses: Optional[Iterable[str]] = None,
            technologies: Optional[Iterable[str]] = None,
            observed_iso: Optional[str] = None,
            evidence: str = "", metadata: Optional[Dict[str, Any]] = None
            ) -> Optional[str]:
        """เพิ่ม/ผสาน asset หนึ่งตัว คืน asset_id (None ถ้า value ไม่ถูกต้อง/เกินเพดาน)"""
        if asset_type not in ASSET_TYPES or not value:
            return None
        key = self._key(asset_type, value)
        now = observed_iso or _now()
        obs = {"source_module": source_module, "observed_iso": now}
        if evidence:
            obs["evidence"] = evidence[:300]

        existing = self._assets.get(key)
        if existing is None:
            if len(self._assets) >= self.max_assets:
                self.dropped += 1
                return None
            self._seq += 1
            aid = f"ASSET-{self._seq:06d}"
            existing = {
                "asset_id": aid,
                "asset_type": asset_type,
                "value": value,
                "parent_domain": parent_domain or "",
                "ip_addresses": [],
                "technologies": [],
                "source_modules": [],
                "first_seen": now,
                "last_seen": now,
                "confidence": 0.0,
                "observations": [],
                "metadata": {},
            }
            self._assets[key] = existing
            self._order.append(key)

        # merge (ไม่ลบของเดิม)
        if source_module and source_module not in existing["source_modules"]:
            existing["source_modules"].append(source_module)
        existing["observations"].append(obs)
        existing["confidence"] = round(max(existing["confidence"], float(confidence)), 2)
        if parent_domain and not existing["parent_domain"]:
            existing["parent_domain"] = parent_domain
        for ip in (ip_addresses or []):
            nip = normalize_ip(ip)
            if nip and nip not in existing["ip_addresses"]:
                existing["ip_addresses"].append(nip)
        for t in (technologies or []):
            if t and t not in existing["technologies"]:
                existing["technologies"].append(t)
        if existing["first_seen"] > now:
            existing["first_seen"] = now
        if existing["last_seen"] < now:
            existing["last_seen"] = now
        if metadata:
            for k, v in metadata.items():
                existing["metadata"].setdefault(k, v)
        return existing["asset_id"]

    def get(self, asset_type: str, value: str) -> Optional[Dict[str, Any]]:
        return self._assets.get(self._key(asset_type, value))

    def id_for(self, asset_type: str, value: str) -> Optional[str]:
        a = self.get(asset_type, value)
        return a["asset_id"] if a else None

    def assets(self) -> List[Dict[str, Any]]:
        return [self._assets[k] for k in self._order]


# ---------------------------------------------------------------------------
# extractors: output ดิบของแต่ละโมดูล -> asset ลง AssetBuilder
# แต่ละตัวทน input ขาด/เพี้ยน (ไม่ให้ record เสียทำ pipeline ล้ม)
# ---------------------------------------------------------------------------

def _safe_dict(x: Any) -> Dict[str, Any]:
    return x if isinstance(x, dict) else {}


def extract_passive_recon(report: Dict[str, Any], b: AssetBuilder) -> None:
    """passive_recon report (recon.run_recon) -> domain/subdomain/ip/dns/tls/tech/http"""
    report = _safe_dict(report)
    if not report.get("ok", True):
        return
    cats = _safe_dict(report.get("categories"))
    tgt = _safe_dict(report.get("target"))
    collected = report.get("collected_at")
    src = "passive_recon"

    domain = normalize_hostname(tgt.get("domain"))
    registered = normalize_hostname(tgt.get("registered")) or (
        registered_domain(domain) if domain else "")

    if registered:
        b.add("root_domain", registered, source_module=src, confidence=0.95,
              parent_domain=registered, observed_iso=collected,
              evidence="passive recon target")
    if domain:
        atype = "subdomain" if (registered and domain != registered) else "root_domain"
        b.add(atype, domain, source_module=src, confidence=0.9,
              parent_domain=registered, observed_iso=collected,
              evidence="passive recon host")
        url = tgt.get("url") or f"https://{domain}"
        nurl = normalize_url(url)
        if nurl:
            b.add("website", nurl, source_module=src, confidence=0.85,
                  parent_domain=registered, observed_iso=collected,
                  evidence="recon website")

    # subdomains
    for r in _safe_dict(cats.get("subdomains")).get("records", []) or []:
        h = normalize_hostname(_safe_dict(r).get("value"))
        if not h:
            continue
        reg = registered_domain(h)
        atype = "subdomain" if h != reg else "root_domain"
        b.add(atype, h, source_module=src, confidence=0.8, parent_domain=reg,
              observed_iso=collected, evidence=_safe_dict(r).get("source", "CT log"))

    # dns records (+ IP association)
    dns = _safe_dict(cats.get("dns"))
    host_ips: List[str] = []
    for r in dns.get("records", []) or []:
        r = _safe_dict(r)
        rtype, val = r.get("type"), r.get("value")
        if not rtype or not val:
            continue
        b.add("dns_record", f"{domain or registered} {rtype} {val}".strip(),
              source_module=src, confidence=0.9, parent_domain=registered,
              observed_iso=collected, evidence=r.get("source", "dns"),
              metadata={"record_type": rtype, "record_value": val, "host": domain})
        if rtype in ("A", "AAAA"):
            nip = normalize_ip(val)
            if nip:
                host_ips.append(nip)
                b.add("ip", nip, source_module=src, confidence=0.9,
                      observed_iso=collected, evidence=f"{domain} {rtype}")
    # ผูก IP เข้ากับ host asset (ของ domain หลัก)
    if domain and host_ips:
        host_asset = b.get("subdomain", domain) or b.get("root_domain", domain)
        if host_asset:
            for ip in host_ips:
                if ip not in host_asset["ip_addresses"]:
                    host_asset["ip_addresses"].append(ip)

    # infrastructure (ip/asn/geo/isp)
    infra = _safe_dict(cats.get("infrastructure"))
    for r in infra.get("records", []) or []:
        r = _safe_dict(r)
        if r.get("type") == "ip":
            nip = normalize_ip(r.get("value"))
            if nip:
                b.add("ip", nip, source_module=src, confidence=0.85,
                      observed_iso=collected, evidence="infrastructure",
                      metadata={k: r.get(k) for k in ("asn", "name") if r.get(k)})

    # tls certificate
    tls = _safe_dict(cats.get("tls")).get("data")
    tls = _safe_dict(tls)
    if tls and (tls.get("subject_cn") or tls.get("san")):
        fp = tls.get("subject_cn") or (tls.get("san") or [""])[0]
        b.add("certificate", f"{fp}", source_module=src, confidence=0.9,
              parent_domain=registered, observed_iso=collected,
              evidence=f"issuer {tls.get('issuer_cn')}",
              metadata={"san": tls.get("san", []), "issuer_cn": tls.get("issuer_cn"),
                        "issuer_org": tls.get("issuer_org"), "subject_cn": tls.get("subject_cn"),
                        "not_after": tls.get("not_after"), "expired": tls.get("expired")})

    # http service
    http = _safe_dict(cats.get("http")).get("data")
    http = _safe_dict(http)
    if http and domain:
        b.add("http_service", f"https://{domain}/", source_module=src, confidence=0.8,
              parent_domain=registered, observed_iso=collected,
              evidence=f"status {http.get('status')}",
              metadata={"server": http.get("server"), "status": http.get("status"),
                        "title": http.get("title"),
                        "security_headers_missing": http.get("security_headers_missing", [])})

    # technologies
    tech_host = domain or registered
    for r in _safe_dict(cats.get("technology")).get("records", []) or []:
        r = _safe_dict(r)
        name = r.get("tech")
        if not name:
            continue
        tv = f"{name} {r.get('version')}".strip() if r.get("version") else name
        b.add("technology", tv, source_module=src,
              confidence=float(r.get("confidence", 0.6)),
              observed_iso=collected, evidence=r.get("evidence", ""),
              metadata={"tech": name, "category": r.get("category"),
                        "version": r.get("version"), "confirmed": r.get("confirmed", False),
                        "host": tech_host})
        # ผูก tech เข้ากับ host
        if tech_host:
            host_asset = (b.get("subdomain", tech_host) or b.get("root_domain", tech_host))
            if host_asset and tv not in host_asset["technologies"]:
                host_asset["technologies"].append(tv)


def extract_web_assessment(assessment: Dict[str, Any], b: AssetBuilder,
                           source: str = "web_vulnerability_assessment") -> None:
    """wva assessment -> website + endpoint (url) + finding asset"""
    assessment = _safe_dict(assessment)
    target = assessment.get("target") or ""
    collected = assessment.get("created_iso")
    host = normalize_hostname(target)
    reg = registered_domain(host) if host else ""
    nurl = normalize_url(target) or (normalize_url(f"https://{host}/") if host else None)
    if nurl:
        b.add("website", nurl, source_module=source, confidence=0.8,
              parent_domain=reg, observed_iso=collected, evidence="wva target")
    for f in assessment.get("findings", []) or []:
        _extract_finding_asset(f, b, source, default_host=host, parent=reg,
                               observed=collected)


def extract_api_assessment(assessment: Dict[str, Any], b: AssetBuilder,
                           source: str = "api_security_assessment") -> None:
    """api assessment -> api host + api_endpoint + finding asset"""
    assessment = _safe_dict(assessment)
    target = assessment.get("target") or ""
    collected = assessment.get("created_iso")
    host = normalize_hostname(target)
    reg = registered_domain(host) if host else ""
    if host:
        b.add("hostname", host, source_module=source, confidence=0.8,
              parent_domain=reg, observed_iso=collected, evidence="api host",
              metadata={"role": "api"})
    for f in assessment.get("findings", []) or []:
        f = _safe_dict(f)
        ep = f.get("endpoint")
        method = f.get("method", "GET")
        ek = endpoint_key(host, method, ep) if ep else None
        if ek:
            b.add("api_endpoint", ek, source_module=source, confidence=0.7,
                  parent_domain=reg, observed_iso=collected,
                  evidence=f.get("rule", ""),
                  metadata={"host": host, "method": method, "path": ep})
        _extract_finding_asset(f, b, source, default_host=host, parent=reg,
                               observed=collected, endpoint_is_api=True)


def extract_active_scan(scan: Dict[str, Any], b: AssetBuilder,
                        source: str = "active_scan") -> None:
    """active_scan -> ip/hostname + network_service (ip:port)"""
    scan = _safe_dict(scan)
    for h in scan.get("hosts", []) or []:
        h = _safe_dict(h)
        ip = normalize_ip(h.get("ip"))
        hostname = normalize_hostname(h.get("hostname"))
        if ip:
            b.add("ip", ip, source_module=source, confidence=0.9, evidence="active scan host")
        if hostname:
            reg = registered_domain(hostname)
            b.add("hostname", hostname, source_module=source, confidence=0.85,
                  parent_domain=reg, evidence="active scan host",
                  ip_addresses=[ip] if ip else None)
        for p in h.get("ports", []) or []:
            p = _safe_dict(p)
            port = p.get("port")
            if ip and port:
                b.add("network_service", f"{ip}:{port}", source_module=source,
                      confidence=0.9, evidence=p.get("banner", ""),
                      metadata={"ip": ip, "port": port, "service": p.get("service"),
                                "hostname": hostname})


def extract_unified_findings(findings: List[Dict[str, Any]], b: AssetBuilder,
                             source: str = "orchestrator") -> None:
    """unified findings (จาก task record) -> finding asset + asset ที่อนุมานจาก affected_asset

    ใช้เมื่อไม่มี native output (เช่น วิเคราะห์ task เก่าที่เก็บไว้) — lossy แต่ยัง
    traceable เพราะคง detection_source + evidence_refs
    """
    for f in findings or []:
        f = _safe_dict(f)
        src = f.get("detection_source") or source
        _extract_finding_asset(
            f, b, src,
            default_host=None, parent="", observed=None,
            is_unified=True)


def _extract_finding_asset(f: Dict[str, Any], b: AssetBuilder, source: str,
                           *, default_host: Optional[str], parent: str,
                           observed: Optional[str], endpoint_is_api: bool = False,
                           is_unified: bool = False) -> None:
    """แปลง finding (schema wva/api หรือ unified) เป็น finding asset + asset ของ target"""
    f = _safe_dict(f)
    if is_unified:
        category = f.get("category", "finding")
        title = f.get("title", category)
        severity = f.get("severity", "INFORMATIONAL")
        affected = f.get("affected_asset", "")
        confidence = float(f.get("confidence", 0.5))
        verification = f.get("verification_status", "INFORMATIONAL")
        evidence = "; ".join(f.get("evidence_refs", []) or [])[:300]
        fid = f.get("finding_id", "")
    else:
        category = f.get("category", "finding")
        title = f.get("rule", category)
        severity = f.get("severity", "LOW")
        affected = f.get("endpoint") or f.get("target", "")
        confidence = float(f.get("confidence", 0.5))
        verification = f.get("state", "INFORMATIONAL")
        evidence = (f.get("evidence") or "")[:300]
        fid = f.get("test_case_id", "")

    # host/endpoint ที่ finding ชี้ไป
    host = None
    endpoint_val = None
    if affected:
        if is_ip(str(affected).split(":")[0]):
            host = None
        else:
            host = normalize_hostname(affected) or default_host
        if "/" in str(affected) or str(affected).startswith("/"):
            endpoint_val = affected
    host = host or default_host
    reg = parent or (registered_domain(host) if host else "")

    # finding asset (คง source ไว้เสมอ -> traceability)
    fval = f"{source}:{category}:{title}:{affected}"[:200]
    b.add("finding", fval, source_module=source, confidence=confidence,
          parent_domain=reg, observed_iso=observed, evidence=evidence,
          metadata={"category": category, "title": title, "severity": severity,
                    "verification_status": verification, "affected_asset": affected,
                    "finding_id": fid, "detection_source": source})

    # asset ของ endpoint/host ที่ถูกกระทบ
    if endpoint_val and host:
        if endpoint_is_api:
            ek = endpoint_key(host, f.get("method", "GET"), endpoint_val)
            if ek:
                b.add("api_endpoint", ek, source_module=source, confidence=0.6,
                      parent_domain=reg, observed_iso=observed, evidence="from finding",
                      metadata={"host": host, "path": endpoint_val})
        else:
            nurl = normalize_url(f"https://{host}{endpoint_val}" if endpoint_val.startswith("/")
                                 else endpoint_val)
            if nurl:
                b.add("website", nurl, source_module=source, confidence=0.6,
                      parent_domain=reg, observed_iso=observed, evidence="from finding")
    elif host and not b.get("subdomain", host) and not b.get("root_domain", host):
        reg2 = registered_domain(host)
        atype = "subdomain" if host != reg2 else "root_domain"
        b.add(atype, host, source_module=source, confidence=0.5,
              parent_domain=reg2, observed_iso=observed, evidence="from finding")
