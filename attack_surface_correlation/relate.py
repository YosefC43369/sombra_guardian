# -*- coding: utf-8 -*-
"""attack_surface_correlation/relate.py — ตรวจจับความสัมพันธ์ + correlation rules (pure)

รับ list ของ normalized asset (จาก normalize.py) แล้วสร้าง "correlation" ระหว่าง asset
ตามกฎที่กำหนด โดยมี "หลักฐานรองรับ" ทุกเส้น และ "ไม่สร้างความสัมพันธ์ที่ไม่มีหลักฐาน"

กฎกันผลบวกลวง (สำคัญมากตามสเปค):
  * IP/CDN/โฮสต์ร่วม ไม่ถือเป็นหลักฐานว่าเป็นเจ้าของเดียวกัน — ติดป้าย
    ownership="observed_shared_infra" + hypothesis=True + confidence ต่ำ
  * ความเป็นเจ้าของเดียวกันยืนยันได้จาก parent domain ที่ตรวจสอบแล้วเท่านั้น
    (contains/subdomain) -> ownership="confirmed"

correlation:
  {correlation_id, rule, relationship, source, target, confidence, ownership,
   hypothesis, evidence, source_modules, explanation, detected_iso}
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ชุด CDN/โครงสร้างพื้นฐานสาธารณะ — การใช้ร่วมกันไม่พิสูจน์ความเป็นเจ้าของ
_SHARED_INFRA_TECH = {
    "cloudflare", "amazon cloudfront", "cloudfront", "fastly", "akamai",
    "varnish", "vercel", "netlify", "sucuri", "imperva/incapsula", "aws waf",
    "cloudflare waf", "google cloud", "azure",
}

# ช่วง IP ที่มักเป็น shared hosting/CDN จะไม่ถูกตัดสินว่าเจ้าของเดียวกัน (ใช้ heuristic จำนวนโดเมน)
_SHARED_IP_DOMAIN_THRESHOLD = 2   # IP เดียวผูกหลาย registered domain -> ถือเป็น shared infra


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class _CorrelationSink:
    def __init__(self, threshold: float):
        self._out: List[Dict[str, Any]] = []
        self._seen: set = set()
        self._seq = 0
        self.threshold = threshold

    def add(self, *, rule: str, relationship: str, source: str, target: str,
            confidence: float, evidence: List[str], source_modules: List[str],
            explanation: str, ownership: str = "confirmed",
            hypothesis: bool = False) -> None:
        if not source or not target or source == target:
            return
        # กันซ้ำ (ไม่สนทิศ สำหรับความสัมพันธ์ symmetric-ish)
        dedupe_key = (rule, relationship, source, target)
        if dedupe_key in self._seen:
            return
        conf = round(float(confidence), 2)
        if conf < self.threshold:
            return
        self._seen.add(dedupe_key)
        self._seq += 1
        self._out.append({
            "correlation_id": f"CORR-{self._seq:06d}",
            "rule": rule,
            "relationship": relationship,
            "source": source,
            "target": target,
            "confidence": conf,
            "ownership": ownership,
            "hypothesis": bool(hypothesis),
            "evidence": evidence[:8],
            "source_modules": sorted(set(source_modules)),
            "explanation": explanation,
            "detected_iso": _now(),
        })

    def results(self) -> List[Dict[str, Any]]:
        return self._out


def _index(assets: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {a["asset_id"]: a for a in assets}


def _by_type(assets: List[Dict[str, Any]], *types: str) -> List[Dict[str, Any]]:
    s = set(types)
    return [a for a in assets if a["asset_type"] in s]


def correlate_assets(assets: List[Dict[str, Any]],
                     confidence_threshold: float = 0.7) -> List[Dict[str, Any]]:
    """สร้าง correlation ทั้งหมดจาก asset — เรียงตาม confidence มาก->น้อย"""
    sink = _CorrelationSink(confidence_threshold)

    _rule_domain_hierarchy(assets, sink)
    _rule_dns_and_resolution(assets, sink)
    _rule_certificate(assets, sink)
    _rule_website_endpoint(assets, sink)
    _rule_finding_links(assets, sink)
    _rule_shared_ip(assets, sink)
    _rule_shared_certificate(assets, sink)
    _rule_shared_technology(assets, sink)
    _rule_network_service(assets, sink)

    out = sink.results()
    out.sort(key=lambda c: -c["confidence"])
    return out


# ---------------------------------------------------------------------------
# กฎความเป็นเจ้าของ/โครงสร้างที่ "ยืนยันได้" (ownership=confirmed)
# ---------------------------------------------------------------------------

def _rule_domain_hierarchy(assets, sink) -> None:
    """root_domain -> subdomain (contains) เมื่อ parent domain ตรงกันแบบตรวจสอบได้"""
    roots = {a["value"]: a for a in _by_type(assets, "root_domain")}
    for sub in _by_type(assets, "subdomain", "hostname"):
        parent = sub.get("parent_domain")
        host = sub["value"]
        if not parent or host == parent:
            continue
        # subdomain ต้องลงท้ายด้วย parent จริง ๆ (ตรวจสอบได้)
        if not (host == parent or host.endswith("." + parent)):
            continue
        root = roots.get(parent)
        if root is None:
            continue
        sink.add(rule="same_verified_parent_domain", relationship="contains",
                 source=root["asset_id"], target=sub["asset_id"], confidence=1.0,
                 evidence=[f"{host} เป็น subdomain ของ {parent} (suffix ตรง)"],
                 source_modules=sub.get("source_modules", []),
                 explanation=f"{parent} ครอบคลุม {host} โดยตรง (ความเป็นเจ้าของยืนยันจากชื่อโดเมน)",
                 ownership="confirmed")


def _rule_dns_and_resolution(assets, sink) -> None:
    """host -> dns_record (has_dns_record) และ host -> ip (resolves_to)"""
    hosts = {a["value"]: a for a in _by_type(assets, "root_domain", "subdomain", "hostname")}
    ip_assets = {a["value"]: a for a in _by_type(assets, "ip")}

    for dns in _by_type(assets, "dns_record"):
        host = (dns.get("metadata") or {}).get("host")
        h = hosts.get(host)
        if h:
            sink.add(rule="dns_record_of_host", relationship="has_dns_record",
                     source=h["asset_id"], target=dns["asset_id"], confidence=0.9,
                     evidence=[dns["value"]],
                     source_modules=dns.get("source_modules", []),
                     explanation=f"{host} มี DNS record: {dns['value']}",
                     ownership="confirmed")

    # resolves_to: host มี ip_addresses ที่เป็น asset ด้วย
    for h in hosts.values():
        for ip in h.get("ip_addresses", []):
            ipa = ip_assets.get(ip)
            if ipa:
                sink.add(rule="host_resolves_to_ip", relationship="resolves_to",
                         source=h["asset_id"], target=ipa["asset_id"], confidence=0.95,
                         evidence=[f"{h['value']} -> {ip} (A/AAAA)"],
                         source_modules=list(set(h.get("source_modules", []) +
                                                 ipa.get("source_modules", []))),
                         explanation=f"{h['value']} ชี้ไปที่ {ip} ตาม DNS",
                         ownership="observed_shared_infra" if _ip_is_shared(assets, ip)
                         else "confirmed",
                         hypothesis=_ip_is_shared(assets, ip))


def _rule_certificate(assets, sink) -> None:
    """host -> certificate (secured_by) เมื่อ host อยู่ใน SAN หรือ subject_cn"""
    hosts = {a["value"]: a for a in _by_type(assets, "root_domain", "subdomain", "hostname")}
    for cert in _by_type(assets, "certificate"):
        meta = cert.get("metadata") or {}
        san = set((meta.get("san") or []))
        cn = meta.get("subject_cn")
        covered = set(san)
        if cn:
            covered.add(cn)
        for name in covered:
            h = hosts.get((name or "").lower().lstrip("*.").rstrip("."))
            if h:
                sink.add(rule="host_secured_by_certificate", relationship="secured_by",
                         source=h["asset_id"], target=cert["asset_id"], confidence=0.9,
                         evidence=[f"{h['value']} อยู่ใน SAN/CN ของใบรับรอง"],
                         source_modules=cert.get("source_modules", []),
                         explanation=f"{h['value']} ใช้ใบรับรอง TLS นี้ (issuer {meta.get('issuer_cn')})",
                         ownership="confirmed")


def _rule_website_endpoint(assets, sink) -> None:
    """host -> website/http_service/api_endpoint (serves/exposes_endpoint)"""
    hosts = {a["value"]: a for a in _by_type(assets, "root_domain", "subdomain", "hostname")}

    def _host_of(asset) -> Optional[str]:
        meta = asset.get("metadata") or {}
        if meta.get("host"):
            return meta["host"]
        # แกะ host จาก value (url หรือ "METHOD host/path")
        v = asset["value"]
        if "://" in v:
            return v.split("://", 1)[1].split("/", 1)[0].split(":")[0]
        if " " in v:
            return v.split(" ", 1)[1].split("/", 1)[0]
        return None

    for site in _by_type(assets, "website", "http_service"):
        hv = _host_of(site)
        h = hosts.get(hv) if hv else None
        if h:
            sink.add(rule="host_serves_site", relationship="serves",
                     source=h["asset_id"], target=site["asset_id"], confidence=0.85,
                     evidence=[site["value"]],
                     source_modules=site.get("source_modules", []),
                     explanation=f"{h['value']} ให้บริการ {site['asset_type']} {site['value']}",
                     ownership="confirmed")
    for ep in _by_type(assets, "api_endpoint"):
        hv = _host_of(ep)
        h = hosts.get(hv) if hv else None
        if h:
            sink.add(rule="host_exposes_api_endpoint", relationship="exposes_endpoint",
                     source=h["asset_id"], target=ep["asset_id"], confidence=0.8,
                     evidence=[ep["value"]],
                     source_modules=ep.get("source_modules", []),
                     explanation=f"{h['value']} เปิด API endpoint {ep['value']}",
                     ownership="confirmed")


def _rule_finding_links(assets, sink) -> None:
    """asset -> finding (has_finding) เชื่อม finding เข้ากับ host/endpoint ที่กระทบ

    confidence ของเส้นนี้ = "ความมั่นใจว่า finding อยู่บน asset นี้" (linkage) ไม่ใช่
    severity/confidence ของตัว finding เอง — สองอย่างนี้แยกกันตามสเปค (relationship
    strength ≠ finding confidence). severity/confidence ของ finding เก็บไว้ใน evidence
    """
    targets: Dict[str, Dict[str, Any]] = {}
    for a in _by_type(assets, "website", "http_service", "api_endpoint",
                      "root_domain", "subdomain", "hostname"):
        targets[a["value"]] = a

    hosts = {a["value"]: a for a in _by_type(assets, "root_domain", "subdomain", "hostname")}

    for fnd in _by_type(assets, "finding"):
        meta = fnd.get("metadata") or {}
        affected = meta.get("affected_asset") or ""
        ev = [f"finding: {meta.get('severity')}/{meta.get('verification_status')} "
              f"{meta.get('category')} @ {affected} "
              f"(finding confidence {fnd.get('confidence')})"]
        # เลือก target ที่ "จำเพาะที่สุด" (value ยาวสุดที่ match) — เส้นแน่นอน
        best = None
        best_len = -1
        if affected:
            for val, a in targets.items():
                if (affected in val or val in affected) and len(val) > best_len:
                    best, best_len = a, len(val)
        if best is not None:
            sink.add(rule="finding_on_asset", relationship="has_finding",
                     source=best["asset_id"], target=fnd["asset_id"], confidence=0.9,
                     evidence=ev, source_modules=fnd.get("source_modules", []),
                     explanation=f"{best['value']} มี finding: {meta.get('title')} "
                                 f"(severity {meta.get('severity')})",
                     ownership="confirmed")
            continue
        # fallback: ผูกกับ host จาก affected host
        h = hosts.get((affected or "").split("/")[0].split(":")[0])
        if h:
            sink.add(rule="finding_on_host", relationship="has_finding",
                     source=h["asset_id"], target=fnd["asset_id"], confidence=0.8,
                     evidence=ev, source_modules=fnd.get("source_modules", []),
                     explanation=f"{h['value']} เกี่ยวข้องกับ finding {meta.get('title')}",
                     ownership="confirmed")


def _rule_network_service(assets, sink) -> None:
    """ip -> network_service (exposes_service)"""
    ips = {a["value"]: a for a in _by_type(assets, "ip")}
    for svc in _by_type(assets, "network_service"):
        ip = (svc.get("metadata") or {}).get("ip")
        ipa = ips.get(ip)
        if ipa:
            sink.add(rule="ip_exposes_service", relationship="exposes_service",
                     source=ipa["asset_id"], target=svc["asset_id"], confidence=0.9,
                     evidence=[svc["value"]],
                     source_modules=svc.get("source_modules", []),
                     explanation=f"{ip} เปิดบริการ {svc['value']} "
                                 f"({(svc.get('metadata') or {}).get('service')})",
                     ownership="confirmed")


# ---------------------------------------------------------------------------
# กฎ "โครงสร้างพื้นฐานร่วม" — สังเกตได้แต่ไม่พิสูจน์ความเป็นเจ้าของ (hypothesis)
# ---------------------------------------------------------------------------

def _registered_of(asset: Dict[str, Any]) -> str:
    return asset.get("parent_domain") or asset.get("value", "")


def _ips_to_hosts(assets) -> Dict[str, List[Dict[str, Any]]]:
    m: Dict[str, List[Dict[str, Any]]] = {}
    for h in _by_type(assets, "root_domain", "subdomain", "hostname"):
        for ip in h.get("ip_addresses", []):
            m.setdefault(ip, []).append(h)
    return m


def _ip_is_shared(assets, ip: str) -> bool:
    hosts = _ips_to_hosts(assets).get(ip, [])
    regs = {_registered_of(h) for h in hosts if _registered_of(h)}
    return len(regs) >= _SHARED_IP_DOMAIN_THRESHOLD


def _rule_shared_ip(assets, sink) -> None:
    """หลายโฮสต์ (ต่าง registered domain) ใช้ IP เดียวกัน -> observed_shared_infra

    ไม่สรุปว่าเจ้าของเดียวกัน: ติด hypothesis + ownership=observed_shared_infra
    """
    for ip, hosts in _ips_to_hosts(assets).items():
        if len(hosts) < 2:
            continue
        # จับคู่เฉพาะโฮสต์ที่ "ต่าง registered domain" (โฮสต์ domain เดียวกันไป rule hierarchy แล้ว)
        for i in range(len(hosts)):
            for j in range(i + 1, len(hosts)):
                a, bb = hosts[i], hosts[j]
                ra, rb = _registered_of(a), _registered_of(bb)
                if ra and rb and ra == rb:
                    continue   # โดเมนเดียวกัน -> ไม่ใช่ shared infra ข้ามเจ้าของ
                sink.add(rule="shared_ip_address", relationship="shared_infrastructure",
                         source=a["asset_id"], target=bb["asset_id"], confidence=0.75,
                         evidence=[f"ทั้งคู่ resolve ไปที่ {ip}"],
                         source_modules=list(set(a.get("source_modules", []) +
                                                 bb.get("source_modules", []))),
                         explanation=(f"{a['value']} และ {bb['value']} ใช้ IP {ip} ร่วมกัน — "
                                      f"เป็นการสังเกตโครงสร้างพื้นฐานร่วม ไม่ใช่หลักฐานว่าเป็น "
                                      f"เจ้าของเดียวกัน (อาจเป็น shared hosting/CDN)"),
                         ownership="observed_shared_infra", hypothesis=True)


def _rule_shared_certificate(assets, sink) -> None:
    """ใบรับรองใบเดียว ครอบหลาย registered domain -> observed_shared_infra (hypothesis)

    SAN ที่มีหลายโดเมนอาจเป็น multi-tenant/shared cert — ไม่สรุปเจ้าของเดียวกัน
    """
    for cert in _by_type(assets, "certificate"):
        meta = cert.get("metadata") or {}
        san = [s for s in (meta.get("san") or []) if s]
        regs: Dict[str, str] = {}
        for name in san:
            nm = name.lower().lstrip("*.").rstrip(".")
            parts = nm.split(".")
            reg = ".".join(parts[-2:]) if len(parts) >= 2 else nm
            regs.setdefault(reg, nm)
        if len(regs) >= 2:
            names = list(regs.values())
            sink.add(rule="shared_certificate", relationship="shared_infrastructure",
                     source=cert["asset_id"], target=cert["asset_id"] + ":san",
                     confidence=0.7,
                     evidence=[f"SAN ครอบ {len(regs)} โดเมน: {', '.join(names[:6])}"],
                     source_modules=cert.get("source_modules", []),
                     explanation=(f"ใบรับรองนี้ครอบหลาย registered domain ({len(regs)}) — "
                                  f"บ่งชี้โครงสร้างร่วม/multi-tenant ไม่ใช่หลักฐานความเป็น "
                                  f"เจ้าของเดียวกัน"),
                     ownership="observed_shared_infra", hypothesis=True)


def _rule_shared_technology(assets, sink) -> None:
    """หลาย asset ใช้เทคโนโลยีเดียวกัน -> shared_technology

    เทคที่เป็น CDN/WAF สาธารณะ: ติด hypothesis (ใช้ร่วมกันเป็นเรื่องปกติ)
    """
    tech_hosts: Dict[str, List[Tuple[str, str]]] = {}   # tech_name -> [(asset_id, host)]
    for t in _by_type(assets, "technology"):
        meta = t.get("metadata") or {}
        name = (meta.get("tech") or t["value"]).lower()
        host = meta.get("host")
        tech_hosts.setdefault(name, []).append((t["asset_id"], host or t["value"]))

    for name, entries in tech_hosts.items():
        hosts = sorted({h for _, h in entries if h})
        if len(hosts) < 2:
            continue
        shared_infra = name in _SHARED_INFRA_TECH
        # confidence = ความมั่นใจว่า "ใช้เทคโนโลยีนี้ร่วมกันจริง" (ข้อเท็จจริงที่สังเกตได้) —
        # ส่วนการตีความว่าเป็นเจ้าของเดียวกันเป็นสมมติฐาน (hypothesis=True) เสมอ
        rep = entries[0][0]
        sink.add(rule="shared_application_technology", relationship="shared_technology",
                 source=rep, target=f"tech:{name}", confidence=0.75 if shared_infra else 0.8,
                 evidence=[f"{name} ปรากฏบน {len(hosts)} โฮสต์: {', '.join(hosts[:6])}"],
                 source_modules=[], explanation=(
                     f"{name} ใช้ร่วมกันบน {len(hosts)} โฮสต์" +
                     (" — เป็นผู้ให้บริการสาธารณะ (CDN/WAF) การใช้ร่วมกันไม่บ่งชี้เจ้าของเดียวกัน"
                      if shared_infra else " — อาจมาจาก stack/ทีมเดียวกัน (ควรตรวจสอบเพิ่ม)")),
                 ownership="observed_shared_infra" if shared_infra else "observed",
                 hypothesis=True)
