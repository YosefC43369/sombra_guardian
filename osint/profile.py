"""
osint.profile — fold merged intelligence into a structured target profile.

The orchestrator returns a flat, de-duplicated list of ``MergedRecord`` with a
corroboration count. This module groups those into the categories an analyst
actually reads — infrastructure, registration, exposure, technology — so the
report and the stored case have a stable shape. It performs no I/O and makes no
inference beyond grouping and counting: the confidence attached to each value is
still just "how many sources reported it", carried straight through from the
orchestrator.
"""

from typing import Any, Dict, List


def _by_type(merged: List[Dict[str, Any]], *types: str) -> List[Dict[str, Any]]:
    wanted = set(types)
    return [m for m in merged if m.get("type") in wanted]


def build(merged: List[Dict[str, Any]]) -> Dict[str, Any]:
    """สร้างโปรไฟล์เป้าหมายจากรายการ merged (แต่ละตัวคือ MergedRecord.to_dict())

    คืน dict ที่จัดกลุ่มแล้ว: infrastructure / registration / exposure / technology
    พร้อมนับจำนวนในแต่ละกลุ่ม
    """
    ips = sorted({m["value"] for m in _by_type(merged, "ip")})
    hostnames = sorted({m["value"] for m in _by_type(merged, "hostname", "subdomain")})
    # แยก nameserver ออกจาก hostname ทั่วไปด้วยฟิลด์ record=NS ถ้ามี
    nameservers = sorted({
        m["value"] for m in merged
        if m.get("type") == "hostname" and (m.get("extra", {}) or {}).get("record") == "NS"
    })
    mx = sorted({
        m["value"] for m in merged
        if m.get("type") == "hostname" and (m.get("extra", {}) or {}).get("record") == "MX"
    })
    asns = sorted({m["value"] for m in _by_type(merged, "asn")})
    netnames = sorted({m["value"] for m in _by_type(merged, "netname")})

    registrar = [m["value"] for m in _by_type(merged, "registrar")]
    events = {}
    for m in _by_type(merged, "registration_event"):
        ev = (m.get("extra", {}) or {}).get("event") or "event"
        events[ev] = m["value"]

    breaches = [
        {"name": m["value"],
         "pwn_count": (m.get("extra", {}) or {}).get("pwn_count"),
         "data_classes": (m.get("extra", {}) or {}).get("data_classes", [])}
        for m in _by_type(merged, "breach")
    ]
    dork_hits = [
        {"url": m["value"], "dork": (m.get("extra", {}) or {}).get("dork", "")}
        for m in _by_type(merged, "dork_hit")
    ]
    dork_plan = [m["value"] for m in _by_type(merged, "dork_query")]
    emails = sorted({m["value"] for m in _by_type(merged, "email")})

    technology = []
    for m in _by_type(merged, "tech"):
        technology.append({
            "value": m["value"],
            "product": (m.get("extra", {}) or {}).get("product"),
            "version": (m.get("extra", {}) or {}).get("version"),
            "confidence": m.get("confidence", 1),
        })

    return {
        "infrastructure": {
            "ips": ips,
            "subdomains": [h for h in hostnames if h not in nameservers and h not in mx],
            "nameservers": nameservers,
            "mx": mx,
            "asns": asns,
            "netnames": netnames,
            "counts": {
                "ips": len(ips),
                "subdomains": len(hostnames),
                "nameservers": len(nameservers),
                "mx": len(mx),
            },
        },
        "registration": {
            "registrar": registrar[0] if registrar else None,
            "events": events,
            "abuse_emails": [e for e in emails],
        },
        "exposure": {
            "breaches": breaches,
            "breach_count": len(breaches),
            "dork_hits": dork_hits,
            "dork_plan": dork_plan,
        },
        "technology": technology,
    }
