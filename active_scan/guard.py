# -*- coding: utf-8 -*-
"""active_scan/guard.py — ด่านอนุญาต + ความปลอดภัยปลายทาง (reuse ของเดิมทั้งหมด)

active scan เปิด socket จริงไปยังเป้าหมาย จึง "ต้องผ่านสองด่านเสมอ ก่อนแตะเป้าหมาย":

  1) scope_policy.evaluate_target()  — เป้าหมายอยู่ในขอบเขตที่ได้รับอนุญาตจริงไหม
                                       (authorization ภายนอก + INCLUDE/EXCLUDE, EXCLUDE ชนะ)
  2) security_testing._forbidden_ip_reason() — IP ปลายทางเป็นสาธารณะล้วนไหม
                                       (บล็อก loopback/private/link-local/metadata/rebind — fail closed)

ด่านทั้งสอง reuse จากของเดิม 100% ไม่เขียนเกณฑ์ใหม่ เพื่อให้ "ความปลอดภัยเป็นแหล่งเดียว"
ด่าน 1 คือสิ่งที่ redteam.py จงใจบังคับ; ด่าน 2 เข้มกว่าขอบเขต และปิดไม่ได้ด้วย policy ใด ๆ
"""

from __future__ import annotations

import asyncio
import logging
import ipaddress
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("modbot.active_scan.guard")

# reuse ด่านอนุญาต/normalize จาก scope_policy
try:
    from scope_policy import (evaluate_target, normalize_target, get_program,
                              TargetType)
    _HAS_SCOPE = True
except Exception:  # pragma: no cover
    _HAS_SCOPE = False

# reuse ด่าน IP + resolver จาก security_testing (แหล่งความจริงเดียวของทั้งโปรเจกต์)
try:
    from security_testing import (_forbidden_ip_reason as forbidden_ip_reason,
                                  _resolve_host as resolve_host)
    _HAS_NETGUARD = True
except Exception:  # pragma: no cover
    _HAS_NETGUARD = False

    def forbidden_ip_reason(ip_text):  # fallback เข้มเท่าเดิม
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            return "DESTINATION_UNPARSEABLE"
        if (ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_private
                or ip.is_reserved or ip.is_multicast):
            return "DESTINATION_NOT_PUBLIC"
        return None

    def resolve_host(host, port):
        import socket
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        return list({i[4][0] for i in infos})


class GateError(Exception):
    pass


def scope_gate(program_id: int, raw_target: str) -> Dict[str, Any]:
    """ด่าน 1: scope — คืน {allowed, reason, detail, normalized}"""
    if not _HAS_SCOPE:
        return {"allowed": False, "reason": "SCOPE_POLICY_UNAVAILABLE",
                "detail": "", "normalized": None}
    prog = get_program(program_id)
    if not prog:
        return {"allowed": False, "reason": "PROGRAM_NOT_FOUND", "detail": "",
                "normalized": None}
    decision = evaluate_target(program_id, raw_target)
    norm = normalize_target(raw_target)
    return {"allowed": bool(decision.allowed), "reason": decision.reason,
            "detail": getattr(decision, "detail", ""), "normalized": norm}


def _expand_cidr(network: str, cap: int) -> Tuple[List[str], Optional[str]]:
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return [], "CIDR_INVALID"
    hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
    if len(hosts) > cap:
        return [], f"CIDR_TOO_LARGE ({len(hosts)} > {cap})"
    return [str(h) for h in hosts], None


async def _resolve_public(host: str) -> Tuple[List[str], Optional[str]]:
    """resolve host แล้ว "ทุก IP ต้องเป็นสาธารณะ" (DNS-rebinding ป้องกันแบบเดียวกับ ST)"""
    try:
        addrs = await asyncio.wait_for(asyncio.to_thread(resolve_host, host, 80),
                                       timeout=10.0)
    except asyncio.TimeoutError:
        return [], "DNS_TIMEOUT"
    except Exception:
        return [], "DNS_RESOLUTION_FAILED"
    if not addrs:
        return [], "DNS_NO_ADDRESS"
    for a in addrs:
        r = forbidden_ip_reason(a)
        if r:
            return [], r          # เจอ IP ไม่สาธารณะแม้ตัวเดียว = ปฏิเสธทั้ง host
    return list(dict.fromkeys(addrs)), None


async def authorize_and_resolve(program_id: int, raw_target: str,
                                max_hosts: int) -> Dict[str, Any]:
    """รวมสองด่าน + แปลงเป็นรายการ host ที่สแกนได้จริง

    คืน {ok, reason, target_type, hosts:[{ip, hostname}]}
    - DENY จาก scope -> ok=False พร้อม reason
    - IP ปลายทางไม่สาธารณะ -> ตัดออก/ปฏิเสธ (fail closed)
    """
    gate = scope_gate(program_id, raw_target)
    if not gate["allowed"]:
        return {"ok": False, "reason": f"SCOPE_DENY:{gate['reason']}",
                "target_type": None, "hosts": []}
    norm = gate["normalized"]
    if norm is None:
        return {"ok": False, "reason": "TARGET_INVALID", "target_type": None, "hosts": []}

    ttype = norm.target_type
    hosts: List[Dict[str, Any]] = []
    normalized_domain = norm.domain if ttype in (TargetType.DOMAIN.value,
                                                 TargetType.URL.value) else None

    if ttype == TargetType.IP.value:
        r = forbidden_ip_reason(norm.ip)
        if r:
            return {"ok": False, "reason": r, "target_type": ttype, "hosts": []}
        hosts = [{"ip": norm.ip, "hostname": norm.ip}]

    elif ttype == TargetType.CIDR.value:
        ips, err = _expand_cidr(norm.network, max_hosts)
        if err:
            return {"ok": False, "reason": err, "target_type": ttype, "hosts": []}
        for ip in ips:
            if forbidden_ip_reason(ip) is None:   # เก็บเฉพาะสาธารณะ
                hosts.append({"ip": ip, "hostname": ip})
        if not hosts:
            return {"ok": False, "reason": "NO_PUBLIC_HOSTS_IN_CIDR",
                    "target_type": ttype, "hosts": []}

    elif ttype in (TargetType.DOMAIN.value, TargetType.URL.value):
        ips, err = await _resolve_public(norm.domain)
        if err:
            return {"ok": False, "reason": err, "target_type": ttype, "hosts": []}
        for ip in ips:
            hosts.append({"ip": ip, "hostname": norm.domain})
    else:
        return {"ok": False, "reason": "TARGET_TYPE_UNSUPPORTED",
                "target_type": ttype, "hosts": []}

    if len(hosts) > max_hosts:
        hosts = hosts[:max_hosts]
    return {"ok": True, "reason": "OK", "target_type": ttype, "hosts": hosts,
            "normalized_domain": normalized_domain}


def revalidate_ip(ip: str) -> Optional[str]:
    """ตรวจ IP ซ้ำก่อน connect จริง (ด่าน 2 อีกชั้น) — คืน None ถ้าผ่าน"""
    return forbidden_ip_reason(ip)
