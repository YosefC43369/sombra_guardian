# -*- coding: utf-8 -*-
"""active_scan/scanner.py — ไพรมิทีฟสแกนแบบ active (async TCP connect + banner + AXFR)

เปิด socket จริง — จึงเรียกได้ "หลังผ่าน guard.authorize_and_resolve เท่านั้น"
ไม่มี raw-socket/SYN (ไม่ต้องใช้ root และตรวจสอบง่าย); ใช้ TCP connect scan ล้วน

ส่วนประกอบ:
  * PROFILES / service map    ชุดพอร์ต + ชื่อบริการ
  * scan_port / scan_host     connect + วัด latency + grab banner + ระบุบริการ
  * try_zone_transfer         ลอง DNS AXFR (RFC 1035 wire format) — ปกติ server จะปฏิเสธ
"""

from __future__ import annotations

import time
import struct
import socket
import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("modbot.active_scan.scanner")

# reuse token-bucket rate limiter ของโปรเจกต์
try:
    from osint.utils.async_http import RateLimiter
except Exception:  # pragma: no cover
    class RateLimiter:  # fallback เรียบง่าย
        def __init__(self, rate, burst=None):
            self.rate = rate
            self._sem = asyncio.Semaphore(int(burst or max(1, rate)))
        async def acquire(self):
            await asyncio.sleep(1.0 / max(1.0, self.rate))


# ---------------------------------------------------------------------------
# ชุดพอร์ต (profiles)
# ---------------------------------------------------------------------------

_TOP_100 = [
    7, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119,
    135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515,
    543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027,
    1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2375,
    3000, 3128, 3306, 3389, 4443, 4444, 5000, 5432, 5601, 5672, 5900, 5984,
    6379, 7001, 7070, 8000, 8008, 8009, 8080, 8081, 8088, 8089, 8181, 8443,
    8888, 9000, 9042, 9092, 9200, 9300, 9418, 9999, 10000, 11211, 15672,
    27017, 27018, 50070,
]
_QUICK = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
_WEB = [80, 81, 443, 591, 2082, 2087, 2095, 3000, 5000, 8000, 8008, 8080,
        8081, 8088, 8443, 8888, 9000, 9200]
_DB = [1433, 1521, 3306, 5432, 5984, 6379, 7000, 9042, 9200, 11211, 27017, 50070]

PROFILES: Dict[str, List[int]] = {
    "quick": _QUICK,
    "top100": _TOP_100,
    "web": _WEB,
    "db": _DB,
}


# ---------------------------------------------------------------------------
# service map + banner probe
# ---------------------------------------------------------------------------

_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 9300: "elasticsearch",
    11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
}

# พอร์ตที่ควร "ส่ง probe" เพื่อเรียก banner (ส่วนใหญ่ขอให้ server พูดก่อน)
_HTTP_PORTS = {80, 81, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8888, 9000}
_HTTPS_PORTS = {443, 2083, 2087, 2096, 4443, 8443}


def service_for(port: int, banner: str = "") -> str:
    b = banner.lower()
    if "ssh-" in b:
        return "ssh"
    if "http/" in b or "<html" in b or "server:" in b:
        return "http"
    if b.startswith("220") and "ftp" in b:
        return "ftp"
    if b.startswith("220") and ("smtp" in b or "esmtp" in b):
        return "smtp"
    if "-err" in b or "redis" in b:
        return "redis"
    if "mysql" in b or "mariadb" in b:
        return "mysql"
    return _SERVICE.get(port, "unknown")


async def _grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                       port: int, timeout: float) -> str:
    """อ่าน banner — ส่ง probe เบา ๆ เฉพาะพอร์ต HTTP (ที่ไม่พูดก่อน)"""
    try:
        if port in _HTTP_PORTS:
            writer.write(b"HEAD / HTTP/1.0\r\nHost: scan\r\nConnection: close\r\n\r\n")
            await asyncio.wait_for(writer.drain(), timeout=timeout)
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        return data.decode("latin-1", errors="replace").strip()
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return ""


async def scan_port(ip: str, port: int, *, connect_timeout: float,
                    banner_timeout: float, sem: asyncio.Semaphore,
                    limiter: RateLimiter, grab: bool = True) -> Optional[Dict[str, Any]]:
    """สแกนพอร์ตเดียวแบบ TCP connect — คืน dict เฉพาะพอร์ตที่ "open" (ไม่งั้น None)"""
    async with sem:
        await limiter.acquire()
        start = time.monotonic()
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=connect_timeout)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None       # closed/filtered — ไม่รายงาน (ลดสัญญาณรบกวน)
        latency = int((time.monotonic() - start) * 1000)
        banner = ""
        if grab:
            banner = await _grab_banner(reader, writer, port, banner_timeout)
        try:
            if writer is not None:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except (asyncio.TimeoutError, OSError):
            pass
        return {"port": port, "state": "open", "service": service_for(port, banner),
                "banner": banner[:300], "latency_ms": latency}


async def scan_host(ip: str, hostname: str, ports: List[int], *,
                    policy: Dict[str, Any]) -> Dict[str, Any]:
    """สแกนทุกพอร์ตของ host หนึ่ง — คุม concurrency + rate ตาม policy"""
    conc = int(policy.get("concurrency", 100))
    rate = float(policy.get("rate_per_sec", 200.0))
    ctimeout = float(policy.get("connect_timeout", 2.0))
    btimeout = float(policy.get("banner_timeout", 2.0))
    ports = ports[: int(policy.get("max_ports_per_host", 1024))]

    sem = asyncio.Semaphore(conc)
    limiter = RateLimiter(rate, burst=conc)
    tasks = [scan_port(ip, p, connect_timeout=ctimeout, banner_timeout=btimeout,
                       sem=sem, limiter=limiter) for p in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    open_ports = []
    for r in results:
        if isinstance(r, dict):
            open_ports.append(r)
    open_ports.sort(key=lambda x: x["port"])
    return {"ip": ip, "hostname": hostname, "up": bool(open_ports),
            "ports": open_ports}


# ---------------------------------------------------------------------------
# DNS zone transfer (AXFR) — RFC 1035 wire format ผ่าน TCP/53
# ---------------------------------------------------------------------------

def _encode_qname(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        lb = label.encode("idna") if label else b""
        out += struct.pack("!B", len(lb)) + lb
    return out + b"\x00"


def _decode_name(buf: bytes, offset: int) -> Tuple[str, int]:
    """ถอดชื่อ DNS รองรับ compression pointer — คืน (name, offset_ถัดไป)"""
    labels = []
    jumped = False
    next_off = offset
    seen = 0
    while True:
        if offset >= len(buf) or seen > 128:
            break
        length = buf[offset]
        if length & 0xC0 == 0xC0:               # pointer
            ptr = struct.unpack("!H", buf[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                next_off = offset + 2
            offset = ptr
            jumped = True
            seen += 1
            continue
        if length == 0:
            offset += 1
            if not jumped:
                next_off = offset
            break
        labels.append(buf[offset + 1:offset + 1 + length].decode("latin-1", "replace"))
        offset += 1 + length
        if not jumped:
            next_off = offset
    return ".".join(labels), next_off


async def try_zone_transfer(domain: str, nameserver_ip: str,
                            timeout: float = 8.0, max_records: int = 5000
                            ) -> Dict[str, Any]:
    """ลอง AXFR ต่อ nameserver — คืน {ok, refused, records:[...], reason}

    ถ้า server ตั้งค่าถูกต้อง จะ "ปฏิเสธ" (refused=True) ซึ่งเป็นผลที่ปลอดภัย
    ถ้ายอม transfer = การตั้งค่าผิด (เปิดเผยทั้งโซน) — รายงานเป็นข้อสังเกต
    """
    # header: id, flags(standard query), qd=1
    tid = 0x1337
    header = struct.pack("!HHHHHH", tid, 0x0000, 1, 0, 0, 0)
    question = _encode_qname(domain) + struct.pack("!HH", 252, 1)  # QTYPE=AXFR, IN
    msg = header + question
    framed = struct.pack("!H", len(msg)) + msg

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(nameserver_ip, 53), timeout=timeout)
    except (asyncio.TimeoutError, OSError) as e:
        return {"ok": False, "refused": False, "records": [],
                "reason": f"connect: {type(e).__name__}"}
    try:
        writer.write(framed)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        records: List[str] = []
        # อ่านหลาย message (AXFR ส่งเป็นสตรีมของ DNS message ที่มี length prefix)
        buffer = b""
        while len(records) < max_records:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buffer += chunk
            while len(buffer) >= 2:
                mlen = struct.unpack("!H", buffer[:2])[0]
                if len(buffer) < 2 + mlen:
                    break
                dnsmsg = buffer[2:2 + mlen]
                buffer = buffer[2 + mlen:]
                recs, refused = _parse_axfr_message(dnsmsg)
                if refused:
                    return {"ok": True, "refused": True, "records": records,
                            "reason": "server refused AXFR (ตั้งค่าถูกต้อง)"}
                records.extend(recs)
        return {"ok": True, "refused": not records,
                "records": list(dict.fromkeys(records))[:max_records],
                "reason": "" if records else "ไม่มีข้อมูล/ปฏิเสธ"}
    except Exception as e:
        return {"ok": False, "refused": False, "records": [], "reason": str(e)}
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except (asyncio.TimeoutError, OSError):
            pass


def _parse_axfr_message(msg: bytes) -> Tuple[List[str], bool]:
    """แยกชื่อ owner จาก answer records ของ DNS message — คืน (names, refused)"""
    if len(msg) < 12:
        return [], False
    _id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", msg[:12])
    rcode = flags & 0x000F
    if rcode in (5, 9):            # REFUSED / NOTAUTH
        return [], True
    off = 12
    for _ in range(qd):           # ข้าม question section
        _name, off = _decode_name(msg, off)
        off += 4
    names: List[str] = []
    for _ in range(an):
        name, off = _decode_name(msg, off)
        if off + 10 > len(msg):
            break
        _rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
        off += 10 + rdlen
        if name:
            names.append(name)
    return names, False
