"""
osint.sources.dns_records — passive DNS record enumeration via DNS-over-HTTPS.

WHAT / WHY. Resolving a domain's public DNS records (A / AAAA / MX / NS / TXT /
CNAME / SOA) is the most basic, entirely passive OSINT step: it reads what the
domain's authoritative servers already publish to the whole internet. We use
DNS-over-HTTPS JSON endpoints (Cloudflare 1.1.1.1 and Google 8.8.8.8) rather
than a UDP resolver so the whole framework keeps a single HTTP chokepoint
(async_http) with its rate limiting, retry and timeouts — no dnspython, no raw
sockets, no dependency the repo does not already carry.

Cloudflare is tried first; Google is the fallback if Cloudflare errors. Each
record becomes a typed record so the orchestrator can merge/​corroborate: MX and
NS values also expose related hostnames worth pivoting on.
"""

import logging
from typing import Dict, List

from .base import Source, SourceResult, SourceStatus
from ..utils import validators

logger = logging.getLogger("modbot.osint.dns")

CLOUDFLARE_DOH = "https://cloudflare-dns.com/dns-query"
GOOGLE_DOH = "https://dns.google/resolve"

# ชนิดเรกคอร์ดที่ดึง + ป้าย type สำหรับระเบียนผลลัพธ์
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
# แม็พ numeric DNS type -> ชื่อ (ใช้ตอนอ่านฟิลด์ Answer[].type)
_RTYPE_NUM = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT",
              28: "AAAA"}


class DnsRecordsSource(Source):
    name = "dns_records"
    kind = "domain"
    requires_key = False

    async def fetch(self, client, target: str) -> SourceResult:
        domain = validators.normalize_domain(target)
        if domain is None:
            return self._invalid(target, "not a valid domain")

        records: List[Dict[str, str]] = []
        seen = set()
        any_answer = False
        errors = 0

        for rtype in RECORD_TYPES:
            answers = await self._query(client, domain, rtype)
            if answers is None:
                errors += 1
                continue
            for value in answers:
                any_answer = True
                key = (rtype, value.lower())
                if key in seen:
                    continue
                seen.add(key)
                records.append(self._record(rtype, value))

        if not records:
            if errors >= len(RECORD_TYPES):
                return self._error(domain, "all DoH queries failed")
            return self._empty(domain, "no DNS records returned")

        return SourceResult(
            self.name, domain, SourceStatus.OK, records=records,
            meta={"record_types": sorted({r["record"] for r in records}),
                  "any_answer": any_answer},
        )

    def _record(self, rtype: str, value: str) -> Dict[str, str]:
        """สร้างระเบียนหนึ่งอัน — MX/NS/CNAME ให้ type='hostname' เพิ่มด้วยเพื่อให้
        orchestrator เอาไป pivot ต่อได้ ส่วน A/AAAA ให้ type='ip'"""
        if rtype in ("A", "AAAA"):
            rec_type = "ip"
        elif rtype in ("MX", "NS", "CNAME"):
            rec_type = "hostname"
        else:
            rec_type = "dns_record"
        return {"type": rec_type, "value": value, "record": rtype,
                "source": self.name}

    async def _query(self, client, domain: str, rtype: str):
        """คืนรายการค่าคำตอบ (list[str]) หรือ None ถ้าคิวรีล้มเหลวทั้งสอง endpoint"""
        answers = await self._query_endpoint(
            client, CLOUDFLARE_DOH, domain, rtype,
            headers={"Accept": "application/dns-json"})
        if answers is not None:
            return answers
        return await self._query_endpoint(client, GOOGLE_DOH, domain, rtype)

    async def _query_endpoint(self, client, url: str, domain: str, rtype: str,
                              headers=None):
        params = {"name": domain, "type": rtype}
        result = await client.get(url, params=params,
                                  headers=headers or {"Accept": "application/dns-json"})
        if not result.ok:
            return None
        try:
            data = result.json()
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        out: List[str] = []
        for ans in data.get("Answer", []) or []:
            if not isinstance(ans, dict):
                continue
            num = ans.get("type")
            got = _RTYPE_NUM.get(num)
            # เก็บเฉพาะที่ตรงชนิดที่ขอ (DoH คืน CNAME แฝงมาบ่อย)
            if got != rtype:
                continue
            value = str(ans.get("data", "")).strip().strip('"')
            if not value:
                continue
            if rtype == "MX":
                # รูปแบบ "10 mail.example.com." -> เอา hostname
                parts = value.split()
                value = parts[-1].rstrip(".") if parts else value
            elif rtype in ("NS", "CNAME"):
                value = value.rstrip(".")
            out.append(value)
        return out
