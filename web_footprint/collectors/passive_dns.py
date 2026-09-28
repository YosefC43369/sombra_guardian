"""
web_footprint.collectors.passive_dns — public DNS intelligence over DoH.

Resolving a hostname's public DNS records (A / AAAA / CNAME / MX / NS / TXT) is
standard passive reconnaissance: the records are what the authoritative servers
publish to the whole internet. This collector reads them through a public
DNS-over-HTTPS resolver rather than by probing the target's own infrastructure,
which keeps the lookup passive and routed through the shared HTTP client's rate
limiting (spec §15, §16, §17).

It is DNS-as-evidence, not DNS-as-ownership: a shared nameserver or MX host is a
*signal* that two domains may be related, never proof of common ownership (spec
§16, §43). The records feed the graph and hosting-correlation layers, which
label those relationships as signals.

The pure ``parse`` staticmethod converts a DoH JSON answer into records and is
unit-tested with canned resolver output.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .base import Collector, CollectorResult, CollectorStatus
from .. import normalize

# Google's DoH JSON endpoint returns application/json without a special Accept
# header, which keeps the shared client's get_json path simple.
DOH_URL = "https://dns.google/resolve"

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")
# DNS numeric type -> name, for decoding the resolver's Answer rows.
_TYPE_NAMES = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 2: "NS", 16: "TXT"}


class PassiveDNSCollector(Collector):
    name = "passive_dns"
    requires_key = False
    stage = "passive_dns"

    async def fetch(self, client, target: str, limits: Any = None) -> CollectorResult:
        host = normalize.normalize_domain(target)
        if host is None:
            return self._invalid(target, "not a valid domain")
        records: List[Dict[str, Any]] = []
        requests = 0
        errors = 0
        for rtype in RECORD_TYPES:
            result = await client.get_json(DOH_URL, params={"name": host, "type": rtype})
            requests += 1
            if not result.ok:
                errors += 1
                continue
            try:
                payload = result.json()
            except Exception:
                errors += 1
                continue
            records.extend(self.parse(payload, host, rtype))
        if not records and errors:
            res = self._error(host, f"{errors}/{requests} DoH queries failed")
            res.requests_made = requests
            return res
        res = self._ok(host, records, record_types=list(RECORD_TYPES))
        res.requests_made = requests
        return res

    @staticmethod
    def parse(payload: Dict[str, Any], host: str, expected_type: str) -> List[Dict[str, Any]]:
        """Turn one DoH JSON answer into DNS records. Each record carries the
        RR type and value; A/AAAA also yield an ``ip`` record and CNAME/NS/MX a
        ``related_host`` for the graph layer."""
        if not isinstance(payload, dict):
            return []
        out: List[Dict[str, Any]] = []
        for ans in payload.get("Answer", []) or []:
            if not isinstance(ans, dict):
                continue
            rtype = _TYPE_NAMES.get(ans.get("type"), expected_type)
            data = str(ans.get("data", "")).strip().rstrip(".")
            if not data:
                continue
            rec = {"type": "dns_record", "rr_type": rtype, "host": host,
                   "value": data, "source": "passive_dns"}
            out.append(rec)
            if rtype in ("A", "AAAA"):
                ip = normalize.normalize_ip(data)
                if ip and normalize.is_public_ip(ip):
                    out.append({"type": "ip", "value": ip, "host": host,
                                "source": "passive_dns"})
            elif rtype in ("CNAME", "NS"):
                rel = normalize.normalize_domain(data)
                if rel:
                    out.append({"type": "related_host", "value": rel, "host": host,
                                "rr_type": rtype, "source": "passive_dns"})
            elif rtype == "MX":
                # MX data is "<pref> <host>"; keep the mail host.
                mx_host = normalize.normalize_domain(data.split()[-1]) if data.split() else None
                if mx_host:
                    out.append({"type": "related_host", "value": mx_host, "host": host,
                                "rr_type": "MX", "source": "passive_dns"})
        return out
