"""
osint.sources.bgpview — ASN / IP context via the BGPView public API
(https://api.bgpview.io). No authentication required.

Given an ASN, returns the announced IPv4/IPv6 prefixes and the holder's name/
country. Given an IP, returns the ASN(s) announcing the covering prefix. This is
routing information published in the global BGP table — public infrastructure
metadata, not information about any person.
"""

import logging
from typing import Dict, List

from .base import Source, SourceResult, SourceStatus
from ..utils import validators

logger = logging.getLogger("modbot.osint.bgpview")

BASE = "https://api.bgpview.io"


class BGPViewASNSource(Source):
    name = "bgpview_asn"
    kind = "asn"
    requires_key = False

    async def fetch(self, client, target: str) -> SourceResult:
        asn = validators.normalize_asn(target)
        if asn is None:
            return self._invalid(target, "not a valid ASN")

        meta_res = await client.get_json(f"{BASE}/asn/{asn}")
        pfx_res = await client.get_json(f"{BASE}/asn/{asn}/prefixes")
        if not meta_res.ok and not pfx_res.ok:
            reason = meta_res.reason or pfx_res.reason or "request failed"
            status = (SourceStatus.RATE_LIMITED if 429 in (meta_res.status, pfx_res.status)
                      else SourceStatus.ERROR)
            return SourceResult(self.name, str(asn), status, reason=reason)

        records: List[Dict[str, str]] = []
        meta: Dict[str, object] = {}
        if meta_res.ok:
            data = (meta_res.json().get("data") or {})
            meta = {"name": data.get("name"), "description": data.get("description_short"),
                    "country": data.get("country_code")}
        if pfx_res.ok:
            data = (pfx_res.json().get("data") or {})
            for fam, key in (("ipv4", "ipv4_prefixes"), ("ipv6", "ipv6_prefixes")):
                for p in (data.get(key) or []):
                    prefix = p.get("prefix")
                    if prefix:
                        records.append({"type": f"{fam}_prefix", "value": prefix,
                                        "source": self.name})
        if not records:
            return self._empty(str(asn), "no prefixes announced")
        return SourceResult(self.name, str(asn), SourceStatus.OK,
                            records=records, meta=meta)


class BGPViewIPSource(Source):
    name = "bgpview_ip"
    kind = "ip"
    requires_key = False

    async def fetch(self, client, target: str) -> SourceResult:
        ip = validators.normalize_ip(target)
        if ip is None:
            return self._invalid(target, "not a valid IP address")
        if not validators.is_public_ip(ip):
            return self._invalid(ip, "non-public IP address")

        res = await client.get_json(f"{BASE}/ip/{ip}")
        if not res.ok:
            status = (SourceStatus.RATE_LIMITED if res.status == 429
                      else SourceStatus.ERROR)
            return SourceResult(self.name, ip, status, reason=res.reason)

        data = (res.json().get("data") or {})
        records: List[Dict[str, str]] = []
        for pfx in (data.get("prefixes") or []):
            asn = (pfx.get("asn") or {})
            if asn.get("asn"):
                records.append({"type": "asn", "value": f"AS{asn['asn']}",
                                "name": asn.get("name"), "source": self.name})
            if pfx.get("prefix"):
                records.append({"type": "prefix", "value": pfx["prefix"],
                                "source": self.name})
        if not records:
            return self._empty(ip, "no routing data")
        return SourceResult(self.name, ip, SourceStatus.OK, records=records,
                            meta={"ptr": data.get("ptr_record")})
