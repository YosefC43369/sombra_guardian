"""
entity_fusion.enrichers.ipinfo — passive IP geolocation/ASN context via
ipinfo.io. The free endpoint works without a key at a low rate limit; an
``IPINFO_TOKEN`` in the environment (never hard-coded) raises it. Only globally
routable IPs are queried. Emits an ASN entity from the org field when present.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from ..entity import Entity, EntityType, Evidence, SourceRef, Relationship, RelationType
from .base import Enricher, EnrichmentResult


class IPInfoEnricher(Enricher):
    name = "ipinfo"
    handles = (EntityType.IP,)
    env_key = "IPINFO_TOKEN"        # optional

    async def _fetch(self, entity: Entity, client: Any) -> EnrichmentResult:
        result = EnrichmentResult()
        try:
            ip = ipaddress.ip_address(entity.value.strip())
        except ValueError:
            result.ok = False
            result.reason = "invalid ip"
            return result
        if not ip.is_global:
            result.ok = False
            result.reason = "non-global ip not queried"
            return result
        params = {}
        token = self.api_key()
        if token:
            params["token"] = token
        resp = await client.get_json(f"https://ipinfo.io/{ip}/json", params=params)
        if not resp.ok:
            result.ok = False
            result.reason = resp.reason
            return result
        try:
            data = resp.json()
        except Exception:
            result.ok = False
            result.reason = "unparseable ipinfo"
            return result
        for key in ("city", "region", "country", "org", "hostname", "timezone"):
            if data.get(key):
                result.derived[key] = data[key]
        org = str(data.get("org", ""))
        m = re.match(r"AS(\d+)\s+(.*)", org)
        if m:
            asn_val = m.group(1)
            child = Entity(type=EntityType.ASN, value=f"AS{asn_val}")
            child.metadata["asn_name"] = m.group(2)
            child.add_source(SourceRef(provider="ipinfo"))
            child.add_relationship(Relationship(target_id=entity.id,
                                                type=RelationType.APPEARED_IN))
            result.entities.append(child)
        result.evidence.append(Evidence(
            kind="ip_geo", value=str(ip), weight=0.1,
            source=SourceRef(provider="ipinfo"),
            note="passive geolocation/ASN context"))
        return result
