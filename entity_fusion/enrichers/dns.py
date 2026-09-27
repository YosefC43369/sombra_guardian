"""
entity_fusion.enrichers.dns — passive DNS resolution over DNS-over-HTTPS
(Cloudflare's public resolver). Fetches A / AAAA / MX / TXT / NS for a domain and
emits IP entities plus derived SPF/DMARC hints. Public resolver, no key, no
contact with the target's own servers. IPv4/IPv6 answers are emitted only when
globally routable (SSRF hygiene).
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ..entity import Entity, EntityType, Evidence, SourceRef, Relationship, RelationType
from .. import normalization as norm
from .base import Enricher, EnrichmentResult

_DOH = "https://cloudflare-dns.com/dns-query"
_RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS")


class DNSEnricher(Enricher):
    name = "dns"
    handles = (EntityType.DOMAIN, EntityType.SUBDOMAIN)

    async def _fetch(self, entity: Entity, client: Any) -> EnrichmentResult:
        result = EnrichmentResult()
        domain = norm.canonical_domain(entity.value)
        if not domain:
            result.ok = False
            result.reason = "invalid domain"
            return result
        headers = {"Accept": "application/dns-json"}
        records: dict = {}
        for rtype in _RECORD_TYPES:
            resp = await client.get_json(_DOH, params={"name": domain, "type": rtype},
                                         headers=headers)
            if not resp.ok:
                continue
            try:
                answers = resp.json().get("Answer", []) or []
            except Exception:
                continue
            values = [a.get("data", "").strip('"') for a in answers if a.get("data")]
            if values:
                records[rtype] = values

        for ip_str in records.get("A", []) + records.get("AAAA", []):
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if not ip.is_global:
                continue
            child = Entity(type=EntityType.IP, value=str(ip))
            child.add_source(SourceRef(provider="dns", detail="A/AAAA record"))
            child.add_relationship(Relationship(target_id=entity.id,
                                                type=RelationType.RESOLVES_TO))
            result.entities.append(child)

        txt = records.get("TXT", [])
        result.derived["dns"] = records
        for value in txt:
            low = value.lower()
            if low.startswith("v=spf1"):
                result.derived["spf"] = value
            elif low.startswith("v=dmarc1"):
                result.derived["dmarc"] = value
        if records.get("MX"):
            result.derived["mx"] = records["MX"]
        if records:
            result.evidence.append(Evidence(
                kind="dns_records", value=",".join(records.keys()), weight=0.1,
                source=SourceRef(provider="dns"),
                note=f"resolved {sum(len(v) for v in records.values())} DNS records"))
        else:
            result.ok = False
            result.reason = "no DNS records"
        return result
