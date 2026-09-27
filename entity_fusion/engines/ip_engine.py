"""
entity_fusion.engines.ip_engine — validate and classify an IP record offline
(version, global/private/reserved), reusing the OSINT framework's validators
when present. Passive geo/ASN/rDNS enrichment lives in the enrichers.
"""

from __future__ import annotations

import ipaddress

from ..entity import Entity, EntityType, Evidence
from .base import CorrelationEngine, EngineResult


class IPEngine(CorrelationEngine):
    name = "ip_engine"
    handles = (EntityType.IP,)

    def analyze(self, entity: Entity) -> EngineResult:
        result = EngineResult()
        try:
            ip = ipaddress.ip_address(entity.value.strip())
        except ValueError:
            result.evidence.append(Evidence(
                kind="ip_invalid", value=entity.value, weight=-0.2,
                note="not a valid IP address"))
            return result
        entity.normalized = str(ip)
        result.derived["ip_version"] = ip.version
        result.derived["ip_is_global"] = bool(ip.is_global)
        result.derived["ip_is_private"] = bool(ip.is_private)
        if not ip.is_global:
            # Non-global IPs are not public infrastructure and should never
            # drive an outbound enrichment (SSRF hygiene, matching osint.validators).
            result.evidence.append(Evidence(
                kind="ip_non_global", value=str(ip), weight=0.0,
                note="private/reserved/loopback — excluded from active enrichment"))
        return result
