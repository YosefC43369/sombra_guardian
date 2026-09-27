"""
entity_fusion.enrichers.alienvault — IOC enrichment via AlienVault OTX (the
Open Threat Exchange). This is the primary BLUE-TEAM enricher: given a domain or
IP, it pulls community threat-intel context (passive DNS, related pulses,
associated malware indicators) to enrich an IOC during an investigation.

The OTX API needs a key (free account) read from ``ALIENVAULT_OTX_API_KEY`` or
``OTX_API_KEY`` — never hard-coded. Without a key the enricher is a no-op.
"""

from __future__ import annotations

import os
from typing import Any

from ..entity import Entity, EntityType, Evidence, SourceRef, Relationship, RelationType
from .. import normalization as norm
from .base import Enricher, EnrichmentResult

_BASE = "https://otx.alienvault.com/api/v1/indicators"


class AlienVaultEnricher(Enricher):
    name = "alienvault_otx"
    handles = (EntityType.DOMAIN, EntityType.IP)
    requires_key = True
    env_key = "ALIENVAULT_OTX_API_KEY"

    def api_key(self) -> str:
        return (os.environ.get("ALIENVAULT_OTX_API_KEY")
                or os.environ.get("OTX_API_KEY") or "")

    def _indicator_path(self, entity: Entity) -> str:
        if entity.type == EntityType.IP:
            fam = "IPv6" if ":" in entity.value else "IPv4"
            return f"{_BASE}/{fam}/{entity.value.strip()}"
        return f"{_BASE}/domain/{norm.canonical_domain(entity.value)}"

    async def _fetch(self, entity: Entity, client: Any) -> EnrichmentResult:
        result = EnrichmentResult()
        headers = {"X-OTX-API-KEY": self.api_key()}
        # general section
        resp = await client.get_json(self._indicator_path(entity) + "/general",
                                     headers=headers)
        if not resp.ok:
            result.ok = False
            result.reason = resp.reason
            return result
        try:
            data = resp.json()
        except Exception:
            result.ok = False
            result.reason = "unparseable otx"
            return result
        pulses = (data.get("pulse_info", {}) or {}).get("pulses", []) or []
        result.derived["otx_pulse_count"] = len(pulses)
        result.derived["otx_pulses"] = [p.get("name", "") for p in pulses[:10]]
        weight = 0.0 if not pulses else min(0.4, 0.05 * len(pulses))
        result.evidence.append(Evidence(
            kind="otx_reputation", value=str(len(pulses)), weight=weight,
            source=SourceRef(provider="alienvault_otx"),
            note=f"appears in {len(pulses)} OTX threat pulse(s)"))

        # passive DNS → linked domains/IPs
        resp2 = await client.get_json(self._indicator_path(entity) + "/passive_dns",
                                      headers=headers)
        if resp2.ok:
            try:
                pdns = resp2.json().get("passive_dns", []) or []
            except Exception:
                pdns = []
            for row in pdns[:50]:
                if entity.type == EntityType.DOMAIN and row.get("address"):
                    child = Entity(type=EntityType.IP, value=str(row["address"]))
                    child.add_source(SourceRef(provider="alienvault_otx",
                                               detail="passive dns"))
                    child.add_relationship(Relationship(target_id=entity.id,
                                                        type=RelationType.RESOLVES_TO))
                    result.entities.append(child)
        return result
