"""
entity_fusion.enrichers.crtsh — Certificate Transparency subdomain discovery,
reusing the OSINT framework's tested ``CrtShSource`` and lifting its records
into subdomain entities linked to the queried domain. Passive, no key.
"""

from __future__ import annotations

from typing import Any

from ..entity import Entity, EntityType, Evidence, SourceRef, Relationship, RelationType
from .. import normalization as norm
from .base import Enricher, EnrichmentResult


class CrtShEnricher(Enricher):
    name = "crtsh"
    handles = (EntityType.DOMAIN,)

    async def _fetch(self, entity: Entity, client: Any) -> EnrichmentResult:
        result = EnrichmentResult()
        try:
            from osint.sources.crtsh import CrtShSource
        except Exception:
            result.ok = False
            result.reason = "osint.sources.crtsh unavailable"
            return result
        domain = norm.canonical_domain(entity.value)
        if not domain:
            result.ok = False
            result.reason = "invalid domain"
            return result
        source_result = await CrtShSource().run(client, domain)
        if not source_result.ok:
            result.ok = False
            result.reason = source_result.reason
            return result
        for rec in source_result.records:
            sub = rec.get("value")
            if not sub:
                continue
            child = Entity(type=EntityType.SUBDOMAIN, value=str(sub))
            child.add_source(SourceRef(provider="crtsh", url="https://crt.sh/"))
            child.add_relationship(Relationship(target_id=entity.id,
                                                type=RelationType.SHARES_CERTIFICATE))
            result.entities.append(child)
        result.evidence.append(Evidence(
            kind="ct_subdomains", value=str(len(result.entities)), weight=0.1,
            source=SourceRef(provider="crtsh"),
            note=f"{len(result.entities)} subdomain(s) from certificate transparency"))
        return result
