"""
entity_fusion.enrichers.urlscan — query urlscan.io's PUBLIC search API for prior
scans of a domain. Returns pages/hosts already scanned publicly by the community,
surfacing linked infrastructure without scanning the target ourselves. The
public search endpoint works without a key; a ``URLSCAN_API_KEY`` in the
environment raises limits and exposes more results.
"""

from __future__ import annotations

from typing import Any

from ..entity import Entity, EntityType, Evidence, SourceRef, Relationship, RelationType
from .. import normalization as norm
from .base import Enricher, EnrichmentResult


class URLScanEnricher(Enricher):
    name = "urlscan"
    handles = (EntityType.DOMAIN, EntityType.WEBSITE)
    env_key = "URLSCAN_API_KEY"     # optional

    def __init__(self, *, limit: int = 50):
        self.limit = limit

    async def _fetch(self, entity: Entity, client: Any) -> EnrichmentResult:
        result = EnrichmentResult()
        domain = norm.canonical_domain(entity.value)
        if not domain:
            result.ok = False
            result.reason = "invalid domain"
            return result
        headers = {}
        key = self.api_key()
        if key:
            headers["API-Key"] = key
        params = {"q": f"page.domain:{domain}", "size": str(self.limit)}
        resp = await client.get_json("https://urlscan.io/api/v1/search/",
                                     params=params, headers=headers)
        if not resp.ok:
            result.ok = False
            result.reason = resp.reason
            return result
        try:
            results = resp.json().get("results", []) or []
        except Exception:
            result.ok = False
            result.reason = "unparseable urlscan"
            return result
        seen_ips, seen_domains = set(), set()
        for row in results:
            page = row.get("page", {}) or {}
            ip = page.get("ip")
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                child = Entity(type=EntityType.IP, value=str(ip))
                child.add_source(SourceRef(provider="urlscan",
                                           url=row.get("result", "")))
                child.add_relationship(Relationship(target_id=entity.id,
                                                    type=RelationType.RESOLVES_TO))
                result.entities.append(child)
            server_domain = page.get("domain")
            if server_domain and server_domain not in seen_domains and \
                    norm.canonical_domain(server_domain) != domain:
                seen_domains.add(server_domain)
        result.derived["urlscan_results"] = len(results)
        result.evidence.append(Evidence(
            kind="urlscan_history", value=str(len(results)), weight=0.1,
            source=SourceRef(provider="urlscan"),
            note=f"{len(results)} public urlscan result(s)"))
        return result
