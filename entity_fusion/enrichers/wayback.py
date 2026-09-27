"""
entity_fusion.enrichers.wayback — historical URL discovery via the Internet
Archive's public CDX API. Given a domain, lists archived URLs (deduplicated by
path), which reveals historically-linked hosts and pages for the temporal
engine. Public, no key.
"""

from __future__ import annotations

from typing import Any

from ..entity import Entity, EntityType, Evidence, SourceRef
from .. import normalization as norm
from .base import Enricher, EnrichmentResult

_CDX = "https://web.archive.org/cdx/search/cdx"


class WaybackEnricher(Enricher):
    name = "wayback"
    handles = (EntityType.DOMAIN, EntityType.WEBSITE)

    def __init__(self, *, limit: int = 200):
        self.limit = limit

    async def _fetch(self, entity: Entity, client: Any) -> EnrichmentResult:
        result = EnrichmentResult()
        domain = norm.canonical_domain(entity.value)
        if not domain:
            result.ok = False
            result.reason = "invalid domain"
            return result
        params = {"url": f"{domain}/*", "output": "json",
                  "collapse": "urlkey", "fl": "original,timestamp",
                  "limit": str(self.limit)}
        resp = await client.get_json(_CDX, params=params)
        if not resp.ok:
            result.ok = False
            result.reason = resp.reason
            return result
        try:
            rows = resp.json()
        except Exception:
            result.ok = False
            result.reason = "unparseable cdx"
            return result
        # first row is the header
        data_rows = rows[1:] if rows and isinstance(rows[0], list) else rows
        urls = []
        first_ts, last_ts = None, None
        for row in data_rows:
            if not row:
                continue
            original = row[0]
            ts = row[1] if len(row) > 1 else ""
            urls.append(original)
            if ts:
                first_ts = min(first_ts, ts) if first_ts else ts
                last_ts = max(last_ts, ts) if last_ts else ts
        result.derived["wayback_urls"] = urls[:self.limit]
        if first_ts:
            result.derived["wayback_first"] = first_ts
            result.derived["wayback_last"] = last_ts
        result.evidence.append(Evidence(
            kind="wayback_history", value=str(len(urls)), weight=0.05,
            source=SourceRef(provider="wayback", url=_CDX),
            note=f"{len(urls)} archived URL(s)"))
        return result
