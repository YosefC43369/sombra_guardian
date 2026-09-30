"""
cve_tracker.sources.epss — FIRST.org EPSS enrichment source.

EPSS is not a *discovery* source (it does not find new CVEs); it is an
enrichment feed. Modelled as a source anyway so it flows through the same
merge path: it fetches the highest-EPSS recent CVEs from the FIRST.org API and
emits thin records carrying the EPSS score in provenance, which the merge folds
onto the full records from NVD/CVE.org. That keeps the engine uniform — a source
is a source — without EPSS needing repository access.

API: ``https://api.first.org/data/v1/epss`` (public, no key). We pull ordered by
descending EPSS so the operationally interesting CVEs are enriched first, paging
politely under the shared rate limiter.
"""

from __future__ import annotations

from typing import List

from ..enums import SourceKind
from ..models import CVERecord, SourceRecord
from ..enrichment.epss import parse_epss, apply_epss
from ..utils import now_epoch
from .base import CVESource, FetchContext, SourceFetchResult

EPSS_API = "https://api.first.org/data/v1/epss"


class EPSSSource(CVESource):
    name = "epss"
    kind = SourceKind.OTHER.value

    async def fetch(self, ctx: FetchContext) -> SourceFetchResult:
        try:
            return await self._fetch(ctx)
        except Exception as exc:
            self.logger.exception("EPSS fetch crashed")
            return self._failure(f"{type(exc).__name__}: {exc}")

    async def _fetch(self, ctx: FetchContext) -> SourceFetchResult:
        base = self.config.base_url or EPSS_API
        per_page = 200
        records: List[CVERecord] = []
        total_latency = 0
        pages = 0
        offset = 0

        while len(records) < ctx.max_records:
            params = {"order": "!epss", "limit": str(per_page), "offset": str(offset)}
            result, data = await ctx.fetcher.fetch_json(
                base, source=self.name, params=params,
                timeout=self.config.timeout, rate=self.config.rate_limit_per_sec)
            total_latency += result.latency_ms
            pages += 1
            if not data:
                break
            rows = data.get("data", []) or []
            if not rows:
                break
            for row in rows:
                epss = parse_epss(row)
                if epss is None:
                    continue
                rec = CVERecord(cve_id=epss.cve_id)
                apply_epss(rec, epss)
                rec.sources = [SourceRecord(
                    source=self.name, source_kind=self.kind, source_id=epss.cve_id,
                    source_url="https://www.first.org/epss/", fetched_at=now_epoch(),
                    raw=row)]
                records.append(rec)
            offset += per_page
            total = int(data.get("total", 0) or 0)
            if offset >= total or pages >= 10:
                break

        return self._success(
            records[: ctx.max_records], latency_ms=total_latency, pages_fetched=pages)
