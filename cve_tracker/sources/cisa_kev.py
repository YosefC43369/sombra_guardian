"""
cve_tracker.sources.cisa_kev — CISA Known Exploited Vulnerabilities adapter.

The KEV catalogue is one JSON document listing every CVE CISA has confirmed as
exploited in the wild. It is small (a few thousand entries) and updated a few
times a week, so we fetch the whole document with conditional requests
(ETag/Last-Modified) and only reprocess it when it actually changed (304 = skip
entirely). Each entry becomes a minimal :class:`CVERecord` carrying a
:class:`KEVInfo` — the merge step folds that KEV fact onto the full record from
NVD/CVE.org.
"""

from __future__ import annotations

from typing import List

from ..enums import SourceKind, ExploitMaturity
from ..models import CVERecord, SourceRecord
from ..enrichment.kev import parse_kev_entry
from ..utils import now_epoch, normalize_cve_id
from .base import CVESource, FetchContext, SourceFetchResult


class CISAKEVSource(CVESource):
    name = "cisa_kev"
    kind = SourceKind.CISA_KEV.value

    async def fetch(self, ctx: FetchContext) -> SourceFetchResult:
        try:
            return await self._fetch(ctx)
        except Exception as exc:
            self.logger.exception("CISA KEV fetch crashed")
            return self._failure(f"{type(exc).__name__}: {exc}")

    async def _fetch(self, ctx: FetchContext) -> SourceFetchResult:
        result, data = await ctx.fetcher.fetch_json(
            self.config.base_url, source=self.name,
            timeout=self.config.timeout, rate=self.config.rate_limit_per_sec,
            etag=ctx.state.etag, last_modified=ctx.state.http_last_modified,
        )
        if result.not_modified:
            return self._empty(not_modified=True, latency_ms=result.latency_ms,
                               etag=ctx.state.etag,
                               http_last_modified=ctx.state.http_last_modified)
        if not data:
            return self._failure("empty KEV document", degraded=True)

        entries = data.get("vulnerabilities", []) or []
        catalog_version = str(data.get("catalogVersion", "") or "")
        records: List[CVERecord] = []
        for entry in entries:
            kev = parse_kev_entry(entry)
            if kev is None:
                continue
            norm = normalize_cve_id(entry.get("cveID"))
            if not norm:
                continue
            rec = CVERecord(cve_id=norm)
            rec.kev = kev
            rec.exploit_maturity = ExploitMaturity.CONFIRMED.value
            # A KEV record on its own carries a title/date so it still renders
            # even if no richer source has it yet.
            rec.title = kev.vulnerability_name or norm
            rec.published_at = kev.date_added
            rec.last_modified_at = kev.date_added
            rec.sources = [SourceRecord(
                source=self.name, source_kind=self.kind, source_id=norm,
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                fetched_at=now_epoch(), raw=entry,
            )]
            records.append(rec)

        # Bound memory: KEV is small, but respect the ceiling anyway.
        if len(records) > ctx.max_records:
            records = records[-ctx.max_records:]

        return self._success(
            records,
            new_cursor=catalog_version,
            new_etag=result.etag or ctx.state.etag,
            new_http_last_modified=result.last_modified or ctx.state.http_last_modified,
            latency_ms=result.latency_ms,
            pages_fetched=1,
        )
