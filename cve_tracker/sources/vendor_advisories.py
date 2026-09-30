"""
cve_tracker.sources.vendor_advisories — extensible vendor-advisory adapter.

Vendors publish advisories as RSS/Atom feeds (or JSON). This adapter is an
*extensible skeleton* (rule §5): operators register vendor feeds via env
(``CVE_VENDOR_FEEDS=microsoft=https://…,cisco=https://…``) and each entry is
scanned for CVE ids; a matched CVE becomes a thin record carrying the vendor
advisory URL as a reference, so the merge attaches the vendor's advisory to the
richer NVD/CVE.org record.

Design intent: adding a new vendor never touches code — you either add a feed
URL, or subclass this and override :meth:`parse_entry` for a vendor with a
bespoke JSON shape, then register it in the registry. It is disabled by default.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..enums import SourceKind, ReferenceType
from ..models import CVERecord, SourceRecord, Reference
from ..enrichment.references import classify_reference
from ..utils import extract_cve_ids, normalize_ws, truncate, now_epoch, to_epoch
from ..constants import MAX_DESCRIPTION_STORE
from .base import CVESource, FetchContext, SourceFetchResult

try:
    import feedparser
    HAVE_FEEDPARSER = True
except Exception:  # pragma: no cover
    feedparser = None  # type: ignore
    HAVE_FEEDPARSER = False


def _load_vendor_feeds() -> Dict[str, str]:
    """Parse ``CVE_VENDOR_FEEDS`` = 'name=url,name2=url2' into a mapping."""
    import os
    raw = (os.getenv("CVE_VENDOR_FEEDS", "") or "").strip()
    feeds: Dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        name, _, url = pair.partition("=")
        name = name.strip()
        url = url.strip()
        if name and url.startswith(("http://", "https://")):
            feeds[name] = url
    return feeds


class VendorAdvisorySource(CVESource):
    name = "vendor_advisory"
    kind = SourceKind.VENDOR_ADVISORY.value

    async def fetch(self, ctx: FetchContext) -> SourceFetchResult:
        feeds = _load_vendor_feeds()
        if not feeds:
            return self._empty()
        if not HAVE_FEEDPARSER:
            return self._failure("feedparser not installed", degraded=True)
        try:
            return await self._fetch(ctx, feeds)
        except Exception as exc:
            self.logger.exception("Vendor advisory fetch crashed")
            return self._failure(f"{type(exc).__name__}: {exc}")

    async def _fetch(self, ctx: FetchContext, feeds: Dict[str, str]) -> SourceFetchResult:
        import asyncio

        all_records: List[CVERecord] = []
        total_latency = 0
        pages = 0
        errors: List[str] = []

        for vendor, url in feeds.items():
            try:
                result = await ctx.fetcher.fetch(
                    url, source=f"{self.name}:{vendor}", timeout=self.config.timeout,
                    rate=self.config.rate_limit_per_sec,
                )
                total_latency += result.latency_ms
                pages += 1
                if not result.content:
                    continue
                parsed = await asyncio.to_thread(feedparser.parse, result.content)
                for entry in parsed.entries[: ctx.max_records]:
                    all_records.extend(self.parse_entry(vendor, url, entry))
            except Exception as exc:
                errors.append(f"{vendor}: {exc}")
                self.logger.warning("VENDOR FEED ERROR | %s | %s", vendor, exc)

        if not all_records and errors:
            return self._failure("; ".join(errors[:3]), degraded=True)

        return self._success(
            all_records[: ctx.max_records],
            latency_ms=total_latency, pages_fetched=pages,
        )

    def parse_entry(self, vendor: str, feed_url: str, entry: Any) -> List[CVERecord]:
        """Turn one feed entry into zero-or-more thin CVE records (one per CVE
        id mentioned). Override for a vendor with a non-feed shape."""
        title = normalize_ws(getattr(entry, "title", "") or "")
        summary = normalize_ws(
            getattr(entry, "summary", "") or getattr(entry, "description", "") or "")
        link = (getattr(entry, "link", "") or "").strip()
        published = to_epoch(getattr(entry, "published", "")
                             or getattr(entry, "updated", ""))
        haystack = f"{title}\n{summary}\n{link}"
        cve_ids = extract_cve_ids(haystack)
        if not cve_ids:
            return []

        out: List[CVERecord] = []
        for cve_id in cve_ids:
            rec = CVERecord(cve_id=cve_id)
            rec.title = truncate(title, 120)
            rec.description = truncate(summary, MAX_DESCRIPTION_STORE)
            rec.published_at = published
            rec.last_modified_at = published
            if link:
                ref = classify_reference(link, title=title, source=self.name)
                # A vendor's own feed link is a vendor advisory.
                if ref.ref_type == ReferenceType.UNKNOWN.value:
                    ref.ref_type = ReferenceType.VENDOR_ADVISORY.value
                rec.references = [ref]
            rec.sources = [SourceRecord(
                source=self.name, source_kind=self.kind, source_id=cve_id,
                source_url=link, fetched_at=now_epoch(),
                raw={"vendor": vendor, "feed": feed_url, "title": title,
                     "summary": summary, "link": link},
            )]
            out.append(rec)
        return out
