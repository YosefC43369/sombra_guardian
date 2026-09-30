"""
cve_tracker.sources.cve_org — MITRE CVE Services (CVE List 5.x) adapter.

CVE.org exposes the authoritative CVE List in the CVE Record Format 5.x via the
``cveawg.mitre.org`` API. We use the ``/cve`` collection with time filters to
list recently published/updated ids, then fetch each record. The 5.x schema
nests everything under ``containers.cna`` (and optional ``adp`` containers):
descriptions, metrics (CVSS), problemTypes (CWE), affected (vendor/product/
versions), references.

To stay gentle (rule §5 — don't scrape aggressively), the per-record fetches go
through the shared rate-limited fetcher and we cap records per pass.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ..enums import SourceKind
from ..models import CVERecord, SourceRecord, AffectedProduct
from ..enrichment import cvss as cvss_engine
from ..enrichment.cwe import make_weakness
from ..enrichment.references import classify_references
from ..enrichment.cpe import merge_products
from ..utils import (
    normalize_cve_id,
    to_epoch,
    now_epoch,
    normalize_ws,
    truncate,
    dedupe_preserve_order,
)
from ..constants import MAX_DESCRIPTION_STORE
from .base import CVESource, FetchContext, SourceFetchResult


class CVEOrgSource(CVESource):
    name = "cve_org"
    kind = SourceKind.CVE_ORG.value

    async def fetch(self, ctx: FetchContext) -> SourceFetchResult:
        try:
            return await self._fetch(ctx)
        except Exception as exc:
            self.logger.exception("CVE.org fetch crashed")
            return self._failure(f"{type(exc).__name__}: {exc}")

    async def _fetch(self, ctx: FetchContext) -> SourceFetchResult:
        start_dt = self._since(ctx)
        # The list endpoint supports time_modified.gt style filters.
        params = {
            "time_modified.gt": start_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "count_only": "0",
        }
        result, data = await ctx.fetcher.fetch_json(
            self.config.base_url, source=self.name, params=params,
            timeout=self.config.timeout, rate=self.config.rate_limit_per_sec,
        )
        if not data:
            return self._empty(latency_ms=result.latency_ms)

        # The listing may return full records (cveRecords) or just ids.
        listing = (data.get("cveRecords") or data.get("cves")
                   or data.get("data") or [])
        records: List[CVERecord] = []
        highest_modified = ctx.state.last_modified_seen or 0
        total_latency = result.latency_ms
        pages = 1

        for item in listing[: ctx.max_records]:
            rec = self._parse_record(item)
            if rec is None:
                continue
            records.append(rec)
            if rec.last_modified_at and rec.last_modified_at > highest_modified:
                highest_modified = rec.last_modified_at

        return self._success(
            records,
            new_last_modified_seen=highest_modified or None,
            new_cursor=str(highest_modified or ""),
            latency_ms=total_latency,
            pages_fetched=pages,
        )

    def _since(self, ctx: FetchContext) -> datetime:
        now = datetime.now(timezone.utc)
        if ctx.first_run or not ctx.state.last_modified_seen:
            return now - timedelta(days=max(1, self.config.backfill_days))
        return datetime.fromtimestamp(
            ctx.state.last_modified_seen, tz=timezone.utc) - timedelta(minutes=5)

    # ---------------- CVE 5.x parsing ----------------

    def _parse_record(self, item: Dict[str, Any]) -> Optional[CVERecord]:
        # A record may be the full 5.x object or a thin listing entry.
        meta = (item or {}).get("cveMetadata") or {}
        cve_id = normalize_cve_id(
            meta.get("cveId") or item.get("cveId") or item.get("id"))
        if not cve_id:
            return None

        rec = CVERecord(cve_id=cve_id)
        rec.published_at = to_epoch(meta.get("datePublished") or item.get("datePublished"))
        rec.last_modified_at = to_epoch(
            meta.get("dateUpdated") or item.get("dateUpdated") or meta.get("datePublished"))

        containers = (item or {}).get("containers") or {}
        cna = containers.get("cna") or {}
        adp_list = containers.get("adp") or []

        rec.description = self._pick_description(cna.get("descriptions", []))
        title = cna.get("title") or ""
        rec.title = truncate(title, 120) if title else (
            truncate(rec.description, 120) if rec.description else cve_id)

        # metrics (CVSS) can live in cna and adp containers
        rec.cvss_scores = self._parse_metrics(cna.get("metrics", []))
        for adp in adp_list:
            rec.cvss_scores += self._parse_metrics(adp.get("metrics", []))

        # problemTypes → CWE
        for pt in cna.get("problemTypes", []) or []:
            for desc in pt.get("descriptions", []) or []:
                cwe = desc.get("cweId") or desc.get("description")
                w = make_weakness(cwe, name=desc.get("description", ""), source=self.name)
                if w:
                    rec.weaknesses.append(w)

        # affected → products
        rec.products = merge_products(self._parse_affected(cna.get("affected", [])))

        # references
        refs = cna.get("references", [])
        for adp in adp_list:
            refs = refs + (adp.get("references", []) or [])
        rec.references = classify_references(refs, source=self.name)

        rec.sources = [SourceRecord(
            source=self.name, source_kind=self.kind, source_id=cve_id,
            source_url=f"https://www.cve.org/CVERecord?id={cve_id}",
            fetched_at=now_epoch(), raw=item,
        )]
        return rec

    def _pick_description(self, descriptions: List[Dict[str, Any]]) -> str:
        en = ""
        for d in descriptions or []:
            if (d.get("lang") or "").lower().startswith("en"):
                en = d.get("value", "")
                break
        if not en and descriptions:
            en = descriptions[0].get("value", "")
        return truncate(normalize_ws(en), MAX_DESCRIPTION_STORE)

    def _parse_metrics(self, metrics: List[Dict[str, Any]]) -> List:
        out = []
        for entry in metrics or []:
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0", "cvssV2"):
                data = entry.get(key)
                if not data:
                    continue
                vector = data.get("vectorString", "")
                base = data.get("baseScore")
                severity = data.get("baseSeverity", "")
                version = str(data.get("version", "") or "").replace("_", ".")
                out.append(cvss_engine.build_score(
                    version=version or _version_from_key(key),
                    base_score=float(base) if base is not None else None,
                    vector=vector, source=self.name, severity=severity,
                ))
        return out

    def _parse_affected(self, affected: List[Dict[str, Any]]) -> List[AffectedProduct]:
        out: List[AffectedProduct] = []
        for a in affected or []:
            vendor = a.get("vendor", "") or ""
            product = a.get("product", "") or ""
            if vendor.lower() in ("n/a", "unknown"):
                vendor = ""
            ap = AffectedProduct(vendor=vendor, product=product, source=self.name,
                                 default_status=a.get("defaultStatus", "") or "")
            affected_versions: List[str] = []
            fixed_versions: List[str] = []
            for v in a.get("versions", []) or []:
                ver = str(v.get("version", "") or "")
                status = (v.get("status", "") or "").lower()
                if status == "affected" and ver and ver != "*":
                    affected_versions.append(ver)
                if v.get("lessThan"):
                    ap.version_end_excluding = str(v.get("lessThan"))
                if v.get("lessThanOrEqual"):
                    ap.version_end_including = str(v.get("lessThanOrEqual"))
                if status == "affected" and v.get("version") and not v.get("lessThan"):
                    if v.get("versionType") and ver.lower() in ("0", "0.0"):
                        ap.version_start_including = ver
            ap.versions_affected = dedupe_preserve_order(affected_versions)
            ap.versions_fixed = dedupe_preserve_order(fixed_versions)
            if ap.vendor or ap.product:
                out.append(ap)
        return out


def _version_from_key(key: str) -> str:
    return {
        "cvssV4_0": "4.0", "cvssV3_1": "3.1", "cvssV3_0": "3.0",
        "cvssV2_0": "2.0", "cvssV2": "2.0",
    }.get(key, "3.1")
