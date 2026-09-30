"""
cve_tracker.sources.nvd — NIST NVD CVE API 2.0 adapter.

NVD is the primary, richest source: it carries CVSS (v2/v3.0/v3.1/v4.0),
weaknesses (CWE), configurations (CPE with version ranges), references with
controlled tags, and reliable published/lastModified timestamps.

Incremental strategy: NVD supports ``lastModStartDate``/``lastModEndDate``
windows (max 120 days). We keep the last ``lastModified`` epoch we saw as the
cursor and ask only for the window since then, paging with
``startIndex``/``resultsPerPage``. A first run backfills ``backfill_days``.

NVD asks clients to send an API key (higher rate) and to respect its rate
window; the shared fetcher's per-source token bucket handles the pacing, and we
send the key as ``apiKey`` header when configured.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ..enums import SourceKind
from ..models import CVERecord, SourceRecord
from ..enrichment import cvss as cvss_engine
from ..enrichment.cwe import make_weakness
from ..enrichment.cpe import products_from_nvd_configurations
from ..enrichment.references import classify_references
from ..utils import (
    normalize_cve_id,
    to_epoch,
    now_epoch,
    normalize_ws,
    truncate,
)
from ..constants import MAX_DESCRIPTION_STORE
from .base import CVESource, FetchContext, SourceFetchResult


class NVDSource(CVESource):
    name = "nvd"
    kind = SourceKind.NVD.value

    async def fetch(self, ctx: FetchContext) -> SourceFetchResult:
        try:
            return await self._fetch(ctx)
        except Exception as exc:  # last-resort isolation
            self.logger.exception("NVD fetch crashed")
            return self._failure(f"{type(exc).__name__}: {exc}")

    async def _fetch(self, ctx: FetchContext) -> SourceFetchResult:
        results_per_page = int(self.config.options.get("results_per_page", "200") or 200)
        results_per_page = max(1, min(results_per_page, 2000))

        start_dt, end_dt = self._window(ctx)
        headers = {}
        if self.config.api_token:
            headers["apiKey"] = self.config.api_token

        records: List[CVERecord] = []
        start_index = 0
        pages = 0
        total_latency = 0
        highest_modified = ctx.state.last_modified_seen or 0

        while len(records) < ctx.max_records:
            params = {
                "lastModStartDate": _nvd_dt(start_dt),
                "lastModEndDate": _nvd_dt(end_dt),
                "startIndex": str(start_index),
                "resultsPerPage": str(results_per_page),
            }
            result, data = await ctx.fetcher.fetch_json(
                self.config.base_url, source=self.name, headers=headers,
                params=params, timeout=self.config.timeout,
                rate=self.config.rate_limit_per_sec,
            )
            total_latency += result.latency_ms
            pages += 1
            if not data:
                break

            vulns = data.get("vulnerabilities", []) or []
            for item in vulns:
                rec = self._parse_vuln(item)
                if rec is None:
                    continue
                records.append(rec)
                if rec.last_modified_at and rec.last_modified_at > highest_modified:
                    highest_modified = rec.last_modified_at

            total_results = int(data.get("totalResults", 0) or 0)
            start_index += results_per_page
            if start_index >= total_results or not vulns:
                break
            if pages >= 50:  # safety cap on pagination per pass
                break

        return self._success(
            records,
            new_last_modified_seen=highest_modified or None,
            new_cursor=str(highest_modified or ""),
            latency_ms=total_latency,
            pages_fetched=pages,
        )

    # ---------------- incremental window ----------------

    def _window(self, ctx: FetchContext):
        now = datetime.now(timezone.utc)
        if ctx.first_run or not ctx.state.last_modified_seen:
            start = now - timedelta(days=max(1, self.config.backfill_days))
        else:
            # Re-scan a small overlap before the cursor to catch late writes.
            start = datetime.fromtimestamp(
                ctx.state.last_modified_seen, tz=timezone.utc) - timedelta(minutes=5)
        # NVD windows must be <= 120 days.
        if (now - start).days > 119:
            start = now - timedelta(days=119)
        return start, now

    # ---------------- parsing ----------------

    def _parse_vuln(self, item: Dict[str, Any]) -> Optional[CVERecord]:
        cve = (item or {}).get("cve") or {}
        cve_id = normalize_cve_id(cve.get("id"))
        if not cve_id:
            return None

        rec = CVERecord(cve_id=cve_id)
        rec.description = self._pick_description(cve.get("descriptions", []))
        rec.title = truncate(rec.description, 120) if rec.description else cve_id
        rec.published_at = to_epoch(cve.get("published"))
        rec.last_modified_at = to_epoch(cve.get("lastModified"))

        # CVSS metrics (v4/v3.1/v3.0/v2)
        rec.cvss_scores = self._parse_metrics(cve.get("metrics", {}))

        # weaknesses
        for w in cve.get("weaknesses", []) or []:
            for desc in w.get("description", []) or []:
                val = desc.get("value")
                weak = make_weakness(val, source=self.name)
                if weak:
                    rec.weaknesses.append(weak)

        # configurations → products
        rec.products = products_from_nvd_configurations(
            cve.get("configurations"), source=self.name)

        # references
        rec.references = classify_references(cve.get("references", []), source=self.name)

        source_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        rec.sources = [SourceRecord(
            source=self.name, source_kind=self.kind, source_id=cve_id,
            source_url=source_url, fetched_at=now_epoch(), raw=item,
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

    def _parse_metrics(self, metrics: Dict[str, Any]) -> List:
        out = []
        # Key order defines preference; the enrichment picker re-sorts anyway.
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for entry in metrics.get(key, []) or []:
                data = entry.get("cvssData", {}) or {}
                vector = data.get("vectorString", "")
                base = data.get("baseScore")
                severity = (data.get("baseSeverity")
                            or entry.get("baseSeverity") or "")
                version = str(data.get("version", "") or "")
                score = cvss_engine.build_score(
                    version=version or _version_from_key(key),
                    base_score=float(base) if base is not None else None,
                    vector=vector,
                    source=self.name,
                    severity=severity,
                )
                # NVD provides exploitability/impact subscores directly.
                if entry.get("exploitabilityScore") is not None:
                    score.exploitability_score = entry.get("exploitabilityScore")
                if entry.get("impactScore") is not None:
                    score.impact_score = entry.get("impactScore")
                out.append(score)
        return out


def _version_from_key(key: str) -> str:
    return {
        "cvssMetricV40": "4.0", "cvssMetricV31": "3.1",
        "cvssMetricV30": "3.0", "cvssMetricV2": "2.0",
    }.get(key, "3.1")


def _nvd_dt(dt: datetime) -> str:
    """NVD wants ISO-8601 with an explicit offset."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
