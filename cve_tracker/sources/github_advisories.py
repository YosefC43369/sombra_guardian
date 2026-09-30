"""
cve_tracker.sources.github_advisories — GitHub Security Advisories adapter.

GitHub publishes reviewed advisories (GHSA-…) at ``/advisories``, many mapped to
a CVE id. The REST endpoint supports ``sort=updated`` + ``per_page`` +
cursor-style pagination via the ``Link`` header, and needs a token for a usable
rate limit — so the source is only enabled by default when ``CVE_GITHUB_TOKEN``
(or ``GITHUB_TOKEN``) is set.

We key each record on its CVE id when present; a GHSA with no CVE is kept under
its GHSA id as an alias-only record so the merge can still attach its references
and CVSS to a CVE that arrives later from another source.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..enums import SourceKind, ExploitMaturity
from ..models import CVERecord, SourceRecord, AffectedProduct
from ..enrichment import cvss as cvss_engine
from ..enrichment.cwe import make_weakness
from ..enrichment.references import classify_references
from ..utils import (
    normalize_cve_id,
    normalize_ghsa_id,
    to_epoch,
    now_epoch,
    normalize_ws,
    truncate,
    dedupe_preserve_order,
)
from ..constants import MAX_DESCRIPTION_STORE
from .base import CVESource, FetchContext, SourceFetchResult


class GitHubAdvisorySource(CVESource):
    name = "github_advisory"
    kind = SourceKind.GITHUB_ADVISORY.value

    async def fetch(self, ctx: FetchContext) -> SourceFetchResult:
        if not self.config.api_token:
            # Without a token the rate limit makes this source pointless; skip
            # cleanly rather than burn the unauthenticated budget.
            return self._empty()
        try:
            return await self._fetch(ctx)
        except Exception as exc:
            self.logger.exception("GitHub advisories fetch crashed")
            return self._failure(f"{type(exc).__name__}: {exc}")

    async def _fetch(self, ctx: FetchContext) -> SourceFetchResult:
        per_page = int(self.config.options.get("per_page", "100") or 100)
        per_page = max(1, min(per_page, 100))
        headers = {
            "Authorization": f"Bearer {self.config.api_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        params = {"sort": "updated", "direction": "desc", "per_page": str(per_page)}
        if ctx.state.last_modified_seen and not ctx.first_run:
            from datetime import datetime, timezone
            since = datetime.fromtimestamp(
                ctx.state.last_modified_seen, tz=timezone.utc)
            params["updated"] = ">=" + since.strftime("%Y-%m-%dT%H:%M:%SZ")

        result, data = await ctx.fetcher.fetch_json(
            self.config.base_url, source=self.name, headers=headers,
            params=params, timeout=self.config.timeout,
            rate=self.config.rate_limit_per_sec,
        )
        if not data:
            return self._empty(latency_ms=result.latency_ms)
        if isinstance(data, dict):
            data = data.get("advisories") or data.get("data") or []

        records: List[CVERecord] = []
        highest = ctx.state.last_modified_seen or 0
        for adv in data[: ctx.max_records]:
            rec = self._parse_advisory(adv)
            if rec is None:
                continue
            records.append(rec)
            if rec.last_modified_at and rec.last_modified_at > highest:
                highest = rec.last_modified_at

        return self._success(
            records,
            new_last_modified_seen=highest or None,
            new_cursor=str(highest or ""),
            latency_ms=result.latency_ms,
            pages_fetched=1,
        )

    def _parse_advisory(self, adv: Dict[str, Any]) -> Optional[CVERecord]:
        ghsa = normalize_ghsa_id(adv.get("ghsa_id"))
        cve_id = normalize_cve_id(adv.get("cve_id"))
        # Key the record on the CVE when present; otherwise fall back to GHSA so
        # nothing is lost (it merges later if a CVE mapping appears).
        primary = cve_id or ghsa
        if not primary:
            return None
        rec = CVERecord(cve_id=cve_id or "CVE-0000-0000")  # sentinel for non-CVE
        if not cve_id and ghsa:
            # Non-CVE GHSA: store under a synthetic key we can still index.
            rec.cve_id = ghsa  # not a CVE id; repository treats it as alias key
        if ghsa:
            rec.aliases = dedupe_preserve_order(rec.aliases + [ghsa])

        rec.title = truncate(adv.get("summary", "") or "", 120)
        rec.description = truncate(
            normalize_ws(adv.get("description", "") or adv.get("summary", "")),
            MAX_DESCRIPTION_STORE)
        rec.published_at = to_epoch(adv.get("published_at"))
        rec.last_modified_at = to_epoch(adv.get("updated_at") or adv.get("published_at"))

        # CVSS
        cvss = adv.get("cvss") or {}
        vector = cvss.get("vector_string") or ""
        score = cvss.get("score")
        cvss_v4 = adv.get("cvss_severities", {}).get("cvss_v4", {}) if isinstance(
            adv.get("cvss_severities"), dict) else {}
        if vector or score is not None:
            rec.cvss_scores.append(cvss_engine.build_score(
                version="3.1", base_score=float(score) if score is not None else None,
                vector=vector, source=self.name,
                severity=str(adv.get("severity", "") or ""),
            ))
        if cvss_v4.get("vector_string"):
            rec.cvss_scores.append(cvss_engine.build_score(
                version="4.0",
                base_score=(float(cvss_v4["score"]) if cvss_v4.get("score") is not None else None),
                vector=cvss_v4.get("vector_string", ""), source=self.name,
                severity=str(adv.get("severity", "") or ""),
            ))

        # CWEs
        for cwe in adv.get("cwes", []) or []:
            w = make_weakness(cwe.get("cwe_id"), name=cwe.get("name", ""), source=self.name)
            if w:
                rec.weaknesses.append(w)

        # affected products from vulnerabilities[]
        for vuln in adv.get("vulnerabilities", []) or []:
            pkg = vuln.get("package", {}) or {}
            ap = AffectedProduct(
                vendor=str(pkg.get("ecosystem", "") or ""),
                product=str(pkg.get("name", "") or ""),
                source=self.name, default_status="affected",
            )
            rng = vuln.get("vulnerable_version_range", "") or ""
            ap.version_end_excluding, ap.version_start_including = _parse_range(rng)
            first_patched = (vuln.get("first_patched_version") or {})
            if isinstance(first_patched, dict) and first_patched.get("identifier"):
                ap.versions_fixed = [str(first_patched["identifier"])]
            if ap.vendor or ap.product:
                rec.products.append(ap)

        # references
        refs = adv.get("references", []) or []
        # GitHub references can be bare url strings.
        rec.references = classify_references(
            [{"url": r} if isinstance(r, str) else r for r in refs], source=self.name)
        html_url = adv.get("html_url") or (f"https://github.com/advisories/{ghsa}" if ghsa else "")
        rec.sources = [SourceRecord(
            source=self.name, source_kind=self.kind, source_id=ghsa or (cve_id or ""),
            source_url=html_url, fetched_at=now_epoch(), raw=adv,
        )]
        return rec


def _parse_range(rng: str):
    """Extract (<upper_excl>, >=lower) bounds from a GHSA version range string
    like '>= 1.0.0, < 2.0.0'. Best-effort; unknown pieces return ''."""
    upper_excl = ""
    lower_incl = ""
    for part in (rng or "").split(","):
        part = part.strip()
        if part.startswith("<") and not part.startswith("<="):
            upper_excl = part.lstrip("< ").strip()
        elif part.startswith(">="):
            lower_incl = part.lstrip(">= ").strip()
    return upper_excl, lower_incl
