"""
threat_actor_intelligence.ingestion.cisa_ingestor — CISA KEV + advisories.

Two public CISA sources:
  * the Known Exploited Vulnerabilities (KEV) catalog JSON — each entry becomes a
    ``Report`` (an advisory-class evidence record) tagged with its CVE, product
    and whether it is tied to ransomware campaign use;
  * CISA advisory items (the advisories RSS/Atom feed is handled by the RSS
    ingestor; this parser also accepts the JSON advisory index form).

All CISA content is government-class evidence (high trust weight). Nothing here
fetches anything but the public catalogs.
"""

from __future__ import annotations

import json
import time
from typing import Any, List

from ..models.report import Report, content_fingerprint
from ..models.evidence import SourceClass, TLP
from .base import BaseIngestor, IngestResult

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _kev_date(value: str) -> float:
    for fmt in ("%Y-%m-%d", "%Y/%m/%d"):
        try:
            return float(time.mktime(time.strptime(value, fmt)))
        except Exception:
            continue
    return 0.0


class CISAIngestor(BaseIngestor):
    name = "cisa"
    source_class = "government"

    def parse(self, raw: Any, **kw) -> IngestResult:
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", "replace")
        data = json.loads(raw) if isinstance(raw, str) else raw
        result = IngestResult(provider=self.name)
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        catalog_version = data.get("catalogVersion", "") if isinstance(data, dict) else ""
        for v in vulns:
            cve = (v.get("cveID") or "").upper()
            name = v.get("vulnerabilityName") or cve
            vendor = v.get("vendorProject", "")
            product = v.get("product", "")
            desc = v.get("shortDescription", "")
            added = _kev_date(v.get("dateAdded", ""))
            ransomware = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
            title = f"CISA KEV: {cve} — {vendor} {product}".strip()
            url = (f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "")
            report = Report(
                title=title, url=url, vendor="CISA", source=self.name,
                source_class=SourceClass.GOVERNMENT,
                published_at=added or time.time(),
                summary=f"{name}. {desc}"[:2000], tlp=TLP.CLEAR,
                cve_ids=[cve] if cve else [],
                tags=(["kev"] + (["ransomware"] if ransomware else [])),
                provider_version=catalog_version,
                content_hash=content_fingerprint(cve, name, desc))
            if ransomware:
                report.tags.append("known-ransomware-campaign-use")
            result.reports.append(report)
            if cve:
                result.cve_ids.append(cve)
        return result

    def run(self, *, kev_url: str = KEV_URL, store=None) -> IngestResult:  # pragma: no cover
        result = IngestResult(provider=self.name)
        resp, _ = self.conditional_get(kev_url, store=store)
        if resp.not_modified:
            result.not_modified = True
            return result
        if resp.status != 200:
            result.errors.append(f"{kev_url}: HTTP {resp.status}")
            return result
        result.extend(self.parse(resp.body))
        return result


__all__ = ["CISAIngestor", "KEV_URL"]
