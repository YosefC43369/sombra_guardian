"""
news_intelligence.ingestion.nvd_ingestor — NVD CVE feed ingestion.

Parses the NVD CVE 2.0 API JSON into one ``Article`` per CVE, carrying the CVE id,
CVSS severity wording (quoted verbatim — never re-scored by the engine), affected
vendor/product references and the published/modified dates. Classified as
standards/government evidence. ``NVD_API_KEY`` raises the rate limit but is not
required. Pure parse; the API JSON is fetched by ``run``.
"""

from __future__ import annotations

import json
import time
from typing import Any, List, Optional

from ..models.article import Article, content_hash
from ..models.source import NewsSource, SourceCategory, ReliabilityClass
from ..models.evidence import SourceClass
from ..parsing.publication_parser import parse_date
from .base import BaseIngestor, IngestResult

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDIngestor(BaseIngestor):
    name = "nvd"
    default_source_class = "standards"

    def parse(self, raw: Any, *, since: float = 0.0) -> IngestResult:
        text = (raw.decode("utf-8", "replace")
                if isinstance(raw, (bytes, bytearray)) else str(raw))
        result = IngestResult(provider=self.name)
        try:
            data = json.loads(text)
        except Exception as exc:
            result.errors.append(f"nvd json: {exc}")
            return result
        source = NewsSource(name="NVD", category=SourceCategory.GOVERNMENT_ADVISORY,
                            reliability_class=ReliabilityClass.OFFICIAL_GOVERNMENT,
                            country="US", website="https://nvd.nist.gov")
        for vuln in data.get("vulnerabilities", []) or []:
            cve = vuln.get("cve", {})
            cve_id = (cve.get("id") or "").upper()
            if not cve_id:
                continue
            published = parse_date(cve.get("published", "")) or time.time()
            if since and published < since:
                result.skipped += 1
                continue
            descs = cve.get("descriptions", []) or []
            desc = next((d.get("value", "") for d in descs
                         if d.get("lang") == "en"), "")
            severity, score = self._severity(cve.get("metrics", {}))
            vendors = self._vendors(cve.get("configurations", []))
            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            sev_quote = (f"{severity} (CVSS {score})" if severity else "")
            art = Article(
                title=f"{cve_id}: {desc[:120]}", url=url, canonical_url=url,
                summary=desc[: self.max_summary], source_name=source.name,
                source_id=source.source_id, source_domain=source.domain,
                source_class=SourceClass.STANDARDS, language="en",
                publication_date=published, tags=["nvd", "cve"],
                content_hash=content_hash(cve_id, "nvd", str(published)),
                detail={"cve": cve_id, "severity": severity, "cvss": score,
                        "severity_quote": sev_quote, "vendors": vendors})
            art.cve_mentions = [cve_id]
            art.evidence = [art.as_evidence().to_dict()]
            result.articles.append(art)
            result.fetched += 1
        return result

    @staticmethod
    def _severity(metrics: dict):
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key) or []
            if arr:
                data = arr[0].get("cvssData", {})
                return (data.get("baseSeverity", "")
                        or arr[0].get("baseSeverity", ""),
                        data.get("baseScore", ""))
        return "", ""

    @staticmethod
    def _vendors(configs: list) -> List[str]:
        out: List[str] = []
        for cfg in configs or []:
            for node in cfg.get("nodes", []) or []:
                for m in node.get("cpeMatch", []) or []:
                    cpe = m.get("criteria", "")
                    parts = cpe.split(":")
                    if len(parts) > 4 and parts[3] not in out:
                        out.append(parts[3])
        return out[:20]

    def run(self, *, store=None, results_per_page: int = 200) -> IngestResult:  # pragma: no cover
        result = IngestResult(provider=self.name)
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        url = f"{NVD_API}?resultsPerPage={results_per_page}"
        resp = self.http.get(url, headers=headers)
        if resp.status != 200:
            result.errors.append(f"{url}: HTTP {resp.status}")
            return result
        since = 0.0
        if store is not None:
            st = store.get_provider_state(self.name, NVD_API)
            since = float(st.get("last_run", 0.0) or 0.0)
            store.set_provider_state(self.name, NVD_API)
        return self.parse(resp.body, since=since)


__all__ = ["NVDIngestor", "NVD_API"]
