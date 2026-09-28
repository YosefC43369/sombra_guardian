"""
news_intelligence.ingestion.cisa_ingestor — CISA advisories + Known Exploited Vulns.

Two modes:
  * feed mode — parses CISA's advisory/news RSS as government-advisory articles
    (highest evidence weight);
  * KEV mode — parses the CISA Known Exploited Vulnerabilities catalog JSON into one
    article per newly-added CVE, tagged as publicly-confirmed exploited (the only
    exploitation signal the engine treats as authoritative, and still cited to CISA).

Pure parse for both; KEV JSON is a public catalog, no key required.
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

from ..models.article import Article, content_hash
from ..models.source import NewsSource, SourceCategory, ReliabilityClass
from ..models.evidence import SourceClass
from ..parsing.publication_parser import parse_date
from .base import BaseIngestor, IngestResult
from .rss_ingestor import RSSIngestor

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAIngestor(RSSIngestor):
    name = "cisa"
    default_source_class = "government"

    def parse(self, raw: Any, *, source: Optional[NewsSource] = None,
              feed_url: str = "") -> IngestResult:
        if source is None:
            source = NewsSource(name="CISA",
                                category=SourceCategory.GOVERNMENT_ADVISORY,
                                reliability_class=ReliabilityClass.OFFICIAL_GOVERNMENT,
                                country="US", rss_url=feed_url)
        result = super().parse(raw, source=source, feed_url=feed_url)
        result.provider = self.name
        return result


class CISAKEVIngestor(BaseIngestor):
    name = "cisa_kev"
    default_source_class = "government"

    def parse(self, raw: Any, *, since: float = 0.0) -> IngestResult:
        text = (raw.decode("utf-8", "replace")
                if isinstance(raw, (bytes, bytearray)) else str(raw))
        result = IngestResult(provider=self.name)
        try:
            data = json.loads(text)
        except Exception as exc:
            result.errors.append(f"kev json: {exc}")
            return result
        source = NewsSource(name="CISA KEV Catalog",
                            category=SourceCategory.GOVERNMENT_ADVISORY,
                            reliability_class=ReliabilityClass.OFFICIAL_GOVERNMENT,
                            country="US",
                            website="https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
        for v in data.get("vulnerabilities", []) or []:
            cve = (v.get("cveID") or "").upper()
            if not cve:
                continue
            added = parse_date(v.get("dateAdded", "")) or time.time()
            if since and added < since:
                result.skipped += 1
                continue
            vendor = v.get("vendorProject", "")
            product = v.get("product", "")
            name = v.get("vulnerabilityName", cve)
            summary = (f"CISA added {cve} ({vendor} {product}) to the Known "
                       f"Exploited Vulnerabilities catalog: {name}. "
                       f"{v.get('shortDescription', '')}").strip()
            url = ("https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                   f"#{cve.lower()}")
            art = Article(
                title=f"CISA KEV: {cve} — {name}", url=url, canonical_url=url,
                summary=summary[: self.max_summary], source_name=source.name,
                source_id=source.source_id, source_domain=source.domain,
                source_class=SourceClass.GOVERNMENT, language="en",
                publication_date=added,
                tags=["kev", "known-exploited", vendor.lower()] if vendor else ["kev"],
                content_hash=content_hash(cve, "kev", str(added)),
                detail={"kev": True, "cve": cve, "vendor": vendor,
                        "product": product,
                        "required_action": v.get("requiredAction", ""),
                        "due_date": v.get("dueDate", "")})
            art.evidence = [art.as_evidence(
                excerpt=f"{cve} listed in CISA KEV on {v.get('dateAdded','')}"
            ).to_dict()]
            result.articles.append(art)
            result.fetched += 1
        return result

    def run(self, *, store=None) -> IngestResult:  # pragma: no cover
        result = IngestResult(provider=self.name)
        resp, _ = self.conditional_get(KEV_URL, store=store)
        if resp.not_modified:
            result.not_modified = True
            return result
        if resp.status != 200:
            result.errors.append(f"{KEV_URL}: HTTP {resp.status}")
            return result
        since = 0.0
        if store is not None:
            st = store.get_provider_state(self.name, KEV_URL)
            since = float(st.get("last_run", 0.0) or 0.0)
        return self.parse(resp.body, since=since)


__all__ = ["CISAIngestor", "CISAKEVIngestor", "KEV_URL"]
