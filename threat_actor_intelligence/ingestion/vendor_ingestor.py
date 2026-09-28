"""
threat_actor_intelligence.ingestion.vendor_ingestor — generic vendor reports.

A catch-all for security-vendor research: a blog HTML page, a plain-text report,
or a structured report dict. It strips markup, mines the body for IOCs/CVEs/
techniques/name candidates and emits a vendor-class ``Report``. Vendor blogs are
the richest narrative source for actor/campaign attribution, so this ingestor is
where most free-text extraction happens; the extracted names are resolved to
actors/campaigns/malware by the pipeline (never merged blindly).

Feed it HTML (``parse(html, url=..., vendor=...)``) or a structured dict
(``parse({"title":..,"body":..,"url":..})``). Both paths are pure and offline.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

from ..models.report import Report, content_fingerprint
from ..models.evidence import SourceClass
from .base import BaseIngestor, IngestResult
from .extract import extract

try:
    from bs4 import BeautifulSoup
    HAVE_BS4 = True
except Exception:  # pragma: no cover
    BeautifulSoup = None
    HAVE_BS4 = False

_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def html_to_text(html: str) -> str:
    if HAVE_BS4:  # pragma: no cover
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "nav", "footer"]):
            tag.decompose()
        return re.sub(r"\s+", " ", soup.get_text(" ")).strip()
    text = _SCRIPT_RE.sub(" ", html or "")
    text = _TAG_RE.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()


def html_title(html: str) -> str:
    m = _TITLE_RE.search(html or "")
    if HAVE_BS4:  # pragma: no cover
        soup = BeautifulSoup(html, "html.parser")
        if soup.title and soup.title.string:
            return soup.title.string.strip()
        h1 = soup.find("h1")
        if h1:
            return h1.get_text(" ").strip()
    return (_TAG_RE.sub("", m.group(1)).strip() if m else "")


class VendorIngestor(BaseIngestor):
    name = "vendor"
    source_class = "vendor"

    def __init__(self, *, vendor: str = "", source_class: str = "vendor",
                 max_summary: int = 2000, **kw):
        super().__init__(**kw)
        self.vendor = vendor
        self._source_class = source_class
        self.max_summary = max_summary

    def parse(self, raw: Any, *, url: str = "", vendor: str = "",
              title: str = "", is_html: bool = True) -> IngestResult:
        vendor = vendor or self.vendor
        result = IngestResult(provider=self.name)

        if isinstance(raw, dict):
            title = raw.get("title", title)
            body = raw.get("body", raw.get("content", ""))
            url = raw.get("url", url)
            vendor = raw.get("vendor", vendor)
            published = float(raw.get("published_at", 0) or 0)
        else:
            text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) \
                else str(raw)
            if is_html:
                title = title or html_title(text)
                body = html_to_text(text)
            else:
                body = text
            published = 0.0

        report = Report(
            title=title or url or "Vendor report", url=url, vendor=vendor,
            source=self.name, source_class=SourceClass.coerce(self._source_class),
            published_at=published or time.time(),
            summary=body[:self.max_summary],
            content_hash=content_fingerprint(title, url, body[:512]))
        ex = extract(body)
        ev = report.as_evidence()
        for ioc in ex.iocs:
            ioc.first_seen = ioc.last_seen = report.published_at
            ioc.evidence.add(ev)
        report.actor_names = ex.actor_names
        report.malware_names = ex.malware_names
        report.cve_ids = ex.cve_ids
        report.technique_ids = ex.technique_ids
        report.ioc_ids = [i.id for i in ex.iocs]

        result.reports.append(report)
        result.iocs.extend(ex.iocs)
        result.actor_names.extend(ex.actor_names)
        result.malware_names.extend(ex.malware_names)
        result.cve_ids.extend(ex.cve_ids)
        result.technique_ids.extend(ex.technique_ids)
        return result

    def run(self, *, urls: Optional[List[str]] = None, vendor: str = "",
            store=None) -> IngestResult:  # pragma: no cover
        result = IngestResult(provider=self.name)
        for url in (urls or []):
            resp, _ = self.conditional_get(url, store=store)
            if resp.not_modified:
                result.not_modified = True
                continue
            if resp.status != 200:
                result.errors.append(f"{url}: HTTP {resp.status}")
                continue
            result.extend(self.parse(resp.body, url=url, vendor=vendor))
        return result


__all__ = ["VendorIngestor", "html_to_text", "html_title", "HAVE_BS4"]
