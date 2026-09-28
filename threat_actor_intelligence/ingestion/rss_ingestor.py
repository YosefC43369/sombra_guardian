"""
threat_actor_intelligence.ingestion.rss_ingestor — public RSS/Atom security feeds.

Parses RSS 2.0 and Atom feeds into ``Report`` objects and mines each item's
title+summary for IOCs, CVEs, techniques and actor/malware name candidates.
Uses ``feedparser`` (project dependency) when available; falls back to a
stdlib ``xml.etree`` parser so the module works and its tests run without it.

Only publicly-published feeds are read; the item link is preserved as the
report's primary-source URL. Per-item content hashing lets the pipeline skip
items already stored (incremental ingestion).
"""

from __future__ import annotations

import re
import time
from calendar import timegm
from email.utils import parsedate_tz, mktime_tz
from typing import Any, List, Optional
from xml.etree import ElementTree as ET

from ..models.report import Report, content_fingerprint
from ..models.evidence import SourceClass
from .base import BaseIngestor, IngestResult
from .extract import extract

try:
    import feedparser
    HAVE_FEEDPARSER = True
except Exception:  # pragma: no cover
    feedparser = None
    HAVE_FEEDPARSER = False

_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    return re.sub(r"\s+", " ", _TAG_RE.sub(" ", text or "")).strip()


def _parse_date(value: str) -> float:
    if not value:
        return 0.0
    # RFC822 (RSS)
    try:
        dt = parsedate_tz(value)
        if dt:
            return float(mktime_tz(dt))
    except Exception:
        pass
    # ISO 8601 (Atom)
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d"):
        try:
            return float(timegm(time.strptime(value.replace("Z", "+0000")
                                              if fmt.endswith("%z") else value, fmt)))
        except Exception:
            continue
    return 0.0


class RSSIngestor(BaseIngestor):
    name = "rss"
    source_class = "feed"

    def __init__(self, *, vendor: str = "", source_class: str = "feed",
                 max_summary: int = 2000, **kw):
        super().__init__(**kw)
        self.vendor = vendor
        self._source_class = source_class
        self.max_summary = max_summary

    def parse(self, raw: Any, *, feed_url: str = "", vendor: str = "") -> IngestResult:
        text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) \
            else str(raw)
        vendor = vendor or self.vendor
        result = IngestResult(provider=self.name)
        items = (self._parse_feedparser(text) if HAVE_FEEDPARSER
                 else self._parse_etree(text))
        for it in items:
            title = _strip_html(it.get("title", ""))
            link = it.get("link", "")
            summary = _strip_html(it.get("summary", ""))[:self.max_summary]
            published = _parse_date(it.get("published", ""))
            if not title and not link:
                continue
            report = Report(
                title=title or link, url=link,
                vendor=vendor or it.get("author", ""), source=self.name,
                source_class=SourceClass.coerce(self._source_class),
                published_at=published or time.time(), summary=summary,
                authors=[it["author"]] if it.get("author") else [],
                content_hash=content_fingerprint(title, link, summary))
            blob = f"{title}\n{summary}"
            ex = extract(blob)
            report.actor_names = ex.actor_names
            report.malware_names = ex.malware_names
            report.cve_ids = ex.cve_ids
            report.technique_ids = ex.technique_ids
            report.ioc_ids = [i.id for i in ex.iocs]
            ev = report.as_evidence()
            for ioc in ex.iocs:
                ioc.first_seen = ioc.last_seen = published or time.time()
                ioc.evidence.add(ev)
            result.reports.append(report)
            result.iocs.extend(ex.iocs)
            result.actor_names.extend(ex.actor_names)
            result.malware_names.extend(ex.malware_names)
            result.cve_ids.extend(ex.cve_ids)
            result.technique_ids.extend(ex.technique_ids)
        return result

    def _parse_feedparser(self, text: str) -> List[dict]:  # pragma: no cover
        d = feedparser.parse(text)
        out = []
        for e in d.entries:
            out.append({
                "title": getattr(e, "title", ""),
                "link": getattr(e, "link", ""),
                "summary": getattr(e, "summary", getattr(e, "description", "")),
                "published": getattr(e, "published", getattr(e, "updated", "")),
                "author": getattr(e, "author", ""),
            })
        return out

    def _parse_etree(self, text: str) -> List[dict]:
        out: List[dict] = []
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return out
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        # RSS 2.0
        for item in root.iter("item"):
            out.append({
                "title": (item.findtext("title") or ""),
                "link": (item.findtext("link") or ""),
                "summary": (item.findtext("description") or ""),
                "published": (item.findtext("pubDate") or ""),
                "author": (item.findtext("author")
                           or item.findtext("{http://purl.org/dc/elements/1.1/}creator")
                           or ""),
            })
        # Atom
        for entry in root.findall(".//atom:entry", ns):
            link_el = entry.find("atom:link", ns)
            link = link_el.get("href") if link_el is not None else ""
            out.append({
                "title": (entry.findtext("atom:title", default="", namespaces=ns)),
                "link": link,
                "summary": (entry.findtext("atom:summary", default="", namespaces=ns)
                            or entry.findtext("atom:content", default="", namespaces=ns)),
                "published": (entry.findtext("atom:published", default="", namespaces=ns)
                              or entry.findtext("atom:updated", default="", namespaces=ns)),
                "author": (entry.findtext("atom:author/atom:name", default="",
                                          namespaces=ns)),
            })
        return out

    def run(self, *, feed_urls: Optional[List[str]] = None, store=None
            ) -> IngestResult:  # pragma: no cover
        result = IngestResult(provider=self.name)
        for url in (feed_urls or []):
            resp, _ = self.conditional_get(url, store=store)
            if resp.not_modified:
                result.not_modified = True
                continue
            if resp.status != 200:
                result.errors.append(f"{url}: HTTP {resp.status}")
                continue
            result.extend(self.parse(resp.body, feed_url=url))
        return result


__all__ = ["RSSIngestor", "HAVE_FEEDPARSER"]
