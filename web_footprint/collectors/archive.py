"""
web_footprint.collectors.archive — historical footprint via the Wayback Machine.

The Internet Archive's Wayback CDX API is a lawful public archive of snapshots
of the open web. Querying it for a domain yields the URLs that were publicly
reachable in the past — old subdomains, old documents, old contact pages, old
technologies — which is a major, entirely passive red-team capability for
understanding how an organization's surface evolved (spec §5, §28, §29).

Everything here is read from the archive, never from the target: no live request
to the organization's own infrastructure is made. Records are tagged with the
snapshot timestamp so the history layer can build CURRENT-vs-HISTORICAL diffs
and technology timelines.

The pure ``parse`` staticmethod turns the CDX rows into records and is
unit-tested with canned CDX output.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .base import Collector, CollectorResult
from .. import normalize

CDX_URL = "https://web.archive.org/cdx/search/cdx"

# File extensions that make an archived URL a "public document" of interest
# (spec §19). Kept in one place so the analyzer and this collector agree.
DOCUMENT_EXTS = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "txt",
    "xml", "json", "rtf", "odt", "ods", "odp",
})


class ArchiveCollector(Collector):
    name = "wayback"
    requires_key = False
    stage = "archive"

    async def fetch(self, client, target: str, limits: Any = None) -> CollectorResult:
        domain = normalize.normalize_domain(target)
        if domain is None:
            return self._invalid(target, "not a valid domain")
        limit = 5000
        if limits is not None:
            limit = max(100, min(limit, int(getattr(limits, "max_urls", limit)) * 5))
        params = {
            "url": f"{domain}/*",
            "output": "json",
            "fl": "timestamp,original,mimetype,statuscode",
            "collapse": "urlkey",
            "limit": str(limit),
        }
        result = await client.get_json(CDX_URL, params=params)
        if not result.ok:
            res = self._error(domain, result.reason or "request failed")
            res.requests_made = 1
            return res
        try:
            rows = result.json()
        except Exception as exc:
            return self._error(domain, f"invalid JSON: {exc}")
        records = self.parse(rows, domain)
        res = self._ok(domain, records, snapshots=max(0, len(rows) - 1))
        res.requests_made = 1
        return res

    @staticmethod
    def _ext(url: str) -> str:
        path = url.split("?", 1)[0].split("#", 1)[0]
        last = path.rsplit("/", 1)[-1]
        return last.rsplit(".", 1)[-1].lower() if "." in last else ""

    @staticmethod
    def parse(rows: List[list], base_domain: str) -> List[Dict[str, Any]]:
        """CDX returns a header row then ``[timestamp, original, mimetype,
        statuscode]`` rows. Emit historical URL/subdomain/document records."""
        base = normalize.normalize_domain(base_domain) or (base_domain or "").lower()
        if not isinstance(rows, list) or len(rows) < 2:
            return []
        out: List[Dict[str, Any]] = []
        seen_hosts = set()
        seen_urls = set()
        for row in rows[1:]:
            if not isinstance(row, (list, tuple)) or len(row) < 2:
                continue
            timestamp = str(row[0])
            original = str(row[1])
            mimetype = str(row[2]) if len(row) > 2 else ""
            url = normalize.normalize_url(original)
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            host = normalize.host_of_url(url)
            if host and normalize.is_subdomain_of(host, base) and host not in seen_hosts:
                seen_hosts.add(host)
                out.append({"type": "subdomain", "value": host, "source": "wayback",
                            "signal_state": "archived", "first_timestamp": timestamp})
            ext = ArchiveCollector._ext(url)
            rec: Dict[str, Any] = {
                "type": "historical_url", "value": url, "source": "wayback",
                "timestamp": timestamp, "mimetype": mimetype,
            }
            out.append(rec)
            if ext in DOCUMENT_EXTS:
                out.append({"type": "document", "value": url, "source": "wayback",
                            "ext": ext, "timestamp": timestamp, "signal_state": "archived"})
        return out
