"""
web_footprint.collectors.wellknown — the target's own published public files.

Some of the most useful passive signals are files an organization publishes for
the whole world to read: ``robots.txt`` (which often names sitemaps and path
prefixes), ``sitemap.xml`` (a self-declared URL inventory), and
``/.well-known/security.txt`` (the declared security-reporting process — spec
§31, §32). Retrieving these is ordinary public-page retrieval of documents the
target intends to be public; the spec explicitly permits reading them and draws
the line only at active testing, which this does not do.

This collector also fetches the site root once so downstream *offline* analyzers
(technology fingerprinting, reference extraction, security-header analysis) have
the response headers and HTML to work from. It emits:
  * ``page`` records — {url, status, headers, body, title} for analyzers,
  * ``wellknown_file`` records — raw text of security.txt for the security
    analyzer,
  * ``url`` records — URLs declared in sitemap.xml / robots.txt,
  * ``sitemap_ref`` / ``robots`` records — the declarations themselves.

Only a small, fixed set of the target's own paths is fetched; nothing is brute
-forced or enumerated.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .base import Collector, CollectorResult
from .. import normalize

# The fixed, well-known public paths this collector reads on the target itself.
WELLKNOWN_PATHS = (
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)
_MAX_BODY = 300_000   # cap stored body so a huge page cannot bloat the result


class WellKnownCollector(Collector):
    name = "wellknown"
    requires_key = False
    stage = "wellknown"

    async def fetch(self, client, target: str, limits: Any = None) -> CollectorResult:
        host = normalize.normalize_domain(target) or normalize.host_of_url(target)
        if host is None:
            return self._invalid(target, "not a valid domain/URL")
        records: List[Dict[str, Any]] = []
        requests = 0
        got_any = False
        for path in WELLKNOWN_PATHS:
            url = f"https://{host}{path}"
            result = await client.get(url)
            requests += 1
            if not result.ok:
                continue
            got_any = True
            records.extend(self.parse(path, url, result.status,
                                      dict(result.headers or {}), result.text or "",
                                      host))
        if not got_any:
            res = self._empty(host, "no well-known files reachable over https")
            res.requests_made = requests
            return res
        res = self._ok(host, records, paths_tried=len(WELLKNOWN_PATHS))
        res.requests_made = requests
        return res

    @staticmethod
    def parse(path: str, url: str, status: int, headers: Dict[str, str],
              body: str, host: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}
        body = body[:_MAX_BODY]

        if path == "/":
            title = ""
            m = _TITLE_RE.search(body)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
            out.append({
                "type": "page", "value": url, "source": "wellknown",
                "status": status, "headers": lower_headers, "body": body,
                "title": title, "host": host,
            })
        elif path.endswith("security.txt"):
            out.append({"type": "wellknown_file", "name": "security.txt",
                        "value": url, "source": "wellknown", "text": body})
        elif path.endswith("robots.txt"):
            sitemaps, disallows = WellKnownCollector._parse_robots(body)
            out.append({"type": "robots", "value": url, "source": "wellknown",
                        "sitemaps": sitemaps, "disallow": disallows[:200]})
            for sm in sitemaps:
                nu = normalize.normalize_url(sm)
                if nu:
                    out.append({"type": "sitemap_ref", "value": nu, "source": "wellknown"})
        elif path.endswith("sitemap.xml"):
            for loc in _LOC_RE.findall(body):
                nu = normalize.normalize_url(loc)
                if nu:
                    out.append({"type": "url", "value": nu, "source": "sitemap"})
        return out

    @staticmethod
    def _parse_robots(body: str) -> Tuple[List[str], List[str]]:
        sitemaps: List[str] = []
        disallows: List[str] = []
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key == "sitemap" and value:
                sitemaps.append(value)
            elif key == "disallow" and value:
                disallows.append(value)
        return sitemaps, disallows
