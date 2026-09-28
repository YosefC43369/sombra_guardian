"""
web_footprint.collectors.repos — public repository discovery via the GitHub API.

Public source-code hosts frequently reveal an organization's domains, service
names, deployment references and developer footprint (spec §23, §27). This
collector performs *discovery only*: it queries GitHub's public search API for
repositories referencing the target domain / organization and returns the public
repository references it finds. It reads only public metadata — it does not clone
private repositories, authenticate as a user, or access anything gated.

The GitHub search API works unauthenticated at a low rate limit; when a token is
present in the environment (``GITHUB_TOKEN`` / ``GH_TOKEN``) it is used purely to
raise that rate limit, never to reach private data. Without one the collector
still runs, degrading to ``AUTH_REQUIRED`` only if GitHub refuses the
unauthenticated request.

Deeper *code intelligence* (extracting endpoints, package names, deployment
config and redacting secret-like strings from repository text — spec §24) is
performed offline by :mod:`web_footprint.analysis.extract` on any repository text
supplied to it; this collector's job is to find the repositories.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from .base import Collector, CollectorResult, CollectorStatus
from .. import normalize

SEARCH_URL = "https://api.github.com/search/repositories"


class RepositoryCollector(Collector):
    name = "github_repos"
    requires_key = False   # optional; only raises the rate limit
    stage = "repositories"

    def __init__(self, token: Optional[str] = None) -> None:
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    def _headers(self) -> Dict[str, str]:
        h = {"Accept": "application/vnd.github+json",
             "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    async def fetch(self, client, target: str, limits: Any = None) -> CollectorResult:
        domain = normalize.normalize_domain(target)
        if domain is None:
            return self._invalid(target, "not a valid domain")
        base = normalize.registrable_domain(domain) or domain
        org = base.split(".", 1)[0]
        cap = 50
        if limits is not None:
            cap = max(5, min(cap, int(getattr(limits, "max_repositories", cap))))
        # Query the registrable domain and the leading label as an org guess.
        params = {"q": f"{base} OR {org} in:name,description,readme",
                  "per_page": str(min(cap, 100))}
        result = await client.get_json(SEARCH_URL, params=params, headers=self._headers())
        if not result.ok:
            if result.status in (401, 403):
                return CollectorResult(self.name, domain, CollectorStatus.AUTH_REQUIRED,
                                       reason=result.reason or "github rate limit / auth",
                                       requests_made=1)
            res = self._error(domain, result.reason or "request failed")
            res.requests_made = 1
            return res
        try:
            payload = result.json()
        except Exception as exc:
            return self._error(domain, f"invalid JSON: {exc}")
        records = self.parse(payload, base, org)
        res = self._ok(domain, records[:cap],
                       total=int(payload.get("total_count", 0)) if isinstance(payload, dict) else 0)
        res.requests_made = 1
        return res

    @staticmethod
    def parse(payload: Dict[str, Any], base_domain: str, org: str) -> List[Dict[str, Any]]:
        if not isinstance(payload, dict):
            return []
        out: List[Dict[str, Any]] = []
        base = (base_domain or "").lower()
        org = (org or "").lower()
        for item in payload.get("items", []) or []:
            if not isinstance(item, dict):
                continue
            full = str(item.get("full_name", "")).strip()
            if not full:
                continue
            text = " ".join(str(item.get(k, "")) for k in
                            ("full_name", "description", "homepage")).lower()
            # Keep only repositories that actually mention the base domain or the
            # org label — the search is broad, so filter for relevance.
            relevant = base in text or (org and (f"/{org}" in "/" + full.lower()
                                                 or full.lower().startswith(org + "/")))
            out.append({
                "type": "repository", "value": full, "source": "github",
                "url": str(item.get("html_url", "")),
                "description": str(item.get("description") or "")[:300],
                "homepage": str(item.get("homepage") or ""),
                "stars": int(item.get("stargazers_count", 0) or 0),
                "language": str(item.get("language") or ""),
                "relevant": bool(relevant),
                "updated_at": str(item.get("updated_at") or ""),
            })
        # Relevant repositories first.
        out.sort(key=lambda r: (not r.get("relevant"), -int(r.get("stars", 0))))
        return out
