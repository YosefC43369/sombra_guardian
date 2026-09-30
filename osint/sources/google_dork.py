"""
osint.sources.google_dork — advanced-operator (Google dork) query builder, with
optional execution via the Google Programmable Search (CSE) JSON API.

WHAT / WHY. "Google dorking" is just composing normal search-engine queries with
advanced operators (site:, filetype:, intitle:, inurl:) to surface documents an
organization has published to the open web but that a plain search buries —
exposed PDFs/spreadsheets, index-of listings, login portals, config files. It is
passive: it queries a search engine, never the target. This module's core value
is the *query planner* — it always returns a curated set of dorks for the target
so an operator can run them by hand. If ``GOOGLE_CSE_KEY`` and ``GOOGLE_CSE_CX``
are configured it will also execute them through the official CSE JSON API (a
supported, ToS-compliant path) and return the hits; without those it reports the
planned dorks and marks itself AUTH_REQUIRED for the execution step.

We deliberately use the official CSE API, not HTML scraping of google.com, which
Google's terms forbid and which would get the framework blocked.
"""

import os
import logging
from typing import Any, Dict, List

from .base import Source, SourceResult, SourceStatus
from ..utils import validators

logger = logging.getLogger("modbot.osint.google_dork")

CSE_ENDPOINT = "https://www.googleapis.com/customsearch/v1"

# ชุดเทมเพลต dork มาตรฐานสำหรับประเมิน exposure ขององค์กร/โดเมน
_DORK_TEMPLATES = [
    'site:{d}',
    'site:{d} filetype:pdf',
    'site:{d} (filetype:xls OR filetype:xlsx OR filetype:csv)',
    'site:{d} (filetype:doc OR filetype:docx)',
    'site:{d} (filetype:env OR filetype:cfg OR filetype:conf OR filetype:ini)',
    'site:{d} intitle:"index of"',
    'site:{d} (inurl:login OR inurl:admin OR inurl:signin)',
    'site:{d} (inurl:wp-admin OR inurl:administrator)',
    'site:{d} ("api_key" OR "apikey" OR "secret" OR "password")',
    'site:{d} intext:"internal use only"',
    'site:pastebin.com "{d}"',
    'site:github.com "{d}"',
]


def _cse_config():
    key = (os.getenv("GOOGLE_CSE_KEY") or "").strip()
    cx = (os.getenv("GOOGLE_CSE_CX") or "").strip()
    return (key, cx) if key and cx else (None, None)


def plan_dorks(domain: str) -> List[str]:
    """คืนรายการ dork query สำหรับโดเมน — ใช้ได้แม้ไม่มีคีย์ CSE (ให้ operator ยิงเอง)"""
    return [t.format(d=domain) for t in _DORK_TEMPLATES]


class GoogleDorkSource(Source):
    name = "google_dork"
    kind = "domain"
    requires_key = False        # planning is keyless; execution needs CSE keys

    # จำกัดจำนวน dork ที่ยิงจริงต่อครั้ง (CSE มีโควตา 100 คิวรี/วันในชั้นฟรี)
    MAX_EXECUTED = int(os.getenv("GOOGLE_DORK_MAX_EXEC", "6") or "6")

    async def fetch(self, client, target: str) -> SourceResult:
        domain = validators.normalize_domain(target)
        if domain is None:
            return self._invalid(target, "not a valid domain")

        dorks = plan_dorks(domain)
        records: List[Dict[str, Any]] = [
            {"type": "dork_query", "value": q, "source": self.name}
            for q in dorks
        ]

        key, cx = _cse_config()
        if not key:
            # ไม่มีคีย์ CSE — คืนแผน dork ไว้ให้ยิงเอง แต่บอกชัดว่า "ยังไม่ได้ execute"
            return SourceResult(
                self.name, domain, SourceStatus.AUTH_REQUIRED, records=records,
                reason="GOOGLE_CSE_KEY/GOOGLE_CSE_CX not set — planned dorks only",
                meta={"planned": len(dorks), "executed": 0})

        executed = 0
        hits = 0
        for q in dorks[:self.MAX_EXECUTED]:
            params = {"key": key, "cx": cx, "q": q, "num": 10}
            result = await client.get_json(CSE_ENDPOINT, params=params)
            executed += 1
            if not result.ok:
                if result.status == 429:
                    return SourceResult(self.name, domain,
                                        SourceStatus.RATE_LIMITED,
                                        records=records, reason="CSE quota exhausted",
                                        meta={"planned": len(dorks),
                                              "executed": executed})
                continue
            try:
                data = result.json()
            except Exception:
                continue
            for item in data.get("items", []) or []:
                link = str(item.get("link", "")).strip()
                if not link:
                    continue
                hits += 1
                records.append({
                    "type": "dork_hit", "value": link, "source": self.name,
                    "dork": q, "title": str(item.get("title", ""))[:200],
                    "snippet": str(item.get("snippet", ""))[:300],
                })

        status = SourceStatus.OK if hits else SourceStatus.EMPTY
        return SourceResult(
            self.name, domain, status, records=records,
            reason="" if hits else "dorks executed, no results",
            meta={"planned": len(dorks), "executed": executed, "hits": hits})
