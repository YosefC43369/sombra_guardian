"""
osint.sources.crtsh — passive subdomain enumeration via crt.sh (Certificate
Transparency logs).

WHAT / WHY. Certificate Transparency is a public, append-only log of every TLS
certificate a CA issues (RFC 6962 — the same mechanism the integrity_ledger
module implements internally). Querying crt.sh for a domain returns the names
that have appeared in certificates for it, which is a standard, entirely passive
way to discover an organization's subdomains during an authorized assessment. No
authentication, no key, no contact with the target's own infrastructure.

crt.sh's JSON is quirky: it returns one row per (certificate, identity) and the
``name_value`` field can hold several newline-separated names, often including a
wildcard (``*.example.com``). This module flattens, de-wildcards, validates and
de-duplicates those into a clean subdomain set.
"""

import logging
from typing import Dict, List

from .base import Source, SourceResult, SourceStatus
from ..utils import validators

logger = logging.getLogger("modbot.osint.crtsh")

CRTSH_URL = "https://crt.sh/"


class CrtShSource(Source):
    name = "crtsh"
    kind = "domain"
    requires_key = False

    async def fetch(self, client, target: str) -> SourceResult:
        domain = validators.normalize_domain(target)
        if domain is None:
            return self._invalid(target, "not a valid domain")

        # '%25.<domain>' is URL-encoded '%.<domain>' — crt.sh's SQL-LIKE wildcard.
        params = {"q": f"%.{domain}", "output": "json"}
        result = await client.get_json(CRTSH_URL, params=params)
        if not result.ok:
            if result.status == 429:
                return SourceResult(self.name, domain, SourceStatus.RATE_LIMITED,
                                    reason=result.reason)
            return self._error(domain, result.reason or "request failed")

        try:
            rows = result.json()
        except Exception as exc:
            return self._error(domain, f"invalid JSON: {exc}")
        if not isinstance(rows, list):
            return self._error(domain, "unexpected response shape")

        subdomains = self._extract_subdomains(rows, domain)
        if not subdomains:
            return self._empty(domain, "no certificates found")

        records: List[Dict[str, str]] = [
            {"type": "subdomain", "value": name, "source": self.name}
            for name in subdomains
        ]
        return SourceResult(
            self.name, domain, SourceStatus.OK, records=records,
            meta={"unique_subdomains": len(subdomains),
                  "certificates_seen": len(rows)},
        )

    @staticmethod
    def _extract_subdomains(rows: List[dict], base_domain: str) -> List[str]:
        """Flatten crt.sh rows into a sorted, de-duplicated, validated set of
        hostnames that are actually within ``base_domain``."""
        found = set()
        suffix = "." + base_domain
        for row in rows:
            if not isinstance(row, dict):
                continue
            raw_names = str(row.get("name_value", ""))
            for piece in raw_names.replace(",", "\n").splitlines():
                candidate = piece.strip().lower().lstrip("*.").rstrip(".")
                if not candidate:
                    continue
                norm = validators.normalize_domain(candidate)
                if norm is None:
                    continue
                # Keep only names inside the queried domain (crt.sh can return
                # SAN entries for unrelated names on a shared certificate).
                if norm == base_domain or norm.endswith(suffix):
                    found.add(norm)
        return sorted(found)


async def fetch_subdomains(client, domain: str) -> SourceResult:
    """Convenience wrapper for callers that just want the crt.sh result."""
    return await CrtShSource().run(client, domain)
