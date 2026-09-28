"""
web_footprint.collectors.certs — Certificate Transparency intelligence via crt.sh.

Certificate Transparency is a public, append-only log of every TLS certificate a
CA issues (RFC 6962). Querying crt.sh for a domain is a standard, entirely
passive way to discover an organization's subdomains and the certificate
relationships between its names — no authentication, no key, and no contact with
the target's own infrastructure (spec §5, §14).

This collector yields two record kinds:
  * ``subdomain`` — each in-scope hostname seen in a certificate,
  * ``certificate`` — one row per issued certificate with issuer, validity, and
    the Subject Alternative Name set, so the graph layer can build
    domain → certificate → SAN → related-domain edges (spec §14, §40).

The pure ``parse`` staticmethod does all record shaping and is unit-tested with
canned crt.sh JSON; ``fetch`` only performs the HTTP GET.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .base import Collector, CollectorResult, CollectorStatus
from .. import normalize

CRTSH_URL = "https://crt.sh/"


class CertificateCollector(Collector):
    name = "crtsh"
    requires_key = False
    stage = "certificates"

    async def fetch(self, client, target: str, limits: Any = None) -> CollectorResult:
        domain = normalize.normalize_domain(target)
        if domain is None:
            return self._invalid(target, "not a valid domain")
        params = {"q": f"%.{domain}", "output": "json"}
        result = await client.get_json(CRTSH_URL, params=params)
        if not result.ok:
            if result.status == 429:
                return CollectorResult(self.name, domain, CollectorStatus.RATE_LIMITED,
                                       reason=result.reason, requests_made=1)
            return CollectorResult(self.name, domain, CollectorStatus.ERROR,
                                   reason=result.reason or "request failed",
                                   requests_made=1)
        try:
            rows = result.json()
        except Exception as exc:
            return self._error(domain, f"invalid JSON: {exc}")
        if not isinstance(rows, list):
            return self._error(domain, "unexpected response shape")

        records = self.parse(rows, domain)
        res = self._ok(domain, records, certificates_seen=len(rows))
        res.requests_made = 1
        return res

    @staticmethod
    def parse(rows: List[dict], base_domain: str) -> List[Dict[str, Any]]:
        """Flatten crt.sh rows into subdomain + certificate records, keeping only
        names within ``base_domain`` (crt.sh returns SANs for unrelated names on
        shared certificates)."""
        base = normalize.normalize_domain(base_domain) or (base_domain or "").lower()
        suffix = "." + base
        subdomains = set()
        cert_records: List[Dict[str, Any]] = []

        def _names(raw: str) -> List[str]:
            out = []
            for piece in str(raw).replace(",", "\n").splitlines():
                cand = piece.strip().lower().lstrip("*.").rstrip(".")
                norm = normalize.normalize_domain(cand)
                if norm:
                    out.append(norm)
            return out

        for row in rows:
            if not isinstance(row, dict):
                continue
            san = _names(row.get("name_value", ""))
            cn = normalize.normalize_domain(str(row.get("common_name", "")).lstrip("*."))
            in_scope_names = [n for n in set(san + ([cn] if cn else []))
                              if n == base or n.endswith(suffix)]
            for n in in_scope_names:
                subdomains.add(n)
            if in_scope_names:
                cert_records.append({
                    "type": "certificate",
                    "value": str(row.get("serial_number")
                                 or row.get("id") or ",".join(sorted(in_scope_names)[:2])),
                    "issuer": str(row.get("issuer_name", "")).strip(),
                    "common_name": cn or "",
                    "not_before": str(row.get("not_before", "")),
                    "not_after": str(row.get("not_after", "")),
                    "sans": sorted(set(in_scope_names)),
                    "source": "crtsh",
                })

        records: List[Dict[str, Any]] = [
            {"type": "subdomain", "value": name, "source": "crtsh",
             "signal_state": "historical"}
            for name in sorted(subdomains)
        ]
        records.extend(cert_records)
        return records
