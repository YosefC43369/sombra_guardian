"""
osint.sources.subfinder — subfinder-style passive subdomain aggregation.

WHAT / WHY. Like the subfinder/amass workflow, this fans out to several FREE,
keyless passive-DNS/inventory endpoints and unions their answers into one
de-duplicated subdomain set for a domain. It complements crtsh.py (Certificate
Transparency) with sources that see names CT never issued a cert for: passive DNS
(AlienVault OTX), host inventory (HackerTarget), and an aggregator (jldc/anubis).
All are reads of already-public data, no key, no contact with the target's own
servers. Each provider is queried through the shared AsyncHTTPClient, so one slow
or rate-limited provider never sinks the batch.
"""

import json
import logging
from typing import Dict, List, Set

from .base import Source, SourceResult, SourceStatus
from ..utils import validators

logger = logging.getLogger("modbot.osint.subfinder")

OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/"
ANUBIS_URL = "https://jldc.me/anubis/subdomains/{d}"


class SubfinderSource(Source):
    name = "subfinder"
    kind = "domain"
    requires_key = False

    async def fetch(self, client, target: str) -> SourceResult:
        domain = validators.normalize_domain(target)
        if domain is None:
            return self._invalid(target, "not a valid domain")

        found: Set[str] = set()
        providers_ok = 0
        providers_tried = 0

        for coro in (self._otx, self._hackertarget, self._anubis):
            providers_tried += 1
            try:
                subs = await coro(client, domain)
            except Exception as exc:
                logger.info("subfinder provider %s failed: %s", coro.__name__, exc)
                continue
            if subs is not None:
                providers_ok += 1
                found.update(subs)

        # เก็บเฉพาะที่อยู่ในโดเมนเป้าหมายจริง
        suffix = "." + domain
        clean = sorted(s for s in found
                       if s == domain or s.endswith(suffix))
        if not clean:
            if providers_ok == 0:
                return self._error(domain, "all passive-DNS providers failed")
            return self._empty(domain, "no subdomains from passive sources")

        records: List[Dict[str, str]] = [
            {"type": "subdomain", "value": s, "source": self.name} for s in clean
        ]
        return SourceResult(self.name, domain, SourceStatus.OK, records=records,
                            meta={"unique_subdomains": len(clean),
                                  "providers_ok": providers_ok,
                                  "providers_tried": providers_tried})

    async def _otx(self, client, domain: str):
        r = await client.get(OTX_URL.format(d=domain))
        if not r.ok:
            return None
        try:
            data = r.json()
        except Exception:
            return None
        out = set()
        for rec in (data.get("passive_dns") or []):
            host = str(rec.get("hostname", "")).strip().lower().rstrip(".")
            norm = validators.normalize_domain(host)
            if norm:
                out.add(norm)
        return out

    async def _hackertarget(self, client, domain: str):
        r = await client.get(HACKERTARGET_URL, params={"q": domain})
        if not r.ok:
            return None
        text = r.text or ""
        # ข้อความแจ้ง error/quota ของ hackertarget ไม่ใช่รายการโฮสต์
        if "error" in text.lower() or "API count exceeded" in text:
            return None
        out = set()
        for line in text.splitlines():
            host = line.split(",", 1)[0].strip().lower().rstrip(".")
            norm = validators.normalize_domain(host)
            if norm:
                out.add(norm)
        return out

    async def _anubis(self, client, domain: str):
        r = await client.get(ANUBIS_URL.format(d=domain))
        if not r.ok:
            return None
        try:
            data = r.json()
        except Exception:
            return None
        if not isinstance(data, list):
            return None
        out = set()
        for host in data:
            norm = validators.normalize_domain(str(host).strip().lower().rstrip("."))
            if norm:
                out.add(norm)
        return out
