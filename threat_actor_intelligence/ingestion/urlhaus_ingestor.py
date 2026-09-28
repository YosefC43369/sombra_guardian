"""
threat_actor_intelligence.ingestion.urlhaus_ingestor — abuse.ch URLhaus (public).

Parses URLhaus public JSON (recent URLs / a query response) into IOCs and a
lightweight ``Report`` per batch. Each malicious URL becomes a URL IOC (and its
host a domain IOC) tagged with the reported threat/tags and the associated
malware ``signature`` when present. Metadata only — no payloads are fetched or
stored.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from ..models.ioc import IOC, IOCType, canonicalize, CanonicalizeError
from ..models.report import Report, content_fingerprint
from ..models.evidence import SourceClass
from .base import BaseIngestor, IngestResult

URLHAUS_RECENT = "https://urlhaus.abuse.ch/downloads/json_recent/"


def _uh_ts(value: str) -> float:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return float(time.mktime(time.strptime((value or "").split("UTC")[0].strip(),
                                                   fmt)))
        except Exception:
            continue
    return 0.0


class URLhausIngestor(BaseIngestor):
    name = "urlhaus"
    source_class = "community"

    def parse(self, raw: Any, **kw) -> IngestResult:
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", "replace")
        data = json.loads(raw) if isinstance(raw, str) else raw
        result = IngestResult(provider=self.name)

        entries: List[Dict[str, Any]] = []
        if isinstance(data, dict):
            if "urls" in data:
                entries = data["urls"]
            else:
                # json_recent maps id -> [entry, ...]
                for v in data.values():
                    if isinstance(v, list):
                        entries.extend(v)
                    elif isinstance(v, dict):
                        entries.append(v)
        elif isinstance(data, list):
            entries = data

        report = Report(title=f"URLhaus batch ({len(entries)} URLs)",
                        url="https://urlhaus.abuse.ch/", vendor="abuse.ch",
                        source=self.name, source_class=SourceClass.COMMUNITY,
                        published_at=time.time(),
                        content_hash=content_fingerprint(
                            "urlhaus", str(len(entries)), str(int(time.time() // 3600))))
        ev = report.as_evidence()

        for e in entries:
            url = e.get("url", "")
            if not url:
                continue
            added = _uh_ts(e.get("date_added", e.get("dateadded", "")))
            threat = e.get("threat", "")
            signature = e.get("signature") or e.get("malware", "") or ""
            tags = e.get("tags", []) or []
            try:
                uval = canonicalize(IOCType.URL, url)
            except CanonicalizeError:
                continue
            ioc = IOC(ioc_type=IOCType.URL, value=uval, role="payload_delivery",
                      malware=signature, tags=([threat] if threat else []) + list(tags),
                      first_seen=added or time.time(), last_seen=added or time.time())
            ioc.evidence.add(ev)
            result.iocs.append(ioc)
            if signature:
                result.malware_names.append(signature)
            host = e.get("host") or e.get("domain") or ""
            if host:
                try:
                    dval = canonicalize(IOCType.DOMAIN, host)
                    dioc = IOC(ioc_type=IOCType.DOMAIN, value=dval, malware=signature,
                               first_seen=added or time.time(),
                               last_seen=added or time.time())
                    dioc.evidence.add(ev)
                    result.iocs.append(dioc)
                except CanonicalizeError:
                    pass
        result.reports.append(report)
        return result

    def run(self, *, url: str = URLHAUS_RECENT, store=None) -> IngestResult:  # pragma: no cover
        result = IngestResult(provider=self.name)
        resp, _ = self.conditional_get(url, store=store)
        if resp.not_modified:
            result.not_modified = True
            return result
        if resp.status != 200:
            result.errors.append(f"{url}: HTTP {resp.status}")
            return result
        result.extend(self.parse(resp.body))
        return result


__all__ = ["URLhausIngestor", "URLHAUS_RECENT"]
