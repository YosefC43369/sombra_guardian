"""
threat_actor_intelligence.ingestion.nvd_ingestor — NIST NVD CVE feed.

Parses the NVD 2.0 CVE JSON API response (``{"vulnerabilities":[{"cve":{...}}]}``)
into ``Report`` objects (one per CVE, advisory-class) carrying the CVSS severity,
CWE weaknesses and reference URLs. CVE ⇄ malware/campaign links are made later by
the pipeline when other sources tie a CVE to a family/campaign; this ingestor's
job is the authoritative vulnerability record and its references.

An ``NVD_API_KEY`` (from the environment) raises the polite rate limit but is not
required — the public endpoint works without one.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from ..models.report import Report, content_fingerprint
from ..models.evidence import SourceClass
from .base import BaseIngestor, IngestResult

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _nvd_ts(value: str) -> float:
    if not value:
        return 0.0
    v = value.split(".")[0].replace("Z", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            return float(time.mktime(time.strptime(v, fmt)))
        except Exception:
            continue
    return 0.0


def _english(descriptions: List[Dict[str, Any]]) -> str:
    for d in descriptions or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _severity(metrics: Dict[str, Any]) -> str:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            data = arr[0].get("cvssData", {})
            sev = arr[0].get("baseSeverity") or data.get("baseSeverity", "")
            score = data.get("baseScore", "")
            return f"{sev} ({score})".strip()
    return ""


class NVDIngestor(BaseIngestor):
    name = "nvd"
    source_class = "government"

    def parse(self, raw: Any, **kw) -> IngestResult:
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", "replace")
        data = json.loads(raw) if isinstance(raw, str) else raw
        result = IngestResult(provider=self.name)
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        for wrap in vulns:
            cve = wrap.get("cve", {})
            cid = (cve.get("id") or "").upper()
            if not cid:
                continue
            desc = _english(cve.get("descriptions", []))
            published = _nvd_ts(cve.get("published", ""))
            severity = _severity(cve.get("metrics", {}))
            cwes: List[str] = []
            for weak in cve.get("weaknesses", []) or []:
                for d in weak.get("description", []) or []:
                    if d.get("value", "").upper().startswith("CWE-"):
                        cwes.append(d["value"].upper())
            refs = [r.get("url", "") for r in cve.get("references", []) or []
                    if r.get("url")]
            tags = ["cve"] + sorted(set(cwes))
            if severity:
                tags.append(f"severity:{severity.split(' ')[0].lower()}")
            report = Report(
                title=f"{cid}: {severity}".strip(),
                url=f"https://nvd.nist.gov/vuln/detail/{cid}",
                vendor="NIST NVD", source=self.name,
                source_class=SourceClass.GOVERNMENT,
                published_at=published or time.time(),
                summary=desc[:2000], cve_ids=[cid], references=refs, tags=tags,
                content_hash=content_fingerprint(cid, desc, severity))
            result.reports.append(report)
            result.cve_ids.append(cid)
        return result

    def run(self, *, params: str = "", store=None) -> IngestResult:  # pragma: no cover
        result = IngestResult(provider=self.name)
        url = NVD_API + (("?" + params) if params else "")
        headers = {"apiKey": self.api_key} if self.api_key else None
        resp, _ = self.conditional_get(url, store=store, headers=headers)
        if resp.not_modified:
            result.not_modified = True
            return result
        if resp.status != 200:
            result.errors.append(f"{url}: HTTP {resp.status}")
            return result
        result.extend(self.parse(resp.body))
        return result


__all__ = ["NVDIngestor", "NVD_API"]
