"""
threat_actor_intelligence.ingestion.github_ingestor — public GitHub CTI content.

Two public GitHub surfaces:
  * repository text files (threat-report markdown, IOC lists, YARA/Sigma rule
    *references*) — parsed as free text via the shared extractor, producing IOCs,
    CVEs, techniques and name candidates plus a ``Report`` citing the file;
  * GitHub Security Advisories (GHSA) JSON — parsed into advisory-class reports
    with their CVE, severity and references.

A ``GITHUB_TOKEN`` (from the environment) raises the rate limit for live fetch
but is not required for the pure parsers. YARA/Sigma content is treated as
detection metadata references, never distributed rule bodies with weaponizable
payloads.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List

from ..models.report import Report, content_fingerprint
from ..models.ioc import IOC, IOCType, canonicalize, CanonicalizeError
from ..models.evidence import SourceClass
from .base import BaseIngestor, IngestResult
from .extract import extract

_YARA_RULE_RE = re.compile(r"\brule\s+([A-Za-z0-9_]+)", re.IGNORECASE)
_SIGMA_TITLE_RE = re.compile(r"^title:\s*(.+)$", re.MULTILINE)


def _gh_ts(value: str) -> float:
    if not value:
        return 0.0
    v = value.split(".")[0].replace("Z", "")
    try:
        return float(time.mktime(time.strptime(v, "%Y-%m-%dT%H:%M:%S")))
    except Exception:
        return 0.0


class GitHubIngestor(BaseIngestor):
    name = "github"
    source_class = "research"

    def parse(self, raw: Any, *, kind: str = "markdown", repo: str = "",
              path: str = "", url: str = "") -> IngestResult:
        if kind == "advisories":
            return self._parse_advisories(raw)
        return self._parse_text(raw, repo=repo, path=path, url=url)

    def _parse_text(self, raw: Any, *, repo: str, path: str, url: str
                    ) -> IngestResult:
        text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) \
            else str(raw)
        result = IngestResult(provider=self.name)
        title = f"{repo}/{path}".strip("/") or (url or "GitHub content")
        report = Report(
            title=title, url=url or f"https://github.com/{repo}/blob/HEAD/{path}",
            vendor=repo.split("/")[0] if "/" in repo else "github",
            source=self.name, source_class=SourceClass.RESEARCH,
            published_at=time.time(),
            content_hash=content_fingerprint(repo, path, text[:512]))
        ex = extract(text)
        ev = report.as_evidence()

        # YARA/Sigma rule *references* (names only)
        yara_names = _YARA_RULE_RE.findall(text)
        sigma_titles = _SIGMA_TITLE_RE.findall(text)
        for yn in yara_names[:50]:
            ex.iocs.append(IOC(ioc_type=IOCType.YARA_REF, value=yn))
        for st in sigma_titles[:50]:
            ex.iocs.append(IOC(ioc_type=IOCType.SIGMA_REF, value=st.strip()))

        for ioc in ex.iocs:
            ioc.first_seen = ioc.last_seen = time.time()
            ioc.evidence.add(ev)
        report.actor_names = ex.actor_names
        report.malware_names = ex.malware_names
        report.cve_ids = ex.cve_ids
        report.technique_ids = ex.technique_ids
        report.ioc_ids = [i.id for i in ex.iocs]
        if yara_names:
            report.tags.append("yara")
        if sigma_titles:
            report.tags.append("sigma")

        result.reports.append(report)
        result.iocs.extend(ex.iocs)
        result.actor_names.extend(ex.actor_names)
        result.malware_names.extend(ex.malware_names)
        result.cve_ids.extend(ex.cve_ids)
        result.technique_ids.extend(ex.technique_ids)
        return result

    def _parse_advisories(self, raw: Any) -> IngestResult:
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", "replace")
        data = json.loads(raw) if isinstance(raw, str) else raw
        advisories = data if isinstance(data, list) else data.get("advisories", [])
        result = IngestResult(provider=self.name)
        for adv in advisories or []:
            ghsa = adv.get("ghsa_id", "")
            cves = [i.get("value", "").upper() for i in adv.get("identifiers", [])
                    if i.get("type") == "CVE"]
            if adv.get("cve_id"):
                cves.append(adv["cve_id"].upper())
            summary = adv.get("summary", "")
            report = Report(
                title=f"{ghsa}: {summary}".strip(": "),
                url=adv.get("html_url", adv.get("url", "")),
                vendor="GitHub Security", source=self.name,
                source_class=SourceClass.VENDOR,
                published_at=_gh_ts(adv.get("published_at", "")) or time.time(),
                summary=(adv.get("description", "") or summary)[:2000],
                cve_ids=sorted(set(cves)),
                tags=["ghsa", adv.get("severity", "")],
                references=[r.get("url", "") for r in adv.get("references", [])
                            if r.get("url")],
                content_hash=content_fingerprint(ghsa, summary))
            result.reports.append(report)
            result.cve_ids.extend(cves)
        return result

    def run(self, *, raw_urls: List[str] = None, store=None
            ) -> IngestResult:  # pragma: no cover
        result = IngestResult(provider=self.name)
        headers = {"Authorization": f"token {self.api_key}"} if self.api_key else None
        for url in (raw_urls or []):
            resp, _ = self.conditional_get(url, store=store, headers=headers)
            if resp.not_modified:
                result.not_modified = True
                continue
            if resp.status != 200:
                result.errors.append(f"{url}: HTTP {resp.status}")
                continue
            result.extend(self.parse(resp.body, url=url))
        return result


__all__ = ["GitHubIngestor"]
