"""
threat_actor_intelligence.ingestion.otx_ingestor — AlienVault OTX pulses (public).

Parses the public OTX pulse JSON (``{"results":[{pulse}...]}``). Each pulse is a
community intelligence report: it becomes a ``Report`` plus a ``Campaign`` (a
pulse is a named, bounded activity set), and yields the pulse's indicators as
IOCs, its ``adversary`` as an actor-name candidate, ``malware_families`` as
malware-name candidates, ``attack_ids`` as ATT&CK techniques, and
``targeted_countries`` as victimology.

An ``OTX_API_KEY`` is required for live fetch (public read scope only); the
parser needs no key and is tested on fixtures.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from ..models.campaign import Campaign
from ..models.report import Report, content_fingerprint
from ..models.ioc import IOC, IOCType, canonicalize, CanonicalizeError
from ..models.evidence import SourceClass, EvidenceRef
from ..models.victimology import VictimObservation, TargetingConfidence
from ..models.threat_actor import slugify
from ..models.relation import Relationship
from .base import BaseIngestor, IngestResult

OTX_PULSES = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# OTX indicator type -> our IOCType
_OTX_TYPE = {
    "domain": IOCType.DOMAIN, "hostname": IOCType.DOMAIN, "URL": IOCType.URL,
    "URI": IOCType.URL, "IPv4": IOCType.IP, "IPv6": IOCType.IP,
    "email": IOCType.EMAIL, "FileHash-MD5": IOCType.MD5,
    "FileHash-SHA1": IOCType.SHA1, "FileHash-SHA256": IOCType.SHA256,
    "CIDR": IOCType.CIDR, "ASN": IOCType.ASN,
}


def _otx_ts(value: str) -> float:
    if not value:
        return 0.0
    v = value.split(".")[0].replace("Z", "")
    try:
        return float(time.mktime(time.strptime(v, "%Y-%m-%dT%H:%M:%S")))
    except Exception:
        return 0.0


class OTXIngestor(BaseIngestor):
    name = "otx"
    source_class = "community"

    def parse(self, raw: Any, **kw) -> IngestResult:
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", "replace")
        data = json.loads(raw) if isinstance(raw, str) else raw
        pulses = data.get("results", data) if isinstance(data, dict) else data
        result = IngestResult(provider=self.name)
        for pulse in (pulses or []):
            self._parse_pulse(pulse, result)
        return result

    def _parse_pulse(self, pulse: Dict[str, Any], result: IngestResult) -> None:
        name = pulse.get("name", "").strip()
        pid = pulse.get("id", "")
        created = _otx_ts(pulse.get("created", ""))
        modified = _otx_ts(pulse.get("modified", "")) or created
        url = f"https://otx.alienvault.com/pulse/{pid}" if pid else ""
        desc = pulse.get("description", "")

        report = Report(
            title=name or pid, url=url, vendor=pulse.get("author_name", "OTX"),
            source=self.name, source_class=SourceClass.COMMUNITY,
            published_at=created or time.time(), summary=desc[:2000],
            tags=list(pulse.get("tags", []) or []),
            content_hash=content_fingerprint(pid, name, desc))
        ev = report.as_evidence()

        camp = Campaign(campaign_name=name or f"OTX Pulse {pid}",
                        summary=desc[:2000], first_observed=created or time.time(),
                        last_observed=modified or time.time())
        camp.evidence.add(ev)

        adversary = (pulse.get("adversary") or "").strip()
        if adversary:
            result.actor_names.append(adversary)
            report.actor_names.append(adversary)
            actor_id = slugify(adversary)
            camp.link("actors", actor_id)
            result.relationships.append(Relationship(
                src_type="campaign", src_id=camp.campaign_id,
                rel_type="attributed_to", dst_type="actor", dst_id=actor_id,
                signal=f"OTX pulse attributes campaign to {adversary}",
                evidence=[ev]))

        for fam in pulse.get("malware_families", []) or []:
            fname = fam.get("display_name") if isinstance(fam, dict) else str(fam)
            if fname:
                result.malware_names.append(fname)
                report.malware_names.append(fname)
                fam_id = "mal-" + slugify(fname)
                camp.link("malware_families", fam_id)
                result.relationships.append(Relationship(
                    src_type="campaign", src_id=camp.campaign_id, rel_type="uses",
                    dst_type="malware", dst_id=fam_id,
                    signal=f"OTX pulse lists {fname} in campaign", evidence=[ev]))

        for att in pulse.get("attack_ids", []) or []:
            tid = att.get("id") if isinstance(att, dict) else str(att)
            if tid:
                result.technique_ids.append(tid.upper())
                camp.link("techniques", tid.upper())
                report.technique_ids.append(tid.upper())

        for country in pulse.get("targeted_countries", []) or []:
            camp.victimology.add(VictimObservation(
                country=country[:2] if len(country) <= 3 else "",
                as_reported=country, targeting=TargetingConfidence.REPORTED,
                observed_from=created, observed_to=modified, evidence=ev))

        for ind in pulse.get("indicators", []) or []:
            itype = _OTX_TYPE.get(ind.get("type", ""))
            if not itype:
                continue
            try:
                val = canonicalize(itype, ind.get("indicator", ""))
            except CanonicalizeError:
                continue
            ioc = IOC(ioc_type=itype, value=val, campaign=name,
                      actor=adversary, first_seen=created or time.time(),
                      last_seen=modified or time.time())
            ioc.evidence.add(ev)
            result.iocs.append(ioc)
            camp.link("iocs", ioc.id)

        camp.recompute_confidence()
        result.campaigns.append(camp)
        result.reports.append(report)

    def run(self, *, url: str = OTX_PULSES, store=None) -> IngestResult:  # pragma: no cover
        result = IngestResult(provider=self.name)
        if not self.api_key:
            result.errors.append("OTX_API_KEY not configured")
            return result
        resp, _ = self.conditional_get(url, store=store,
                                       headers={"X-OTX-API-KEY": self.api_key})
        if resp.not_modified:
            result.not_modified = True
            return result
        if resp.status != 200:
            result.errors.append(f"{url}: HTTP {resp.status}")
            return result
        result.extend(self.parse(resp.body))
        return result


__all__ = ["OTXIngestor", "OTX_PULSES"]
