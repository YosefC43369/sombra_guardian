"""
threat_actor_intelligence.ingestion.stix_ingestor — STIX 2.0/2.1 bundle ingest.

Parses a STIX bundle (OpenCTI / MISP-STIX / OASIS TAXII payloads) into the
engine's structured objects:

    intrusion-set   -> ThreatActor
    threat-actor    -> ThreatActor
    malware / tool  -> MalwareFamily
    campaign        -> Campaign
    indicator       -> IOC (pattern parsed)
    infrastructure  -> Infrastructure
    relationship    -> Relationship (resolved between the above)

Each object becomes evidence-anchored to its STIX id + external references, and
the STIX ``created``/``modified`` timestamps drive first/last seen. Indicator
patterns are parsed for the common comparison forms
(``[domain-name:value = 'x']``, file hashes, ipv4, url, email).
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from ..models.threat_actor import ThreatActor, ActorType, Alias
from ..models.campaign import Campaign
from ..models.malware_family import MalwareFamily
from ..models.infrastructure import Infrastructure, InfraType
from ..models.ioc import IOC, IOCType, canonicalize, CanonicalizeError
from ..models.relation import Relationship, ObjectType, RelationType
from ..models.evidence import EvidenceRef, SourceClass
from .base import BaseIngestor, IngestResult

_STIX_TS_RE = "%Y-%m-%dT%H:%M:%S"


def _ts(value: str) -> float:
    if not value:
        return 0.0
    v = value.split(".")[0].replace("Z", "")
    try:
        return float(time.mktime(time.strptime(v, _STIX_TS_RE)))
    except Exception:
        return 0.0


# STIX pattern comparison → (IOCType, group)
_PATTERN_RES: List[Tuple[str, IOCType]] = [
    (r"domain-name:value\s*=\s*'([^']+)'", IOCType.DOMAIN),
    (r"url:value\s*=\s*'([^']+)'", IOCType.URL),
    (r"ipv4-addr:value\s*=\s*'([^']+)'", IOCType.IP),
    (r"ipv6-addr:value\s*=\s*'([^']+)'", IOCType.IP),
    (r"email-addr:value\s*=\s*'([^']+)'", IOCType.EMAIL),
    (r"file:hashes\.'?SHA-?256'?\s*=\s*'([^']+)'", IOCType.SHA256),
    (r"file:hashes\.'?SHA-?1'?\s*=\s*'([^']+)'", IOCType.SHA1),
    (r"file:hashes\.'?MD5'?\s*=\s*'([^']+)'", IOCType.MD5),
]
_COMPILED = [(re.compile(rx, re.IGNORECASE), t) for rx, t in _PATTERN_RES]


def parse_indicator_pattern(pattern: str) -> List[Tuple[IOCType, str]]:
    out: List[Tuple[IOCType, str]] = []
    for rx, itype in _COMPILED:
        for m in rx.finditer(pattern or ""):
            try:
                out.append((itype, canonicalize(itype, m.group(1))))
            except CanonicalizeError:
                continue
    return out


def _ext_refs(obj: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Return (best external id, [urls])."""
    ext_id, urls = "", []
    for ref in obj.get("external_references", []) or []:
        if ref.get("external_id") and not ext_id:
            ext_id = ref["external_id"]
        if ref.get("url"):
            urls.append(ref["url"])
    return ext_id, urls


class STIXIngestor(BaseIngestor):
    name = "stix"
    source_class = "community"

    def __init__(self, *, provider_name: str = "stix",
                 source_class: str = "community", **kw):
        super().__init__(**kw)
        self.provider_name = provider_name
        self._source_class = source_class

    def _evidence(self, obj: Dict[str, Any], observed_at: float) -> EvidenceRef:
        ext_id, urls = _ext_refs(obj)
        return EvidenceRef(
            provider=self.provider_name,
            source_class=SourceClass.coerce(self._source_class),
            title=obj.get("name", obj.get("type", "")),
            source_url=urls[0] if urls else "",
            external_id=ext_id or obj.get("id", ""),
            excerpt=(obj.get("description", "") or "")[:280],
            observed_at=observed_at or _ts(obj.get("created", "")))

    def parse(self, raw: Any, **kw) -> IngestResult:
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", "replace")
        bundle = json.loads(raw) if isinstance(raw, str) else raw
        objs = bundle.get("objects", []) if isinstance(bundle, dict) else \
            (bundle if isinstance(bundle, list) else [])
        result = IngestResult(provider=self.provider_name)

        stix_to_obj: Dict[str, Tuple[str, str]] = {}   # stix id -> (obj_type, id)

        for obj in objs:
            otype = obj.get("type")
            created = _ts(obj.get("created", ""))
            modified = _ts(obj.get("modified", "")) or created
            ev = self._evidence(obj, created)

            if otype in ("intrusion-set", "threat-actor"):
                actor = ThreatActor(
                    canonical_name=obj.get("name", "").strip() or obj.get("id", ""),
                    actor_type=self._actor_type(obj),
                    description=obj.get("description", ""),
                    first_seen=created, last_seen=modified)
                for al in obj.get("aliases", []) or []:
                    if al and al.lower() != actor.canonical_name.lower():
                        actor.add_alias(Alias(al, source=self.provider_name, kind="vendor"))
                ext_id, urls = _ext_refs(obj)
                actor.references = urls
                if ext_id.startswith("G"):
                    actor.attack_group_id = ext_id
                actor.evidence.add(ev)
                actor.recompute_confidence()
                result.actors.append(actor)
                stix_to_obj[obj["id"]] = ("actor", actor.actor_id)

            elif otype in ("malware", "tool"):
                fam = MalwareFamily(
                    family_name=obj.get("name", "").strip() or obj.get("id", ""),
                    description=obj.get("description", ""),
                    platforms=obj.get("x_mitre_platforms", []) or [],
                    is_family=bool(obj.get("is_family", True)),
                    first_seen=created, last_seen=modified)
                for al in obj.get("x_mitre_aliases", obj.get("aliases", [])) or []:
                    if al and al.lower() != fam.family_name.lower():
                        fam.add_alias(Alias(al, source=self.provider_name, kind="malware"))
                ext_id, urls = _ext_refs(obj)
                fam.references = urls
                if ext_id.startswith("S"):
                    fam.attack_software_id = ext_id
                for label in obj.get("labels", []) or []:
                    if not fam.category:
                        fam.category = label
                fam.evidence.add(ev)
                fam.recompute_confidence()
                result.families.append(fam)
                stix_to_obj[obj["id"]] = ("malware", fam.family_id)

            elif otype == "campaign":
                camp = Campaign(
                    campaign_name=obj.get("name", "").strip() or obj.get("id", ""),
                    summary=obj.get("description", ""),
                    first_observed=_ts(obj.get("first_seen", "")) or created,
                    last_observed=_ts(obj.get("last_seen", "")) or modified)
                for al in obj.get("aliases", []) or []:
                    camp.add_alias(Alias(al, source=self.provider_name, kind="campaign"))
                _, urls = _ext_refs(obj)
                camp.references = urls
                camp.evidence.add(ev)
                camp.recompute_confidence()
                result.campaigns.append(camp)
                stix_to_obj[obj["id"]] = ("campaign", camp.campaign_id)

            elif otype == "infrastructure":
                itype = self._infra_type(obj)
                node = Infrastructure(
                    infra_type=itype, value=obj.get("name", "").strip(),
                    role=",".join(obj.get("infrastructure_types", []) or []),
                    first_seen=created, last_seen=modified)
                node.evidence.add(ev)
                node.recompute_confidence()
                result.infrastructure.append(node)
                stix_to_obj[obj["id"]] = ("infrastructure", node.infra_id)

            elif otype == "indicator":
                for itype, val in parse_indicator_pattern(obj.get("pattern", "")):
                    ioc = IOC(ioc_type=itype, value=val,
                              first_seen=created or time.time(),
                              last_seen=modified or time.time())
                    for label in obj.get("labels", []) or []:
                        ioc.tags.append(label)
                    ioc.evidence.add(ev)
                    result.iocs.append(ioc)

            elif otype == "relationship":
                result.raw_objects.append(obj)   # resolve after all objs indexed

        # resolve relationships
        for obj in result.raw_objects:
            if obj.get("type") != "relationship":
                continue
            src = stix_to_obj.get(obj.get("source_ref", ""))
            dst = stix_to_obj.get(obj.get("target_ref", ""))
            if not src or not dst:
                continue
            rtype = self._rel_type(obj.get("relationship_type", ""))
            ev = self._evidence(obj, _ts(obj.get("created", "")))
            rel = Relationship(
                src_type=ObjectType.coerce(src[0]), src_id=src[1],
                rel_type=rtype, dst_type=ObjectType.coerce(dst[0]), dst_id=dst[1],
                signal=obj.get("relationship_type", "related"),
                evidence=[ev])
            result.relationships.append(rel)

        return result

    @staticmethod
    def _actor_type(obj: Dict[str, Any]) -> ActorType:
        labels = " ".join(obj.get("labels", []) or []).lower()
        text = (obj.get("description", "") + " " + labels).lower()
        if "nation" in text or "state-sponsored" in text or "state sponsored" in text:
            return ActorType.NATION_STATE
        if "ransomware" in text:
            return ActorType.RANSOMWARE
        if "hacktivist" in text or "activist" in text:
            return ActorType.HACKTIVIST
        if "crime" in text or "criminal" in text or "financial" in text:
            return ActorType.CYBERCRIME
        return ActorType.UNKNOWN

    @staticmethod
    def _infra_type(obj: Dict[str, Any]) -> InfraType:
        types = " ".join(obj.get("infrastructure_types", []) or []).lower()
        if "domain" in types:
            return InfraType.DOMAIN
        if "hosting" in types:
            return InfraType.HOSTING
        return InfraType.SERVER

    @staticmethod
    def _rel_type(stix_rel: str) -> RelationType:
        mapping = {
            "uses": RelationType.USES, "targets": RelationType.TARGETS,
            "attributed-to": RelationType.ATTRIBUTED_TO,
            "indicates": RelationType.INDICATES,
            "communicates-with": RelationType.COMMUNICATES_WITH,
            "hosts": RelationType.HOSTS, "variant-of": RelationType.VARIANT_OF,
            "mitigates": RelationType.MITIGATES,
        }
        return mapping.get((stix_rel or "").lower(), RelationType.ASSOCIATED_WITH)

    def run(self, *, urls: Optional[List[str]] = None, store=None
            ) -> IngestResult:  # pragma: no cover
        result = IngestResult(provider=self.provider_name)
        for url in (urls or []):
            resp, _ = self.conditional_get(url, store=store)
            if resp.not_modified:
                result.not_modified = True
                continue
            if resp.status != 200:
                result.errors.append(f"{url}: HTTP {resp.status}")
                continue
            result.extend(self.parse(resp.body))
        return result


__all__ = ["STIXIngestor", "parse_indicator_pattern"]
