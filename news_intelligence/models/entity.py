"""
news_intelligence.models.entity — the extracted-entity vocabulary.

Every extractor in ``news_intelligence.extraction`` emits ``EntityMention``
objects: a typed, normalized reference to something named in an article (a threat
actor, malware family, CVE, organization, country, domain, IP, ATT&CK technique,
product, …) together with the span of source text that supports it. Mentions are
the atoms the correlation, clustering and graph layers work on.

Design rules:
  * ``value`` is the *normalized* form (deduplicates ``APT 29`` == ``APT29``);
    ``surface`` preserves exactly how the source wrote it (provenance).
  * A mention never asserts identity — an ``APT29`` mention and a ``Cozy Bear``
    mention are two mentions until an evidence-backed alias link says otherwise.
  * ``entity_key`` is stable per (type, value) so the same entity across articles
    collapses to one node in the graph.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class EntityType(str, Enum):
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"
    MALWARE_FAMILY = "malware_family"
    ORGANIZATION = "organization"
    COMPANY = "company"
    GOVERNMENT_AGENCY = "government_agency"
    COUNTRY = "country"
    CITY = "city"
    DOMAIN = "domain"
    IP = "ip"
    ASN = "asn"
    URL = "url"
    EMAIL = "email"
    REPOSITORY = "repository"
    CVE = "cve"
    CWE = "cwe"
    CAPEC = "capec"
    ATTACK_TECHNIQUE = "attack_technique"
    SOFTWARE = "software"
    CLOUD_PROVIDER = "cloud_provider"
    PRODUCT = "product"
    HASH = "hash"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, raw: Any) -> "EntityType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN


# Entity types that are indicator-like (feed IOC enrichment downstream).
IOC_ENTITY_TYPES = {EntityType.DOMAIN, EntityType.IP, EntityType.URL,
                    EntityType.EMAIL, EntityType.HASH, EntityType.ASN}


def normalize_value(entity_type: EntityType, surface: str) -> str:
    """Normalize a surface form to a canonical value for its type."""
    s = (surface or "").strip()
    if not s:
        return ""
    if entity_type in (EntityType.CVE, EntityType.CWE, EntityType.CAPEC,
                       EntityType.ATTACK_TECHNIQUE, EntityType.ASN):
        return s.upper().replace(" ", "")
    if entity_type in (EntityType.DOMAIN, EntityType.EMAIL, EntityType.URL):
        return s.lower().replace("[.]", ".").replace("(.)", ".")
    if entity_type == EntityType.HASH:
        return s.lower()
    if entity_type == EntityType.THREAT_ACTOR:
        # collapse "APT 29" -> "APT29"; keep codename casing otherwise
        if re.match(r"(?i)^(apt|unc|ta|fin|temp|dev|g)\s*\d", s):
            return re.sub(r"\s+", "", s).upper()
        return re.sub(r"\s+", " ", s).title()
    if entity_type == EntityType.COUNTRY:
        return re.sub(r"\s+", " ", s).title()
    return re.sub(r"\s+", " ", s).strip()


@dataclass
class EntityMention:
    entity_type: EntityType
    value: str = ""                 # normalized
    surface: str = ""               # exactly as written in the source
    start: int = -1                 # char offset in source text (-1 unknown)
    end: int = -1
    extractor: str = ""             # which extractor produced it
    weight: float = 1.0             # extractor confidence (0..1)
    context: str = ""               # short surrounding span
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.entity_type = EntityType.coerce(self.entity_type)
        if not self.surface:
            self.surface = self.value
        if not self.value:
            self.value = normalize_value(self.entity_type, self.surface)

    @property
    def entity_key(self) -> str:
        """Stable id per (type, value) — the graph node identity."""
        return (self.entity_type.value + ":" +
                hashlib.sha256(self.value.lower().encode("utf-8")).hexdigest()[:16])

    @property
    def is_ioc(self) -> bool:
        return self.entity_type in IOC_ENTITY_TYPES

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["entity_type"] = self.entity_type.value
        d["entity_key"] = self.entity_key
        d["is_ioc"] = self.is_ioc
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EntityMention":
        return cls(
            entity_type=EntityType.coerce(d.get("entity_type")),
            value=str(d.get("value", "")),
            surface=str(d.get("surface", "")),
            start=int(d.get("start", -1)),
            end=int(d.get("end", -1)),
            extractor=str(d.get("extractor", "")),
            weight=float(d.get("weight", 1.0) or 1.0),
            context=str(d.get("context", "")),
            detail=dict(d.get("detail", {}) or {}),
        )


def dedupe_mentions(mentions: List[EntityMention]) -> List[EntityMention]:
    """Collapse mentions with the same entity_key, keeping the highest weight and
    the first surface/span seen; sum a ``count`` into detail."""
    by_key: Dict[str, EntityMention] = {}
    for m in mentions:
        if not m.value:
            continue
        k = m.entity_key
        if k in by_key:
            cur = by_key[k]
            cur.detail["count"] = int(cur.detail.get("count", 1)) + 1
            if m.weight > cur.weight:
                cur.weight = m.weight
        else:
            m.detail.setdefault("count", 1)
            by_key[k] = m
    return list(by_key.values())


__all__ = ["EntityType", "EntityMention", "IOC_ENTITY_TYPES", "normalize_value",
           "dedupe_mentions"]
