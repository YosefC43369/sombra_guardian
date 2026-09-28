"""
web_footprint.assets — the attack-surface inventory data model.

Everything the engine discovers becomes an :class:`Asset` in an
:class:`AttackSurfaceInventory`. An asset is a single publicly-observable thing
(a website, an API doc, a certificate, a public file, a repository) with:

  * a stable identity (``asset_id``) and a canonical ``key`` for de-duplication,
  * typed classification (:class:`AssetType`, and for domains/subdomains a
    :class:`DomainClass` / :class:`SubdomainRole`),
  * append-only :class:`Evidence` — every observation carries the source that
    reported it and when, so the inventory separates *observed fact* from
    *inference* exactly as the rest of this repo does,
  * ``first_seen`` / ``last_seen`` timestamps,
  * a ``confidence`` derived only from corroboration and source quality — never
    a black-box number,
  * a ``scope`` tag (IN_SCOPE / OUT_OF_SCOPE / UNKNOWN) relative to the declared
    engagement scope.

DELIBERATE POSTURE. An asset appearing in the inventory means "this was observed
in a public source", never "this is exploitable" or "this belongs to the
target". Ownership and exposure are separate, evidence-backed judgements made
downstream; a name like ``admin.example.com`` is a *naming signal*, not a claim
that an admin panel is exposed (spec §6). Standard library only.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional


def _now() -> float:
    return time.time()


class AssetType(str, Enum):
    """The kinds of asset the inventory holds (spec §7)."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    WEBSITE = "website"
    API = "api"
    DOCUMENTATION = "documentation"
    PORTAL = "portal"
    BLOG = "blog"
    STATUS_PAGE = "status_page"
    REPOSITORY = "repository"
    PUBLIC_FILE = "public_file"
    PUBLIC_SERVICE_REFERENCE = "public_service_reference"
    CERTIFICATE = "certificate"
    IP = "ip"
    DNS_RECORD = "dns_record"
    CLOUD_REFERENCE = "cloud_reference"
    EMAIL = "email"
    HISTORICAL_ASSET = "historical_asset"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, raw: Any) -> "AssetType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN


class DomainClass(str, Enum):
    """Domain relationship classes (spec §4). Every class but PRIMARY is a
    hypothesis that requires evidence before it is treated as the target's."""

    PRIMARY = "primary_domain"
    SECONDARY = "secondary_domain"
    HISTORICAL = "historical_domain"
    RELATED = "related_domain"
    UNVERIFIED = "unverified_domain"


class SignalState(str, Enum):
    """Liveness class for a discovered subdomain/asset (spec §5)."""

    LIVE_SIGNAL = "live_signal"
    HISTORICAL = "historical"
    ARCHIVED = "archived"
    UNVERIFIED = "unverified"


class ExposureCategory(str, Enum):
    """Public-exposure categories (spec §47). A category is descriptive — it
    says *what kind of public footprint* a signal represents, not that it is a
    vulnerability."""

    DOMAIN = "domain_exposure"
    DOCUMENT = "document_exposure"
    METADATA = "metadata_exposure"
    INFRASTRUCTURE = "infrastructure_exposure"
    TECHNOLOGY = "technology_exposure"
    REPOSITORY = "repository_exposure"
    HISTORICAL = "historical_exposure"
    PUBLIC_IDENTIFIER = "public_identifier_exposure"


class ScopeStatus(str, Enum):
    """Where an asset sits relative to the declared engagement scope (spec §35)."""

    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    UNKNOWN = "unknown"


# Rough, auditable source-quality weights used by the confidence model. Higher
# means "harder to forge / more authoritative for this kind of fact".
SOURCE_QUALITY: Dict[str, float] = {
    "crtsh": 0.9,            # certificate transparency — cryptographic, public
    "certificate": 0.9,
    "passive_dns": 0.8,
    "dns": 0.8,
    "wellknown": 0.85,      # the target's own published /.well-known files
    "sitemap": 0.8,
    "robots": 0.6,
    "wayback": 0.7,         # historical archive
    "archive": 0.7,
    "github": 0.7,
    "repository": 0.7,
    "html": 0.5,            # parsed from a page body
    "technology": 0.5,
    "extract": 0.4,         # a reference scraped from text
    "manual": 0.6,
}


@dataclass
class Evidence:
    """One observation supporting a fact about an asset. Append-only."""

    source: str                     # collector/analyzer name
    detail: str = ""
    url: str = ""                   # where it was seen, if applicable
    observed_at: float = field(default_factory=_now)
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def quality(self) -> float:
        return SOURCE_QUALITY.get(self.source.lower(), 0.4)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source, "detail": self.detail, "url": self.url,
            "observed_at": round(self.observed_at, 3), "meta": self.meta,
        }


# Confidence bands for the 0..100 corroboration score below.
_CONF_BANDS = [
    (80.0, "high"),
    (55.0, "medium"),
    (30.0, "low"),
    (0.0, "tentative"),
]


def confidence_band(score: float) -> str:
    for threshold, name in _CONF_BANDS:
        if score >= threshold:
            return name
    return "tentative"


@dataclass
class Asset:
    """A single publicly-observable asset in the attack-surface inventory."""

    asset_type: AssetType
    value: str                                  # canonical identifier
    label: str = ""                             # human label if different
    domain: str = ""                            # registrable domain it belongs to
    subdomain: str = ""                         # full hostname, when applicable
    url: str = ""
    domain_class: Optional[DomainClass] = None
    subdomain_role: str = ""                    # naming-signal role (spec §6)
    signal_state: SignalState = SignalState.UNVERIFIED
    scope: ScopeStatus = ScopeStatus.UNKNOWN
    technologies: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    evidence: List[Evidence] = field(default_factory=list)
    first_seen: float = field(default_factory=_now)
    last_seen: float = field(default_factory=_now)
    asset_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        self.asset_type = AssetType.coerce(self.asset_type)
        self.value = (self.value or "").strip()

    @property
    def key(self) -> str:
        """The de-duplication key: (type, lower-cased value)."""
        return f"{self.asset_type.value}::{self.value.lower()}"

    @property
    def sources(self) -> List[str]:
        return sorted({e.source for e in self.evidence})

    @property
    def confidence(self) -> float:
        """A 0..100 corroboration score (spec §44/§45): breadth of independent
        sources, weighted by source quality. No source ⇒ 0. Deterministic and
        explainable — never a hidden certainty."""
        if not self.evidence:
            return 0.0
        by_source: Dict[str, float] = {}
        for ev in self.evidence:
            by_source[ev.source.lower()] = max(by_source.get(ev.source.lower(), 0.0),
                                                ev.quality)
        best = max(by_source.values())
        extra = sorted((q for s, q in by_source.items()), reverse=True)[1:]
        corroboration = sum(min(q, 0.5) for q in extra)   # diminishing per-source
        score = 100.0 * min(1.0, best * 0.75 + corroboration * 0.5)
        return round(score, 1)

    @property
    def confidence_band(self) -> str:
        return confidence_band(self.confidence)

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev)
        self.last_seen = max(self.last_seen, ev.observed_at)
        self.first_seen = min(self.first_seen, ev.observed_at)

    def add_tag(self, tag: str) -> None:
        if tag and tag not in self.tags:
            self.tags.append(tag)

    def add_technology(self, tech: Dict[str, Any]) -> None:
        name = str(tech.get("name", "")).lower()
        if not name:
            return
        for existing in self.technologies:
            if str(existing.get("name", "")).lower() == name:
                # Fold in a version if we now have one and did not before.
                if tech.get("version") and not existing.get("version"):
                    existing["version"] = tech["version"]
                return
        self.technologies.append(dict(tech))

    def merge(self, other: "Asset") -> None:
        """Fold another asset with the same key into this one, preserving all
        provenance. The oldest first_seen and newest last_seen win."""
        for ev in other.evidence:
            self.add_evidence(ev)
        for t in other.tags:
            self.add_tag(t)
        for tech in other.technologies:
            self.add_technology(tech)
        for k, v in other.attributes.items():
            self.attributes.setdefault(k, v)
        if not self.url and other.url:
            self.url = other.url
        if not self.subdomain_role and other.subdomain_role:
            self.subdomain_role = other.subdomain_role
        if self.domain_class is None and other.domain_class is not None:
            self.domain_class = other.domain_class
        # Liveness: promote toward "more live" (LIVE > HISTORICAL/ARCHIVED > UNVERIFIED).
        order = {SignalState.UNVERIFIED: 0, SignalState.ARCHIVED: 1,
                 SignalState.HISTORICAL: 1, SignalState.LIVE_SIGNAL: 2}
        if order.get(other.signal_state, 0) > order.get(self.signal_state, 0):
            self.signal_state = other.signal_state
        # Scope: a definite IN/OUT overrides UNKNOWN; conflicting definites keep ours.
        if self.scope is ScopeStatus.UNKNOWN and other.scope is not ScopeStatus.UNKNOWN:
            self.scope = other.scope
        self.first_seen = min(self.first_seen, other.first_seen)
        self.last_seen = max(self.last_seen, other.last_seen)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type.value,
            "value": self.value,
            "label": self.label or self.value,
            "domain": self.domain,
            "subdomain": self.subdomain,
            "url": self.url,
            "domain_class": self.domain_class.value if self.domain_class else None,
            "subdomain_role": self.subdomain_role,
            "signal_state": self.signal_state.value,
            "scope": self.scope.value,
            "technologies": self.technologies,
            "tags": sorted(self.tags),
            "attributes": self.attributes,
            "confidence": self.confidence,
            "confidence_band": self.confidence_band,
            "sources": self.sources,
            "first_seen": round(self.first_seen, 3),
            "last_seen": round(self.last_seen, 3),
            "evidence": [e.to_dict() for e in self.evidence],
        }


class AttackSurfaceInventory:
    """The de-duplicated set of assets discovered for one target.

    Adding an asset whose ``key`` already exists merges it (accumulating
    evidence) rather than creating a duplicate. The inventory is the single
    source of truth the graph, scoring, exposure and report layers all read."""

    def __init__(self, target: str = "") -> None:
        self.target = target
        self._by_key: Dict[str, Asset] = {}

    def __len__(self) -> int:
        return len(self._by_key)

    def __iter__(self) -> Iterable[Asset]:
        return iter(self._by_key.values())

    def add(self, asset: Asset) -> Asset:
        existing = self._by_key.get(asset.key)
        if existing is None:
            self._by_key[asset.key] = asset
            return asset
        existing.merge(asset)
        return existing

    def upsert(self, asset_type: AssetType, value: str, *,
               evidence: Optional[Evidence] = None, **kwargs: Any) -> Optional[Asset]:
        """Convenience: build an asset, attach one evidence, and add it. Returns
        the (possibly merged) live asset, or None if ``value`` is empty."""
        if not value:
            return None
        asset = Asset(asset_type=asset_type, value=value, **kwargs)
        if evidence is not None:
            asset.add_evidence(evidence)
        return self.add(asset)

    def get(self, asset_type: AssetType, value: str) -> Optional[Asset]:
        key = f"{AssetType.coerce(asset_type).value}::{(value or '').lower()}"
        return self._by_key.get(key)

    def of_type(self, *types: AssetType) -> List[Asset]:
        wanted = {AssetType.coerce(t) for t in types}
        return [a for a in self._by_key.values() if a.asset_type in wanted]

    def assets(self) -> List[Asset]:
        return list(self._by_key.values())

    def counts_by_type(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for a in self._by_key.values():
            out[a.asset_type.value] = out.get(a.asset_type.value, 0) + 1
        return out

    def counts_by_scope(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for a in self._by_key.values():
            out[a.scope.value] = out.get(a.scope.value, 0) + 1
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "total": len(self),
            "by_type": self.counts_by_type(),
            "by_scope": self.counts_by_scope(),
            "assets": [a.to_dict() for a in sorted(
                self._by_key.values(),
                key=lambda x: (x.asset_type.value, x.value.lower()))],
        }
