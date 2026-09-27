"""
entity_fusion.entity — the universal entity model at the heart of the fusion
engine.

WHAT / WHY. Every OSINT/SOCMINT module in this repository emits records in its
own shape (a crt.sh subdomain, a BGPView ASN, a username hit, a WHOIS org). The
fusion engine cannot correlate those until they share one vocabulary. This
module defines that vocabulary: a single ``Entity`` dataclass that any record
can be lifted into, plus the supporting value objects — ``EntityType``,
``SourceRef`` (provenance), ``Evidence`` (a single observed fact with its
source) and ``Relationship`` (a typed, directional link to another entity).

DESIGN NOTES
------------
- **Serializable, hashable-by-identity.** Every entity carries a stable UUID so
  it can be referenced from a graph, a cache key, or a report without relying
  on Python object identity. ``to_dict``/``from_dict`` round-trip losslessly so
  entities survive a trip through SQLite or JSON.
- **Provenance is not optional.** An entity records *where every value came
  from* (``sources``) and keeps an append-only ``evidence`` list. This repo's
  discipline is to separate observed fact from inference — the confidence engine
  later reads this evidence, it never invents it.
- **Merge is explicit and reversible-in-spirit.** ``Entity.merge`` folds another
  entity's aliases/values/sources/evidence/relationships in without losing
  provenance, and records the merge as evidence so a later reviewer can see why
  two records were joined.
- **Standard library only.** dataclasses + enum + uuid + time. No third-party
  dependency, matching the ``osint/`` framework this sits on top of.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Set


# --------------------------------------------------------------------------- #
# Enumerations                                                                 #
# --------------------------------------------------------------------------- #

class EntityType(str, Enum):
    """The kinds of thing the engine can represent.

    ``str`` mixin so the value serializes as a plain string in JSON/SQLite and
    compares equal to its literal (``EntityType.DOMAIN == "domain"``)."""

    PERSON = "person"
    ORGANIZATION = "organization"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    ASN = "asn"
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    WEBSITE = "website"
    REPOSITORY = "repository"
    CERTIFICATE = "certificate"
    WALLET = "wallet"
    DOCUMENT = "document"
    IMAGE = "image"
    LOCATION = "location"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, raw: Any) -> "EntityType":
        """Best-effort map an arbitrary string to a type, defaulting to UNKNOWN.
        Never raises — an unrecognized upstream type must not crash ingestion."""
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN


class RelationType(str, Enum):
    """Typed edges between entities. Mirrors the graph engine's edge kinds so a
    relationship added here renders directly as a graph edge."""

    OWNS = "owns"
    MENTIONS = "mentions"
    SHARES_EMAIL = "shares_email"
    SHARES_AVATAR = "shares_avatar"
    SHARES_DOMAIN = "shares_domain"
    SHARES_WALLET = "shares_wallet"
    SHARES_ORG = "shares_org"
    SHARES_CERTIFICATE = "shares_certificate"
    SHARES_PHONE = "shares_phone"
    HISTORICAL_REFERENCE = "historical_reference"
    APPEARED_IN = "appeared_in"
    RESOLVES_TO = "resolves_to"
    SAME_AS = "same_as"           # asserted identity equivalence (post-fusion)

    @classmethod
    def coerce(cls, raw: Any) -> "RelationType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.MENTIONS


def _now() -> float:
    return time.time()


def new_uuid() -> str:
    return str(uuid.uuid4())


# --------------------------------------------------------------------------- #
# Value objects                                                                #
# --------------------------------------------------------------------------- #

@dataclass
class SourceRef:
    """A pointer to where a value was observed.

    ``provider`` is the module/source name (e.g. ``crtsh``, ``github``); ``url``
    is the public location if one exists; ``confidence`` is that source's own
    self-reported reliability in [0, 1] (defaults to 1.0 — "observed directly").
    """

    provider: str
    url: str = ""
    observed_at: float = field(default_factory=_now)
    confidence: float = 1.0
    detail: str = ""

    def key(self) -> str:
        """A stable de-duplication key for a source reference."""
        return f"{self.provider}|{self.url}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SourceRef":
        return cls(
            provider=str(data.get("provider", "")),
            url=str(data.get("url", "")),
            observed_at=float(data.get("observed_at", _now())),
            confidence=float(data.get("confidence", 1.0)),
            detail=str(data.get("detail", "")),
        )


@dataclass
class Evidence:
    """A single observed fact contributing to an entity or a correlation.

    ``kind`` names the signal (``shared_avatar_hash``, ``same_email``,
    ``username_variant`` …); ``value`` is the concrete observed datum;
    ``weight`` is how strongly this evidence supports the claim in [-1, 1]
    (negative = contradicting evidence). The confidence engine sums weighted
    evidence into an explainable score — it does not fabricate weights, they
    are set where the fact is observed."""

    kind: str
    value: str = ""
    weight: float = 0.0
    source: Optional[SourceRef] = None
    note: str = ""
    observed_at: float = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.to_dict() if self.source else None
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Evidence":
        src = data.get("source")
        return cls(
            kind=str(data.get("kind", "")),
            value=str(data.get("value", "")),
            weight=float(data.get("weight", 0.0)),
            source=SourceRef.from_dict(src) if isinstance(src, dict) else None,
            note=str(data.get("note", "")),
            observed_at=float(data.get("observed_at", _now())),
        )


@dataclass
class Relationship:
    """A typed, directional link from this entity to another (by UUID)."""

    target_id: str
    type: RelationType = RelationType.MENTIONS
    weight: float = 1.0
    source: Optional[SourceRef] = None
    note: str = ""

    def key(self) -> str:
        return f"{self.type.value}|{self.target_id}"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        d["source"] = self.source.to_dict() if self.source else None
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Relationship":
        src = data.get("source")
        return cls(
            target_id=str(data.get("target_id", "")),
            type=RelationType.coerce(data.get("type")),
            weight=float(data.get("weight", 1.0)),
            source=SourceRef.from_dict(src) if isinstance(src, dict) else None,
            note=str(data.get("note", "")),
        )


# --------------------------------------------------------------------------- #
# The Entity                                                                   #
# --------------------------------------------------------------------------- #

@dataclass
class Entity:
    """A universal OSINT entity.

    ``value`` is the primary identifier in its raw form; ``normalized`` is the
    canonical form used for correlation (set by the normalization engine).
    ``aliases`` collects every other spelling/handle seen for the same thing.
    ``metadata`` is a free-form bag for type-specific attributes (a bio, a
    display name, a favicon hash, a country code …).
    """

    type: EntityType = EntityType.UNKNOWN
    value: str = ""
    id: str = field(default_factory=new_uuid)
    normalized: str = ""
    aliases: Set[str] = field(default_factory=set)
    sources: List[SourceRef] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    first_seen: float = field(default_factory=_now)
    last_seen: float = field(default_factory=_now)

    def __post_init__(self) -> None:
        self.type = EntityType.coerce(self.type)
        if not self.normalized and self.value:
            # A pre-normalization fallback; the normalization engine overwrites
            # this with a language-aware canonical form.
            self.normalized = self.value.strip().lower()
        # Ensure aliases is a set even if constructed from a list.
        if not isinstance(self.aliases, set):
            self.aliases = set(self.aliases or [])

    # ---- provenance-preserving mutators ---------------------------------- #

    def add_alias(self, alias: Optional[str]) -> None:
        if alias:
            cleaned = alias.strip()
            if cleaned and cleaned != self.value:
                self.aliases.add(cleaned)

    def add_source(self, source: SourceRef) -> None:
        """Append a source, de-duplicating on (provider, url) and keeping the
        earliest ``observed_at`` so ``first_seen`` stays meaningful."""
        for existing in self.sources:
            if existing.key() == source.key():
                existing.observed_at = min(existing.observed_at, source.observed_at)
                self._touch(source.observed_at)
                return
        self.sources.append(source)
        self._touch(source.observed_at)

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev)
        self._touch(ev.observed_at)

    def add_relationship(self, rel: Relationship) -> None:
        """Append a relationship, de-duplicating on (type, target). The strongest
        weight wins so re-observing a link never weakens it."""
        for existing in self.relationships:
            if existing.key() == rel.key():
                existing.weight = max(existing.weight, rel.weight)
                return
        self.relationships.append(rel)

    def _touch(self, when: float) -> None:
        self.first_seen = min(self.first_seen, when)
        self.last_seen = max(self.last_seen, when)

    # ---- provider set (convenience for reports/confidence) --------------- #

    @property
    def providers(self) -> Set[str]:
        return {s.provider for s in self.sources if s.provider}

    def has_provider(self, provider: str) -> bool:
        return provider in self.providers

    # ---- merge ----------------------------------------------------------- #

    def merge(self, other: "Entity", *, note: str = "") -> "Entity":
        """Fold ``other`` into ``self`` in place, preserving all provenance.

        The surviving entity keeps ``self``'s id and type (type is upgraded from
        UNKNOWN if ``other`` is specific). ``other``'s value becomes an alias if
        it differs. The merge itself is recorded as evidence so the join is
        auditable — this engine never silently collapses two records."""
        if self.type == EntityType.UNKNOWN and other.type != EntityType.UNKNOWN:
            self.type = other.type

        self.add_alias(other.value)
        for a in other.aliases:
            self.add_alias(a)
        for s in other.sources:
            self.add_source(s)
        for ev in other.evidence:
            self.add_evidence(ev)
        for rel in other.relationships:
            self.add_relationship(rel)

        # metadata: keep existing keys, fill gaps from other (first-writer wins).
        for k, v in other.metadata.items():
            self.metadata.setdefault(k, v)

        self._touch(other.first_seen)
        self._touch(other.last_seen)
        self.confidence = max(self.confidence, other.confidence)
        self.add_evidence(Evidence(
            kind="entity_merge",
            value=other.id,
            weight=0.0,
            note=note or f"merged {other.type.value}:{other.value!r} into "
                         f"{self.type.value}:{self.value!r}",
        ))
        return self

    # ---- serialization --------------------------------------------------- #

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "value": self.value,
            "normalized": self.normalized,
            "aliases": sorted(self.aliases),
            "sources": [s.to_dict() for s in self.sources],
            "evidence": [e.to_dict() for e in self.evidence],
            "relationships": [r.to_dict() for r in self.relationships],
            "metadata": self.metadata,
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Entity":
        ent = cls(
            type=EntityType.coerce(data.get("type")),
            value=str(data.get("value", "")),
            id=str(data.get("id") or new_uuid()),
            normalized=str(data.get("normalized", "")),
            aliases=set(data.get("aliases", []) or []),
            metadata=dict(data.get("metadata", {}) or {}),
            confidence=float(data.get("confidence", 0.0)),
            first_seen=float(data.get("first_seen", _now())),
            last_seen=float(data.get("last_seen", _now())),
        )
        ent.sources = [SourceRef.from_dict(s) for s in data.get("sources", []) if isinstance(s, dict)]
        ent.evidence = [Evidence.from_dict(e) for e in data.get("evidence", []) if isinstance(e, dict)]
        ent.relationships = [Relationship.from_dict(r) for r in data.get("relationships", []) if isinstance(r, dict)]
        return ent

    # ---- factory --------------------------------------------------------- #

    @classmethod
    def from_record(cls, record: Dict[str, Any], *, provider: str = "") -> "Entity":
        """Lift a loosely-typed OSINT record ``{"type","value",...}`` (the shape
        emitted by ``osint`` sources and the SOCMINT modules) into an Entity,
        attaching the provider as its first source and carrying every other key
        into metadata."""
        etype = EntityType.coerce(record.get("type"))
        value = str(record.get("value", "")).strip()
        ent = cls(type=etype, value=value)
        prov = provider or str(record.get("source", "")) or "unknown"
        ent.add_source(SourceRef(provider=prov, url=str(record.get("url", ""))))
        for k, v in record.items():
            if k not in ("type", "value", "source", "url"):
                ent.metadata[k] = v
        return ent

    def summary(self) -> str:
        """A one-line human description for logs and terse reports."""
        alias_note = f" (+{len(self.aliases)} aliases)" if self.aliases else ""
        return (f"{self.type.value}:{self.value}{alias_note} "
                f"[{len(self.sources)} src, conf={self.confidence:.0f}]")


def merge_entities(entities: Iterable[Entity], *, note: str = "") -> Optional[Entity]:
    """Fold an iterable of entities into a single entity (the first survives).
    Returns None for an empty iterable."""
    it = iter(entities)
    try:
        base = next(it)
    except StopIteration:
        return None
    for other in it:
        base.merge(other, note=note)
    return base
