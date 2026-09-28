"""
threat_actor_intelligence.models.evidence — provenance and evidence primitives.

Every fact this subsystem stores is anchored to a public source. Nothing is
asserted without a traceable ``EvidenceRef`` back to the report, feed item,
advisory or API record it came from. This mirrors the provenance discipline in
``entity_fusion.entity.SourceRef`` and
``behavioral_intelligence.models.confidence.EvidenceRef`` so the three engines
speak the same evidence language and a citation can move between them.

Design rules enforced here:
  * An ``EvidenceRef`` is immutable data (a dataclass) that round-trips through
    ``to_dict``/``from_dict`` without loss.
  * A stable ``ref_id`` is derived from the content so the store can deduplicate
    identical citations across providers (the same CISA advisory ingested twice
    yields one evidence row).
  * ``TLP`` marking travels with every citation so downstream reporting can
    respect the source's sharing constraints.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class TLP(str, Enum):
    """Traffic Light Protocol marking (FIRST TLP 2.0)."""
    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    AMBER_STRICT = "amber+strict"
    RED = "red"

    @classmethod
    def coerce(cls, raw: Any) -> "TLP":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower().replace("tlp:", ""))
        except ValueError:
            return cls.CLEAR


class SourceClass(str, Enum):
    """Coarse category of a public CTI source, used by the confidence model to
    weight corroboration. Government advisories carry more base weight than an
    anonymous blog; an aggregator that re-publishes others' data less than the
    primary."""
    GOVERNMENT = "government"        # CISA, NIST/NVD, CERT, national CSIRTs
    STANDARDS = "standards"          # MITRE ATT&CK/CAPEC/CWE, FIRST
    VENDOR = "vendor"                # security-vendor research blogs/reports
    RESEARCH = "research"            # independent researcher / academic
    COMMUNITY = "community"          # OTX, MISP, community feeds
    AGGREGATOR = "aggregator"        # re-publishes third-party data
    FEED = "feed"                    # RSS / TAXII firehose
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, raw: Any) -> "SourceClass":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN


# Base trust weight (0..1) by source class. Tunable, inspectable, deterministic.
SOURCE_CLASS_WEIGHT: Dict[SourceClass, float] = {
    SourceClass.GOVERNMENT: 0.95,
    SourceClass.STANDARDS: 0.97,
    SourceClass.VENDOR: 0.85,
    SourceClass.RESEARCH: 0.75,
    SourceClass.COMMUNITY: 0.65,
    SourceClass.AGGREGATOR: 0.55,
    SourceClass.FEED: 0.60,
    SourceClass.UNKNOWN: 0.50,
}


@dataclass
class EvidenceRef:
    """A single citation: where a fact came from and how to find it again.

    ``provider`` is the ingestor/source name (e.g. ``cisa``, ``otx``,
    ``vendor:crowdstrike``). ``source_url`` and ``external_id`` locate the
    original public record. ``content_hash`` fingerprints the extracted text so
    identical citations deduplicate. ``observed_at`` is when the underlying event
    was reported; ``collected_at`` is when this engine fetched it."""

    provider: str = ""
    source_class: SourceClass = SourceClass.UNKNOWN
    title: str = ""
    source_url: str = ""
    external_id: str = ""             # advisory id, CVE, feed guid, STIX id
    excerpt: str = ""                 # short quoted span supporting the claim
    content_hash: str = ""
    tlp: TLP = TLP.CLEAR
    observed_at: float = 0.0
    collected_at: float = field(default_factory=time.time)
    reliability: float = 0.0          # source self-reported / assigned (0..1)
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.source_class = SourceClass.coerce(self.source_class)
        self.tlp = TLP.coerce(self.tlp)
        if not self.content_hash and (self.excerpt or self.title):
            self.content_hash = hashlib.sha256(
                (self.title + "\n" + self.excerpt).encode("utf-8")
            ).hexdigest()[:32]
        if not self.reliability:
            self.reliability = SOURCE_CLASS_WEIGHT.get(self.source_class, 0.5)

    @property
    def ref_id(self) -> str:
        """Stable id for deduplication: provider + best available locator."""
        locator = self.external_id or self.source_url or self.content_hash or self.title
        return hashlib.sha256(
            f"{self.provider}|{locator}".encode("utf-8")).hexdigest()[:24]

    @property
    def weight(self) -> float:
        """Effective trust weight: class base blended with source reliability."""
        base = SOURCE_CLASS_WEIGHT.get(self.source_class, 0.5)
        rel = max(0.0, min(1.0, self.reliability or base))
        return round(0.5 * base + 0.5 * rel, 4)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["source_class"] = self.source_class.value
        d["tlp"] = self.tlp.value
        d["ref_id"] = self.ref_id
        d["weight"] = self.weight
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EvidenceRef":
        return cls(
            provider=str(d.get("provider", "")),
            source_class=SourceClass.coerce(d.get("source_class")),
            title=str(d.get("title", "")),
            source_url=str(d.get("source_url", "")),
            external_id=str(d.get("external_id", "")),
            excerpt=str(d.get("excerpt", "")),
            content_hash=str(d.get("content_hash", "")),
            tlp=TLP.coerce(d.get("tlp")),
            observed_at=float(d.get("observed_at", 0.0) or 0.0),
            collected_at=float(d.get("collected_at", time.time()) or time.time()),
            reliability=float(d.get("reliability", 0.0) or 0.0),
            detail=dict(d.get("detail", {}) or {}),
        )


@dataclass
class EvidenceBundle:
    """An ordered, de-duplicated collection of citations backing one assertion or
    entity. Deduplication is by ``ref_id`` so re-ingesting a source does not
    inflate the evidence count."""

    refs: List[EvidenceRef] = field(default_factory=list)

    def add(self, ref: EvidenceRef) -> bool:
        """Add a citation; return True if it was new."""
        seen = {r.ref_id for r in self.refs}
        if ref.ref_id in seen:
            # Merge freshest observed_at into the existing ref.
            for r in self.refs:
                if r.ref_id == ref.ref_id:
                    r.observed_at = max(r.observed_at, ref.observed_at)
                    if ref.excerpt and not r.excerpt:
                        r.excerpt = ref.excerpt
                    break
            return False
        self.refs.append(ref)
        return True

    def extend(self, refs: List[EvidenceRef]) -> int:
        return sum(1 for r in refs if self.add(r))

    def providers(self) -> List[str]:
        return sorted({r.provider for r in self.refs if r.provider})

    def source_classes(self) -> List[SourceClass]:
        return sorted({r.source_class for r in self.refs}, key=lambda c: c.value)

    def distinct_count(self) -> int:
        return len({r.provider for r in self.refs if r.provider})

    def latest(self) -> float:
        return max((r.observed_at for r in self.refs), default=0.0)

    def earliest(self) -> float:
        vals = [r.observed_at for r in self.refs if r.observed_at]
        return min(vals) if vals else 0.0

    def __len__(self) -> int:
        return len(self.refs)

    def __iter__(self):
        return iter(self.refs)

    def to_list(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self.refs]

    @classmethod
    def from_list(cls, items: List[Dict[str, Any]]) -> "EvidenceBundle":
        b = cls()
        for it in items or []:
            b.add(EvidenceRef.from_dict(it))
        return b


__all__ = ["TLP", "SourceClass", "SOURCE_CLASS_WEIGHT", "EvidenceRef",
           "EvidenceBundle"]
