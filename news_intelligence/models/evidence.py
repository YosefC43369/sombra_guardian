"""
news_intelligence.models.evidence — provenance primitives for news intelligence.

The News Intelligence Engine speaks the *same* evidence language as the Threat
Actor Intelligence and Behavioral Intelligence engines, on purpose: a citation
extracted from a news article must be able to travel into
``threat_actor_intelligence`` (IOC enrichment) or ``entity_fusion`` without
translation. Rather than fork the well-tested primitives, this module re-exports
``EvidenceRef`` / ``EvidenceBundle`` / ``TLP`` / ``SourceClass`` from
``threat_actor_intelligence.models.evidence`` and layers on the small amount of
news-specific vocabulary the news engine needs on top of them.

If the CTI engine is ever absent, a self-contained fallback keeps the news engine
importable and its tests runnable — the fallback is a byte-for-byte behavioural
copy of the shared primitives, not a divergent implementation.
"""

from __future__ import annotations

from typing import Any, Dict

try:  # reuse the proven, shared evidence primitives
    from threat_actor_intelligence.models.evidence import (  # type: ignore
        TLP, SourceClass, SOURCE_CLASS_WEIGHT, EvidenceRef, EvidenceBundle,
    )
    _SHARED = True
except Exception:  # pragma: no cover - fallback keeps the engine standalone
    _SHARED = False
    import hashlib
    import time
    from dataclasses import dataclass, field, asdict
    from enum import Enum
    from typing import List, Optional

    class TLP(str, Enum):
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
        GOVERNMENT = "government"
        STANDARDS = "standards"
        VENDOR = "vendor"
        RESEARCH = "research"
        COMMUNITY = "community"
        AGGREGATOR = "aggregator"
        FEED = "feed"
        UNKNOWN = "unknown"

        @classmethod
        def coerce(cls, raw: Any) -> "SourceClass":
            if isinstance(raw, cls):
                return raw
            try:
                return cls(str(raw).strip().lower())
            except ValueError:
                return cls.UNKNOWN

    SOURCE_CLASS_WEIGHT: Dict["SourceClass", float] = {
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
        provider: str = ""
        source_class: "SourceClass" = SourceClass.UNKNOWN
        title: str = ""
        source_url: str = ""
        external_id: str = ""
        excerpt: str = ""
        content_hash: str = ""
        tlp: "TLP" = TLP.CLEAR
        observed_at: float = 0.0
        collected_at: float = field(default_factory=time.time)
        reliability: float = 0.0
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
            locator = (self.external_id or self.source_url
                       or self.content_hash or self.title)
            return hashlib.sha256(
                f"{self.provider}|{locator}".encode("utf-8")).hexdigest()[:24]

        @property
        def weight(self) -> float:
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
                collected_at=float(d.get("collected_at", time.time())
                                   or time.time()),
                reliability=float(d.get("reliability", 0.0) or 0.0),
                detail=dict(d.get("detail", {}) or {}),
            )

    @dataclass
    class EvidenceBundle:
        refs: List[EvidenceRef] = field(default_factory=list)

        def add(self, ref: EvidenceRef) -> bool:
            seen = {r.ref_id for r in self.refs}
            if ref.ref_id in seen:
                for r in self.refs:
                    if r.ref_id == ref.ref_id:
                        r.observed_at = max(r.observed_at, ref.observed_at)
                        if ref.excerpt and not r.excerpt:
                            r.excerpt = ref.excerpt
                        break
                return False
            self.refs.append(ref)
            return True

        def extend(self, refs) -> int:
            return sum(1 for r in refs if self.add(r))

        def providers(self):
            return sorted({r.provider for r in self.refs if r.provider})

        def source_classes(self):
            return sorted({r.source_class for r in self.refs},
                          key=lambda c: c.value)

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

        def to_list(self):
            return [r.to_dict() for r in self.refs]

        @classmethod
        def from_list(cls, items) -> "EvidenceBundle":
            b = cls()
            for it in items or []:
                b.add(EvidenceRef.from_dict(it))
            return b


# News sources have a finer-grained taxonomy than the coarse CTI SourceClass.
# This maps a news source category (see models.source.SourceCategory) onto the
# shared SourceClass so news evidence weights identically to CTI evidence.
NEWS_CATEGORY_TO_SOURCE_CLASS: Dict[str, "SourceClass"] = {
    "government_advisory": SourceClass.GOVERNMENT,
    "cert": SourceClass.GOVERNMENT,
    "public_stix_feed": SourceClass.STANDARDS,
    "vendor_security_blog": SourceClass.VENDOR,
    "threat_intel_vendor": SourceClass.VENDOR,
    "research_blog": SourceClass.RESEARCH,
    "open_source_project": SourceClass.COMMUNITY,
    "github_security_feed": SourceClass.COMMUNITY,
    "cybersecurity_podcast": SourceClass.RESEARCH,
    "news_organization": SourceClass.FEED,
    "unknown": SourceClass.UNKNOWN,
}


def source_class_for_category(category: Any) -> "SourceClass":
    """Resolve a news source category (string or enum) to a shared SourceClass."""
    key = getattr(category, "value", category)
    return NEWS_CATEGORY_TO_SOURCE_CLASS.get(str(key), SourceClass.UNKNOWN)


__all__ = ["TLP", "SourceClass", "SOURCE_CLASS_WEIGHT", "EvidenceRef",
           "EvidenceBundle", "NEWS_CATEGORY_TO_SOURCE_CLASS",
           "source_class_for_category"]
