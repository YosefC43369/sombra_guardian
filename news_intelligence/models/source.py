"""
news_intelligence.models.source — the news source registry model.

A ``NewsSource`` is a publisher the engine collects from: a vendor security blog,
a national CERT, a government advisory feed, a threat-intel vendor, a research
blog, an open-source project's feed, a mainstream news organization, a
cybersecurity podcast, a GitHub security feed or a public STIX feed.

The source's ``category`` and ``reliability_class`` are the only things that
weight the evidence it produces — they never suppress collection. A source is
skipped only when ``enabled`` is False. Reliability is *evidence quality*, never
a claim about truth of any single article.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .evidence import SourceClass, source_class_for_category


class SourceCategory(str, Enum):
    VENDOR_SECURITY_BLOG = "vendor_security_blog"
    CERT = "cert"
    GOVERNMENT_ADVISORY = "government_advisory"
    THREAT_INTEL_VENDOR = "threat_intel_vendor"
    RESEARCH_BLOG = "research_blog"
    OPEN_SOURCE_PROJECT = "open_source_project"
    NEWS_ORGANIZATION = "news_organization"
    CYBERSECURITY_PODCAST = "cybersecurity_podcast"
    GITHUB_SECURITY_FEED = "github_security_feed"
    PUBLIC_STIX_FEED = "public_stix_feed"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, raw: Any) -> "SourceCategory":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN


class ReliabilityClass(str, Enum):
    """Admiralty-style source reliability grading, used only to weight evidence
    quality (never certainty of a claim)."""
    OFFICIAL_GOVERNMENT = "official_government"
    VENDOR_RESEARCH = "vendor_research"
    ACADEMIC = "academic"
    CERT = "cert"
    INDEPENDENT_RESEARCHER = "independent_researcher"
    NEWS_OUTLET = "news_outlet"
    COMMUNITY_BLOG = "community_blog"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, raw: Any) -> "ReliabilityClass":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN


# 0..1 reliability weight per class. Deterministic and inspectable.
RELIABILITY_WEIGHT: Dict[ReliabilityClass, float] = {
    ReliabilityClass.OFFICIAL_GOVERNMENT: 0.95,
    ReliabilityClass.VENDOR_RESEARCH: 0.85,
    ReliabilityClass.ACADEMIC: 0.82,
    ReliabilityClass.CERT: 0.90,
    ReliabilityClass.INDEPENDENT_RESEARCHER: 0.72,
    ReliabilityClass.NEWS_OUTLET: 0.65,
    ReliabilityClass.COMMUNITY_BLOG: 0.55,
    ReliabilityClass.UNKNOWN: 0.50,
}


def domain_of(url: str) -> str:
    """Best-effort registrable-ish domain of a URL (host, www stripped)."""
    if not url:
        return ""
    try:
        host = urlparse(url if "://" in url else "https://" + url).netloc.lower()
    except Exception:
        return ""
    host = host.split("@")[-1].split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host


@dataclass
class NewsSource:
    name: str
    category: SourceCategory = SourceCategory.UNKNOWN
    reliability_class: ReliabilityClass = ReliabilityClass.UNKNOWN
    country: str = ""
    language: str = "en"
    rss_url: str = ""
    website: str = ""
    update_frequency: int = 3600          # polite poll interval seconds
    enabled: bool = True
    last_ingested: float = 0.0
    tags: List[str] = field(default_factory=list)
    source_id: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.category = SourceCategory.coerce(self.category)
        self.reliability_class = ReliabilityClass.coerce(self.reliability_class)
        if not self.website and self.rss_url:
            d = domain_of(self.rss_url)
            self.website = f"https://{d}" if d else ""
        if not self.source_id:
            seed = (self.rss_url or self.website or self.name).lower()
            self.source_id = "src-" + hashlib.sha256(
                seed.encode("utf-8")).hexdigest()[:16]

    @property
    def domain(self) -> str:
        return domain_of(self.website or self.rss_url)

    @property
    def source_class(self) -> SourceClass:
        """The coarse CTI SourceClass this source maps onto, for evidence
        weighting parity across engines."""
        return source_class_for_category(self.category)

    @property
    def reliability_weight(self) -> float:
        return RELIABILITY_WEIGHT.get(self.reliability_class, 0.5)

    def mark_ingested(self, when: Optional[float] = None) -> None:
        self.last_ingested = when if when is not None else time.time()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["reliability_class"] = self.reliability_class.value
        d["source_id"] = self.source_id
        d["domain"] = self.domain
        d["source_class"] = self.source_class.value
        d["reliability_weight"] = self.reliability_weight
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "NewsSource":
        return cls(
            name=str(d.get("name", "")),
            category=SourceCategory.coerce(d.get("category")),
            reliability_class=ReliabilityClass.coerce(d.get("reliability_class")),
            country=str(d.get("country", "")),
            language=str(d.get("language", "en")),
            rss_url=str(d.get("rss_url", "")),
            website=str(d.get("website", "")),
            update_frequency=int(d.get("update_frequency", 3600) or 3600),
            enabled=bool(d.get("enabled", True)),
            last_ingested=float(d.get("last_ingested", 0.0) or 0.0),
            tags=list(d.get("tags", []) or []),
            source_id=str(d.get("source_id", "")),
            detail=dict(d.get("detail", {}) or {}),
        )


__all__ = ["SourceCategory", "ReliabilityClass", "RELIABILITY_WEIGHT",
           "NewsSource", "domain_of"]
