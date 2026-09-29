"""
cybersecurity_intelligence.models.source — publishers and their reliability.

A :class:`SourceRecord` is one publisher/feed the platform collects from (CISA,
a vendor blog, an RSS firehose, a GitHub advisory repo). A
:class:`ReliabilityAssessment` is the *explained* grade the
``SourceReliabilityEngine`` attaches to it — a grade plus the factor-by-factor
reasons that produced it. The reasons are the whole point: the platform never
declares a source absolutely "true" or "false" (spec §6), it grades dependability
and shows its work so an analyst can disagree.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from threat_actor_intelligence.models.evidence import SourceClass

from ..constants import ReliabilityGrade


def source_id_for(name: str, url: str = "") -> str:
    """Stable id for a source: prefer the registrable identity (name), fall back
    to the URL. Case/space-insensitive so "The Hacker News" == "the hacker news"."""
    basis = (name or url or "unknown").strip().lower()
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


@dataclass
class ReliabilityFactor:
    """One contributing reason behind a reliability grade."""
    name: str
    contribution: float          # signed contribution to the 0..1 score
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "contribution": round(self.contribution, 4),
                "note": self.note}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ReliabilityFactor":
        return cls(name=str(d.get("name", "")),
                   contribution=float(d.get("contribution", 0.0) or 0.0),
                   note=str(d.get("note", "")))


@dataclass
class ReliabilityAssessment:
    """An explainable reliability grade for a source at a point in time."""
    grade: ReliabilityGrade = ReliabilityGrade.UNKNOWN
    score: float = 0.0
    factors: List[ReliabilityFactor] = field(default_factory=list)
    assessed_at: float = field(default_factory=time.time)

    def reasons(self) -> List[str]:
        """Human-readable one-liners, strongest contribution first."""
        ordered = sorted(self.factors, key=lambda f: abs(f.contribution),
                         reverse=True)
        return [f"{f.name}: {f.note}".strip().rstrip(":") for f in ordered if f.note]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "grade": self.grade.value,
            "score": round(self.score, 4),
            "factors": [f.to_dict() for f in self.factors],
            "reasons": self.reasons(),
            "assessed_at": self.assessed_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ReliabilityAssessment":
        return cls(
            grade=ReliabilityGrade.coerce(d.get("grade")),
            score=float(d.get("score", 0.0) or 0.0),
            factors=[ReliabilityFactor.from_dict(f) for f in d.get("factors", []) or []],
            assessed_at=float(d.get("assessed_at", time.time()) or time.time()),
        )


@dataclass
class SourceRecord:
    """A public source the platform collects from and grades."""
    name: str
    url: str = ""
    source_class: SourceClass = SourceClass.UNKNOWN
    publisher: str = ""
    language: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    article_count: int = 0
    content_hash: str = ""
    reliability: Optional[ReliabilityAssessment] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.source_class = SourceClass.coerce(self.source_class)
        now = time.time()
        if not self.first_seen:
            self.first_seen = now
        if not self.last_seen:
            self.last_seen = self.first_seen

    @property
    def source_id(self) -> str:
        return source_id_for(self.name, self.url)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "name": self.name,
            "url": self.url,
            "source_class": self.source_class.value,
            "publisher": self.publisher,
            "language": self.language,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "article_count": self.article_count,
            "content_hash": self.content_hash,
            "reliability": self.reliability.to_dict() if self.reliability else None,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SourceRecord":
        return cls(
            name=str(d.get("name", "")),
            url=str(d.get("url", "")),
            source_class=SourceClass.coerce(d.get("source_class")),
            publisher=str(d.get("publisher", "")),
            language=str(d.get("language", "")),
            first_seen=float(d.get("first_seen", 0.0) or 0.0),
            last_seen=float(d.get("last_seen", 0.0) or 0.0),
            article_count=int(d.get("article_count", 0) or 0),
            content_hash=str(d.get("content_hash", "")),
            reliability=(ReliabilityAssessment.from_dict(d["reliability"])
                         if d.get("reliability") else None),
            detail=dict(d.get("detail", {}) or {}),
        )


__all__ = ["SourceRecord", "ReliabilityAssessment", "ReliabilityFactor",
           "source_id_for"]
