"""
news_intelligence.models.cve — a CVE as tracked across the news corpus.

``CVENews`` aggregates every article that mentions one CVE, plus the structured
context news reporting attaches to it: affected products/vendors named, severity
wording quoted (never re-scored by the engine), public-exploitation references
(only when an article states them), and the mitigations referenced. It is the
backing object for the CVE News Profile report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .evidence import EvidenceBundle

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def normalize_cve(raw: str) -> str:
    s = (raw or "").strip().upper().replace(" ", "")
    return s if _CVE_RE.match(s) else ""


def is_cve(raw: str) -> bool:
    return bool(normalize_cve(raw))


@dataclass
class CVENews:
    cve_id: str
    article_ids: List[str] = field(default_factory=list)
    vendors: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    severity_quotes: List[str] = field(default_factory=list)   # verbatim, quoted
    exploited_references: List[str] = field(default_factory=list)  # article_ids
    mitigation_references: List[str] = field(default_factory=list)
    first_reported: float = 0.0
    last_reported: float = 0.0
    mention_count: int = 0
    evidence: EvidenceBundle = field(default_factory=EvidenceBundle)
    confidence: Optional[Dict[str, Any]] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.cve_id = normalize_cve(self.cve_id) or self.cve_id.upper()

    @property
    def independent_report_count(self) -> int:
        return self.evidence.distinct_count()

    @property
    def known_exploited(self) -> bool:
        """True only when a public source in the corpus asserts exploitation."""
        return bool(self.exploited_references)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("evidence", None)
        d["evidence"] = self.evidence.to_list()
        d["independent_report_count"] = self.independent_report_count
        d["known_exploited"] = self.known_exploited
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CVENews":
        obj = cls(
            cve_id=str(d.get("cve_id", "")),
            article_ids=list(d.get("article_ids", []) or []),
            vendors=list(d.get("vendors", []) or []),
            affected_products=list(d.get("affected_products", []) or []),
            severity_quotes=list(d.get("severity_quotes", []) or []),
            exploited_references=list(d.get("exploited_references", []) or []),
            mitigation_references=list(d.get("mitigation_references", []) or []),
            first_reported=float(d.get("first_reported", 0.0) or 0.0),
            last_reported=float(d.get("last_reported", 0.0) or 0.0),
            mention_count=int(d.get("mention_count", 0) or 0),
            confidence=d.get("confidence"),
            detail=dict(d.get("detail", {}) or {}),
        )
        obj.evidence = EvidenceBundle.from_list(d.get("evidence", []) or [])
        return obj


__all__ = ["CVENews", "normalize_cve", "is_cve"]
