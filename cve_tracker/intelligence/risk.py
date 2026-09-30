"""
cve_tracker.intelligence.risk — bundle the factual risk indicators.

Rule §17 is explicit: do NOT invent a fake CVSS; instead expose the separate
indicators. :class:`RiskIndicators` is exactly that bundle — the underlying
facts (CVSS, KEV, exploit-reference count, affected-product count, source
confidence, recency, exposure shape) gathered in one object the formatter and AI
prompt can read, with the internal priority alongside and clearly labelled.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from ..enums import ExploitMaturity
from ..models import CVERecord
from ..utils import now_epoch
from .exposure import assess, ExposureProfile
from .scoring import compute_breakdown, ScoreBreakdown


@dataclass
class RiskIndicators:
    cve_id: str
    cvss_score: float = None  # type: ignore[assignment]
    severity: str = "UNKNOWN"
    kev: bool = False
    exploit_maturity: str = ExploitMaturity.UNKNOWN.value
    exploit_reference_count: int = 0
    affected_product_count: int = 0
    source_count: int = 0
    source_confidence: str = "low"
    recency_days: int = -1
    epss_probability: Optional[float] = None
    epss_percentile: Optional[float] = None
    exposure: ExposureProfile = None  # type: ignore[assignment]
    # internal signal (NOT official)
    priority: str = "INFO"
    priority_score: int = 0
    priority_reasons: List[str] = field(default_factory=list)
    breakdown: ScoreBreakdown = None  # type: ignore[assignment]


def _confidence(source_count: int) -> str:
    if source_count >= 3:
        return "high"
    if source_count == 2:
        return "medium"
    return "low"


def assess_risk(record: CVERecord) -> RiskIndicators:
    from ..enrichment.exploit_status import exploit_reference_count

    from ..enrichment.epss import get_epss

    ref_epoch = record.published_at or record.first_seen_at
    recency = int((now_epoch() - ref_epoch) / 86400) if ref_epoch else -1
    bd = compute_breakdown(record)
    epss = get_epss(record)

    return RiskIndicators(
        cve_id=record.cve_id,
        cvss_score=record.cvss_score,
        severity=record.severity,
        kev=record.in_kev,
        exploit_maturity=record.exploit_maturity,
        exploit_reference_count=exploit_reference_count(record),
        affected_product_count=len(record.products),
        source_count=len(record.source_names),
        source_confidence=_confidence(len(record.source_names)),
        recency_days=recency,
        epss_probability=(epss.probability if epss else None),
        epss_percentile=(epss.percentile if epss else None),
        exposure=assess(record),
        priority=record.priority,
        priority_score=bd.total,
        priority_reasons=bd.reasons[:6],
        breakdown=bd,
    )
