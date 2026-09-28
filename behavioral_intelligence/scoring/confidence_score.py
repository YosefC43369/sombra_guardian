"""
behavioral_intelligence.scoring.confidence_score — confidence aggregation
(spec §33).

Re-exports the canonical ``make_confidence`` constructor and adds aggregation
helpers: combine the confidence of several assertions into an overall figure,
and compute an evidence-source count from a set of ``EvidenceRef``. Keeping these
here means every part of the engine derives confidence the same way, from the
same four dimensions (sample size, observation period, source diversity,
supporting vs. contradicting signals).
"""

from __future__ import annotations

from typing import Any, Dict, Sequence

from ..models.confidence import (Assertion, EvidenceRef,
                                 make_confidence, band_for)
from .. import util


def source_count(evidence: Sequence[EvidenceRef]) -> int:
    """Number of distinct providers/sources among a set of evidence refs."""
    return len({e.provider or e.source_url for e in evidence if (e.provider or
                                                                 e.source_url)})


def aggregate_confidence(assertions: Sequence[Assertion]) -> Dict[str, Any]:
    """Summarise the confidence across many assertions: mean and min score, and
    the share of assertions in each band. Useful for a report header."""
    scored = [a.confidence for a in assertions if a.confidence is not None]
    if not scored:
        return {"mean": 0.0, "min": 0.0, "count": 0}
    scores = [c.score for c in scored]
    bands: Dict[str, int] = {}
    for c in scored:
        bands[c.band] = bands.get(c.band, 0) + 1
    return {
        "mean": round(util.mean(scores), 3),
        "min": round(min(scores), 3),
        "max": round(max(scores), 3),
        "count": len(scored),
        "bands": bands,
    }


# Re-exported so callers import confidence construction from one place.
__all__ = ["make_confidence", "band_for", "source_count", "aggregate_confidence"]
