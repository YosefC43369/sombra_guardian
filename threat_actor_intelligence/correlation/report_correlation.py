"""
threat_actor_intelligence.correlation.report_correlation.

Corroboration across sources: which public reports describe the *same* actor,
campaign or malware. When two independent reports (distinct sources) reference
the same entity, that mutual reference raises the confidence of the underlying
fact — this is the "which sources corroborate the same campaign?" query. The
engine emits ``MENTIONS`` relationships (report→entity) and detects corroboration
clusters (an entity referenced by ≥2 distinct sources).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from ..models.report import Report
from .base import CorrelationResult, build_relationship, correlation_assertion


@dataclass
class Corroboration:
    entity_type: str                 # actor | campaign | malware
    entity_id: str
    report_ids: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)

    @property
    def independent_sources(self) -> int:
        return len(set(self.sources))

    @property
    def corroborated(self) -> bool:
        return self.independent_sources >= 2

    def to_dict(self) -> dict:
        return {"entity_type": self.entity_type, "entity_id": self.entity_id,
                "report_ids": list(self.report_ids), "sources": sorted(set(self.sources)),
                "independent_sources": self.independent_sources,
                "corroborated": self.independent_sources >= 2}


class ReportCorrelator:
    _FIELDS = [("actor_ids", "actor"), ("campaign_ids", "campaign"),
               ("family_ids", "malware")]

    def correlate(self, reports: Sequence[Report],
                  *, now: Optional[float] = None) -> CorrelationResult:
        result = CorrelationResult()
        for r in reports:
            ev = [r.as_evidence()]
            for field_name, etype in self._FIELDS:
                for eid in getattr(r, field_name, []) or []:
                    rel = build_relationship(
                        src_type="report", src_id=r.report_id, rel_type="mentions",
                        dst_type=etype, dst_id=eid,
                        signal=f"{r.source or r.vendor} report references {etype}",
                        evidence=ev, now=now, weight=0.6)
                    result.add_relationship(rel)
        cors = self.corroborations(reports)
        for c in cors:
            if c.corroborated:
                result.candidates.append(c.to_dict())
        strong = [c for c in cors if c.corroborated]
        if strong:
            result.assertions.append(correlation_assertion(
                f"{len(strong)} entity(ies) corroborated by ≥2 independent public "
                f"sources.", "OBSERVED", result.relationships))
        return result

    def corroborations(self, reports: Sequence[Report]) -> List[Corroboration]:
        agg: Dict[tuple, Corroboration] = {}
        for r in reports:
            src = r.source or r.vendor or "unknown"
            for field_name, etype in self._FIELDS:
                for eid in getattr(r, field_name, []) or []:
                    key = (etype, eid)
                    c = agg.setdefault(key, Corroboration(etype, eid))
                    c.report_ids.append(r.report_id)
                    c.sources.append(src)
        return sorted(agg.values(), key=lambda c: -c.independent_sources)


__all__ = ["ReportCorrelator", "Corroboration"]
