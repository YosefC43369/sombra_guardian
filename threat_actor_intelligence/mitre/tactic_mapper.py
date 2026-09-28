"""
threat_actor_intelligence.mitre.tactic_mapper — techniques ⇒ tactics / coverage.

Given a set of observed technique ids, resolve their tactics against the loaded
ATT&CK engine and produce the kill-chain coverage view (which tactics an actor/
campaign is documented to operate in, and with which techniques). This is what
the ATT&CK coverage section of every report and the MITRE graph render from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..models.technique import ENTERPRISE_TACTICS, tactic_order
from .attack_engine import ATTACKEngine


@dataclass
class TacticCoverage:
    tactic_id: str
    short_name: str
    name: str
    order: int
    techniques: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"tactic_id": self.tactic_id, "short_name": self.short_name,
                "name": self.name, "order": self.order,
                "techniques": list(self.techniques), "count": len(self.techniques)}


class TacticMapper:
    def __init__(self, attack: Optional[ATTACKEngine] = None):
        self.attack = attack
        self._name_by_short = {short: (tid, name)
                               for tid, short, name in ENTERPRISE_TACTICS}

    def tactics_for(self, technique_id: str) -> List[str]:
        if self.attack:
            t = self.attack.technique(technique_id)
            if t and t.tactics:
                return t.tactics
        return []

    def coverage(self, technique_ids: List[str]) -> List[TacticCoverage]:
        buckets: Dict[str, List[str]] = {}
        for tid in sorted(set(technique_ids or [])):
            tactics = self.tactics_for(tid) or ["unknown"]
            for tac in tactics:
                buckets.setdefault(tac, []).append(tid)
        out: List[TacticCoverage] = []
        for short, techs in buckets.items():
            tid, name = self._name_by_short.get(short, ("", short.title()))
            out.append(TacticCoverage(tactic_id=tid, short_name=short, name=name,
                                      order=tactic_order(short),
                                      techniques=sorted(set(techs))))
        return sorted(out, key=lambda c: c.order)

    def coverage_score(self, technique_ids: List[str]) -> float:
        """Fraction of the 14 enterprise tactics an entity is documented in."""
        covered = {c.short_name for c in self.coverage(technique_ids)
                   if c.short_name != "unknown"}
        return round(len(covered) / len(ENTERPRISE_TACTICS), 3)

    def summary(self, technique_ids: List[str]) -> Dict[str, object]:
        cov = self.coverage(technique_ids)
        return {"tactics_covered": len([c for c in cov if c.short_name != "unknown"]),
                "tactics_total": len(ENTERPRISE_TACTICS),
                "coverage_score": self.coverage_score(technique_ids),
                "techniques": len(set(technique_ids or [])),
                "by_tactic": [c.to_dict() for c in cov]}


__all__ = ["TacticMapper", "TacticCoverage"]
