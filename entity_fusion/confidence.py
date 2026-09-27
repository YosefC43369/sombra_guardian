"""
entity_fusion.confidence — turn a cluster of correlated entities into an
explainable confidence verdict.

The engine never emits a bare number. Every assessment carries:

  * a 0-100 ``score`` and a human-readable ``band``,
  * ``positives`` — the facts that support the identity being one entity,
  * ``negatives`` / ``conflicts`` — facts that argue against it (contradicting
    countries, two different verified emails, disjoint timezones …),
  * a ``human_explanation`` paragraph and a ``machine`` dict for pipelines.

SCORING MODEL (deliberately simple and auditable)
-------------------------------------------------
  base            = strongest pairwise link score in the cluster        (0..100)
  + corroboration = independent-provider and distinct-signal breadth bonus
  + hard bonus    = a matched hard identifier (email / cert / wallet / avatar)
  - conflict      = each contradicting singular attribute costs a fixed penalty

The result is clamped to [0, 100] and bucketed into bands. The weights are
constants at the top of the file so the model is inspectable and tunable, and so
two runs over the same evidence produce the same verdict (determinism matters —
this feeds investigation reports and the integrity ledger).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .entity import Entity
from .clustering import Cluster
from .similarity import SimilarityResult


# ---- tunable model constants ---------------------------------------------- #
CORROBORATION_PER_PROVIDER = 3.0     # bonus per independent provider beyond 1
CORROBORATION_PER_SIGNAL = 2.5       # bonus per distinct signal type beyond 1
CORROBORATION_CAP = 20.0             # max total corroboration bonus
HARD_MATCH_BONUS = 12.0
CONFLICT_PENALTY = 18.0              # per contradicting singular attribute
MAX_SCORE = 100.0

# Metadata keys expected to be single-valued for one real entity; disagreement
# between cluster members on any of these is a conflict.
_SINGULAR_KEYS = ("country", "country_code", "verified_email", "birth_year",
                  "legal_name", "national_id")

BANDS: List[Tuple[float, str]] = [
    (90.0, "conclusive"),
    (75.0, "strong"),
    (55.0, "moderate"),
    (35.0, "weak"),
    (0.0, "insufficient"),
]


@dataclass
class ConfidenceFactor:
    """One line in the evidence table."""
    label: str
    kind: str            # "positive" | "negative" | "neutral"
    value: str = ""
    weight: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {"label": self.label, "kind": self.kind,
                "value": self.value, "weight": round(self.weight, 2)}


@dataclass
class ConfidenceReport:
    cluster_id: str
    score: float = 0.0
    band: str = "insufficient"
    positives: List[ConfidenceFactor] = field(default_factory=list)
    negatives: List[ConfidenceFactor] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    human_explanation: str = ""

    @property
    def machine(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "score": round(self.score, 1),
            "band": self.band,
            "positives": [p.to_dict() for p in self.positives],
            "negatives": [n.to_dict() for n in self.negatives],
            "conflicts": self.conflicts,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self.machine
        d["human_explanation"] = self.human_explanation
        return d


class ConfidenceEngine:
    """Assess the confidence that a cluster's members are one entity."""

    def __init__(self, *, conflict_penalty: float = CONFLICT_PENALTY):
        self.conflict_penalty = conflict_penalty

    def assess(self, cluster: Cluster) -> ConfidenceReport:
        report = ConfidenceReport(cluster_id=cluster.id)

        if cluster.size <= 1:
            report.score = 0.0
            report.band = "insufficient"
            report.human_explanation = (
                "Single-member cluster: no corroborating record to correlate "
                "against, so no cross-record identity confidence can be asserted."
            )
            report.positives.append(
                ConfidenceFactor("lone record", "neutral", cluster.members[0].summary()
                                 if cluster.members else "", 0.0))
            return report

        base = self._base_from_links(cluster.links, report)
        corroboration = self._corroboration(cluster, report)
        hard = self._hard_bonus(cluster.links, report)
        penalty, conflicts = self._conflicts(cluster.members)
        report.conflicts = conflicts
        for c in conflicts:
            report.negatives.append(ConfidenceFactor(
                "conflicting attribute", "negative", c, -self.conflict_penalty))

        score = base + corroboration + hard - penalty
        report.score = max(0.0, min(MAX_SCORE, score))
        report.band = self._band(report.score)
        report.human_explanation = self._narrate(cluster, report,
                                                  base, corroboration, hard, penalty)
        return report

    # -- components -------------------------------------------------------- #

    def _base_from_links(self, links: List[SimilarityResult],
                         report: ConfidenceReport) -> float:
        if not links:
            report.positives.append(ConfidenceFactor(
                "structural link", "neutral",
                "members grouped by blocking key without a scored pairwise link", 0.0))
            return 40.0   # grouped but unscored (e.g. exact block key) — modest base
        strongest = max(links, key=lambda l: l.score)
        base = strongest.percent
        report.positives.append(ConfidenceFactor(
            "strongest correlation", "positive",
            strongest.explanation(), base))
        # record every distinct firing signal as a positive line
        for sig_name in sorted({s.name for l in links for s in l.signals if s.raw > 0}):
            best = max((s for l in links for s in l.signals if s.name == sig_name),
                       key=lambda s: s.raw)
            report.positives.append(ConfidenceFactor(
                f"signal:{sig_name}", "positive",
                f"raw={best.raw:.2f}", best.contribution))
        return base

    def _corroboration(self, cluster: Cluster, report: ConfidenceReport) -> float:
        providers = set()
        for m in cluster.members:
            providers |= m.providers
        distinct_signals = {s.name for l in cluster.links for s in l.signals if s.raw > 0}
        bonus = (max(0, len(providers) - 1) * CORROBORATION_PER_PROVIDER +
                 max(0, len(distinct_signals) - 1) * CORROBORATION_PER_SIGNAL)
        bonus = min(bonus, CORROBORATION_CAP)
        if bonus > 0:
            report.positives.append(ConfidenceFactor(
                "corroboration", "positive",
                f"{len(providers)} providers, {len(distinct_signals)} signal types",
                bonus))
        return bonus

    def _hard_bonus(self, links: List[SimilarityResult],
                    report: ConfidenceReport) -> float:
        if any(l.hard_match for l in links):
            report.positives.append(ConfidenceFactor(
                "hard identifier", "positive",
                "an exact hard identifier (email/cert/wallet/avatar) matched",
                HARD_MATCH_BONUS))
            return HARD_MATCH_BONUS
        return 0.0

    def _conflicts(self, members: List[Entity]) -> Tuple[float, List[str]]:
        conflicts: List[str] = []
        for key in _SINGULAR_KEYS:
            values = {str(m.metadata[key]).strip().lower()
                      for m in members if m.metadata.get(key)}
            if len(values) > 1:
                conflicts.append(f"{key}: {sorted(values)}")
        # explicit contradicting evidence recorded on any member
        for m in members:
            for ev in m.evidence:
                if ev.weight < 0:
                    conflicts.append(f"{ev.kind}: {ev.value or ev.note}")
        return len(conflicts) * self.conflict_penalty, conflicts

    @staticmethod
    def _band(score: float) -> str:
        for floor, name in BANDS:
            if score >= floor:
                return name
        return "insufficient"

    def _narrate(self, cluster: Cluster, report: ConfidenceReport,
                 base: float, corroboration: float, hard: float,
                 penalty: float) -> str:
        types = ", ".join(cluster.types)
        lead = (f"{cluster.size} records ({types}) were correlated into one "
                f"candidate identity with {report.band} confidence "
                f"({report.score:.0f}/100). ")
        drivers = []
        if base:
            drivers.append(f"the strongest single correlation scored {base:.0f}%")
        if hard:
            drivers.append("an exact hard identifier matched")
        if corroboration:
            drivers.append(f"corroboration across independent providers added "
                           f"{corroboration:.0f} points")
        body = ("Supporting: " + "; ".join(drivers) + ". ") if drivers else ""
        if report.conflicts:
            body += ("Against: contradicting evidence was found — "
                     + "; ".join(report.conflicts)
                     + f" — reducing the score by {penalty:.0f} points. ")
        tail = ("This is a machine-generated correlation for authorized "
                "investigation; treat it as a lead requiring analyst review, "
                "not a proven identity.")
        return lead + body + tail
