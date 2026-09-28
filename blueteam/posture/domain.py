"""
blueteam/posture/domain.py — the Security Posture scoring core (pure; stdlib only).

Score is transparent and defensible:

    score = Σ(w · s · c) / Σ(w · c)          (0..1, then ×100)

where for each control ``w`` is its weight, ``s`` its measured sub-score in [0,1],
and ``c`` its coverage (1 if we have a signal, 0 if UNKNOWN). **UNKNOWN controls
are excluded from BOTH numerator and denominator** — an unmeasured control neither
helps nor hurts, and is reported separately as a coverage gap. The function is:

  * **deterministic**: same inputs -> same output, no wall-clock, no dict-order
    dependence (controls sorted by id);
  * **monotonic**: improving any control's status never lowers the score (weights
    are non-negative and s is monotonic in status) — enforced by a test;
  * **gated**: a failed *critical* control caps the letter grade (a great average
    can't hide a broken must-have), applied transparently and reported.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# status -> sub-score s in [0,1]; UNKNOWN is coverage 0 (excluded)
STATUS_SCORE = {"pass": 1.0, "strong": 1.0, "partial": 0.5, "weak": 0.25,
                "fail": 0.0, "unknown": None}
STATUS_ORDER = {"fail": 0, "weak": 1, "partial": 2, "strong": 3, "pass": 4, "unknown": -1}


class Grade(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


@dataclass(frozen=True)
class Control:
    id: str
    name: str
    category: str
    weight: float = 1.0
    critical: bool = False          # a fail here gates the grade
    description: str = ""
    remediation: str = ""
    applies: bool = True

    def gate_cap(self) -> Optional[Grade]:
        return Grade.C if self.critical else None


@dataclass(frozen=True)
class Assessment:
    control_id: str
    status: str = "unknown"         # pass|strong|partial|weak|fail|unknown
    note: str = ""

    def score(self) -> Optional[float]:
        return STATUS_SCORE.get(self.status, None)

    @property
    def covered(self) -> bool:
        return self.score() is not None


@dataclass
class ScoreResult:
    score: float                    # 0..100
    grade: Grade
    raw_score: float                # 0..100 before gating
    coverage: float                 # fraction of applicable controls with a signal
    covered: int
    applicable: int
    gates: List[str] = field(default_factory=list)   # control ids that capped the grade
    contributions: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"score": round(self.score, 2), "grade": self.grade.value,
                "raw_score": round(self.raw_score, 2), "coverage": round(self.coverage, 4),
                "covered": self.covered, "applicable": self.applicable,
                "gates": list(self.gates), "contributions": self.contributions}


def letter_grade(score_100: float) -> Grade:
    if score_100 >= 90:
        return Grade.A
    if score_100 >= 80:
        return Grade.B
    if score_100 >= 70:
        return Grade.C
    if score_100 >= 60:
        return Grade.D
    return Grade.F


def _cap(grade: Grade, cap: Grade) -> Grade:
    order = [Grade.A, Grade.B, Grade.C, Grade.D, Grade.F]
    return grade if order.index(grade) >= order.index(cap) else cap


def compute_score(controls: Dict[str, Control],
                  assessments: Dict[str, Assessment]) -> ScoreResult:
    """Deterministic posture score. ``controls`` is the catalog; ``assessments`` maps
    control_id -> current status (missing -> UNKNOWN)."""
    num = 0.0
    den = 0.0
    applicable = 0
    covered = 0
    contributions: List[Dict[str, Any]] = []
    gates: List[str] = []
    grade_cap: Optional[Grade] = None

    for cid in sorted(controls):                    # sorted -> order-independent
        ctrl = controls[cid]
        if not ctrl.applies:
            continue
        applicable += 1
        a = assessments.get(cid, Assessment(cid, "unknown"))
        s = a.score()
        w = max(0.0, ctrl.weight)
        if s is None:
            contributions.append({"control": cid, "name": ctrl.name, "status": "unknown",
                                   "weight": w, "sub_score": None, "points": 0.0,
                                   "covered": False, "critical": ctrl.critical})
            continue
        covered += 1
        num += w * s
        den += w
        if ctrl.critical and s <= STATUS_SCORE["fail"]:
            cap = ctrl.gate_cap()
            if cap is not None:
                gates.append(cid)
                grade_cap = cap if grade_cap is None else _cap(grade_cap, cap)
        contributions.append({"control": cid, "name": ctrl.name, "status": a.status,
                              "weight": w, "sub_score": s, "points": round(w * s, 4),
                              "covered": True, "critical": ctrl.critical})

    raw = (num / den * 100.0) if den > 0 else 0.0
    grade = letter_grade(raw)
    if grade_cap is not None:
        grade = _cap(grade, grade_cap)
    coverage = (covered / applicable) if applicable else 0.0
    return ScoreResult(score=raw, grade=grade, raw_score=raw, coverage=coverage,
                       covered=covered, applicable=applicable, gates=gates,
                       contributions=contributions)


def explain(controls: Dict[str, Control], assessments: Dict[str, Assessment],
            top: int = 8) -> Dict[str, Any]:
    """Rank the biggest score *drags*: for each covered-or-unknown control, the
    points it would gain if lifted to 'pass', normalized by the covered weight."""
    res = compute_score(controls, assessments)
    den = sum(max(0.0, controls[c].weight) for c in controls
              if controls[c].applies and assessments.get(c, Assessment(c)).covered)
    den = den or 1.0
    drags = []
    for cid in sorted(controls):
        ctrl = controls[cid]
        if not ctrl.applies:
            continue
        a = assessments.get(cid, Assessment(cid, "unknown"))
        cur = a.score() or 0.0
        gain_points = max(0.0, ctrl.weight) * (1.0 - cur)
        if a.status == "unknown":
            reason = "ยังไม่มีข้อมูล (coverage gap)"
        elif gain_points <= 0:
            continue
        else:
            reason = f"อยู่ที่ {a.status}"
        drags.append({"control": cid, "name": ctrl.name, "status": a.status,
                      "potential_gain": round(gain_points / den * 100.0, 2),
                      "critical": ctrl.critical, "reason": reason,
                      "remediation": ctrl.remediation})
    drags.sort(key=lambda d: (-d["potential_gain"], not d["critical"], d["control"]))
    return {"current": res.to_dict(), "top_actions": drags[:top]}


def whatif(controls: Dict[str, Control], assessments: Dict[str, Assessment],
           changes: Dict[str, str]) -> Dict[str, Any]:
    """Recompute the score if the given controls moved to the given statuses."""
    merged = dict(assessments)
    for cid, status in changes.items():
        if cid in controls and status in STATUS_SCORE:
            merged[cid] = Assessment(cid, status)
    before = compute_score(controls, assessments)
    after = compute_score(controls, merged)
    return {"before": before.to_dict(), "after": after.to_dict(),
            "delta": round(after.score - before.score, 2),
            "grade_change": f"{before.grade.value}->{after.grade.value}",
            "changes": changes}


def load_catalog(entries: List[Dict[str, Any]]) -> Dict[str, Control]:
    out: Dict[str, Control] = {}
    for e in entries:
        try:
            c = Control(id=e["id"], name=e["name"], category=e.get("category", "general"),
                        weight=float(e.get("weight", 1.0)), critical=bool(e.get("critical", False)),
                        description=e.get("description", ""), remediation=e.get("remediation", ""),
                        applies=bool(e.get("applies", True)))
        except (KeyError, TypeError, ValueError):
            continue
        out[c.id] = c
    return out


__all__ = ["Control", "Assessment", "ScoreResult", "Grade", "compute_score",
           "explain", "whatif", "letter_grade", "load_catalog",
           "STATUS_SCORE", "STATUS_ORDER"]
