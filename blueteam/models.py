"""
blueteam/models.py — the explainable-scoring value objects shared by every
Blue Team module (Link Guard, Scam/Impersonation, Join Guard).

ปรัชญาหลัก (กติกาข้อ 11): แยก "ข้อเท็จจริง" ออกจาก "การวิเคราะห์" เสมอ
------------------------------------------------------------------------
A score here is a *triage ordering tool*, never proof of guilt. Every point of a
score is attributable to a concrete :class:`Signal` that names the fact it saw,
why it matters, its weight, and (optionally) a MITRE ATT&CK technique tag for
Purple Team coverage. An :class:`Assessment` is therefore always explainable:
``top_reasons()`` lists the signals that drove the verdict, and every assessment
carries a ``limitation`` line stating what the score does *not* prove.

Design notes
------------
* ``dataclass(slots=True)`` throughout — these are created on the hot path
  (one per analysed message) so we keep them small and allocation-cheap.
* Scoring is **deterministic and monotonic**: adding a signal (or increasing a
  signal's weight) can never lower the score. The combiner is a saturating sum
  capped at 100, which the test-suite asserts. This keeps the model trivial to
  reason about and impossible to game into a *lower* score by piling on more
  evidence.
* Pure stdlib, no I/O, no Telegram — unit-testable in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple

__all__ = ["Verdict", "Signal", "Assessment", "PolicyAction", "combine_score"]


class Verdict(IntEnum):
    """Severity band derived from a 0–100 score. Ordered so comparisons work
    (``verdict >= Verdict.HIGH``). Thresholds are the defaults; a module may pass
    its own via :meth:`from_score`."""

    SAFE = 0          # 0–19   : nothing notable
    LOW = 1           # 20–44  : minor signals, monitor
    SUSPICIOUS = 2    # 45–69  : worth an admin's eyes
    HIGH = 3          # 70–89  : likely malicious/scam
    CRITICAL = 4      # 90–100 : very high confidence

    @classmethod
    def from_score(cls, score: int,
                   thresholds: Tuple[int, int, int, int] = (20, 45, 70, 90)) -> "Verdict":
        low, sus, high, crit = thresholds
        if score >= crit:
            return cls.CRITICAL
        if score >= high:
            return cls.HIGH
        if score >= sus:
            return cls.SUSPICIOUS
        if score >= low:
            return cls.LOW
        return cls.SAFE

    @property
    def label_th(self) -> str:
        return {
            Verdict.SAFE: "ปลอดภัย",
            Verdict.LOW: "เฝ้าระวังต่ำ",
            Verdict.SUSPICIOUS: "น่าสงสัย",
            Verdict.HIGH: "เสี่ยงสูง",
            Verdict.CRITICAL: "อันตรายมาก",
        }[self]

    @property
    def emoji(self) -> str:
        return {Verdict.SAFE: "🟢", Verdict.LOW: "🟡", Verdict.SUSPICIOUS: "🟠",
                Verdict.HIGH: "🔴", Verdict.CRITICAL: "⛔"}[self]


class PolicyAction(IntEnum):
    """What a per-group policy decides to *do* with an assessment. Ordered from
    least to most intrusive so a threshold comparison is meaningful."""

    OFF = 0
    MONITOR = 1        # record only, no visible action
    WARN = 2           # warn (and record)
    DELETE = 3         # delete the message (and record)
    DELETE_RESTRICT = 4  # delete + restrict the sender

    @classmethod
    def parse(cls, value: Any) -> "PolicyAction":
        if isinstance(value, cls):
            return value
        try:
            return cls[str(value).strip().upper().replace("+", "_").replace("-", "_")]
        except KeyError:
            return cls.MONITOR


@dataclass(slots=True)
class Signal:
    """One explainable contribution to a score.

    ``fact`` is the observed truth (e.g. "href โดเมน paypa1.com ต่างจากข้อความ
    paypal.com"); ``weight`` is how many points it adds; ``category`` groups it;
    ``attack`` is an optional ATT&CK technique id (e.g. "T1566.002"). Keeping the
    fact separate from the interpretation is the core honesty rule.
    """

    id: str
    weight: int
    category: str
    fact: str = ""
    attack: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = {"id": self.id, "weight": self.weight, "category": self.category,
             "fact": self.fact}
        if self.attack:
            d["attack"] = self.attack
        if self.meta:
            d["meta"] = dict(self.meta)
        return d


def combine_score(signals: List[Signal]) -> int:
    """Deterministic, monotonic combiner: saturating sum capped at 100.

    Monotonic by construction — adding a signal or raising a weight never lowers
    the result — which is exactly the property the score's role (triage ordering,
    not proof) requires and the test-suite asserts. Negative weights are clamped
    to 0 so an "allow" hint can never be abused to mask real signals here (allow
    decisions are made by policy/allow-lists upstream, not by negative points).
    """
    total = 0
    for s in signals:
        w = s.weight
        if w > 0:
            total += w
    return 100 if total >= 100 else total


@dataclass(slots=True)
class Assessment:
    """The result of analysing one subject (a URL, a message, a join event).

    Always explainable: :meth:`top_reasons` returns the highest-weight signals,
    and :attr:`limitation` states what the score does not prove. ``subject`` is a
    short, non-sensitive identifier (a URL key hash, a user id, a campaign id) —
    never raw message content.
    """

    module: str                       # "linkguard" | "scamguard" | "joinguard" | ...
    subject: str = ""
    signals: List[Signal] = field(default_factory=list)
    score: int = -1                   # -1 => derive from signals
    thresholds: Tuple[int, int, int, int] = (20, 45, 70, 90)
    limitation: str = (
        "คะแนนนี้เป็นเครื่องมือจัดลำดับการตรวจสอบ ไม่ใช่ข้อพิสูจน์ความผิด "
        "การลงโทษถาวรต้องมีมนุษย์ยืนยัน")
    meta: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.score is None or self.score < 0:
            self.score = combine_score(self.signals)
        else:
            self.score = max(0, min(100, int(self.score)))

    def add(self, signal: Optional[Signal]) -> "Assessment":
        """Add a signal and recompute the score (keeps monotonicity)."""
        if signal is not None:
            self.signals.append(signal)
            self.score = combine_score(self.signals)
        return self

    @property
    def verdict(self) -> Verdict:
        return Verdict.from_score(self.score, self.thresholds)

    @property
    def attack_tags(self) -> List[str]:
        seen: List[str] = []
        for s in self.signals:
            if s.attack and s.attack not in seen:
                seen.append(s.attack)
        return seen

    def top_reasons(self, n: int = 3) -> List[Signal]:
        return sorted(self.signals, key=lambda s: s.weight, reverse=True)[:n]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "subject": self.subject,
            "score": self.score,
            "verdict": self.verdict.name,
            "verdict_th": self.verdict.label_th,
            "attack_tags": self.attack_tags,
            "signals": [s.to_dict() for s in self.signals],
            "top_reasons": [s.to_dict() for s in self.top_reasons()],
            "limitation": self.limitation,
            "meta": dict(self.meta),
        }
