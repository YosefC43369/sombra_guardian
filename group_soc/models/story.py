"""
group_soc/models/story.py — a Security Story.

A story turns a timeline into something a human reads quickly, with the four
registers kept strictly separate so analysis is never confused with fact:

  FACTS           what was observed (from events/timeline), no interpretation
  ANALYSIS        what the correlation/detection layer concluded
  HYPOTHESIS      what *might* be happening (explicitly uncertain)
  RECOMMENDATION  suggested next steps for an admin

Confidence is always presented as an analytic signal, never as proof of intent.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class StorySection:
    register: str          # facts|analysis|hypothesis|recommendation
    lines: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Story:
    chat_id: int = 0
    subject: str = ""                 # e.g. "INC-... " or "correlation <id>"
    headline: str = ""
    facts: List[str] = field(default_factory=list)
    analysis: List[str] = field(default_factory=list)
    hypotheses: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    confidence: float = 0.0
    current_state: str = ""
    generated_at: int = 0

    def sections(self) -> List[StorySection]:
        return [
            StorySection("facts", list(self.facts)),
            StorySection("analysis", list(self.analysis)),
            StorySection("hypothesis", list(self.hypotheses)),
            StorySection("recommendation", list(self.recommendations)),
        ]

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)
