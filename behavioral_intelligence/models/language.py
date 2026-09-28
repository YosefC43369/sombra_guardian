"""
behavioral_intelligence.models.language — typed results for linguistic analysis.

Observable language *use* only. The engine reports which languages/scripts appear
in public text and how that mix changes over time; it never infers nationality,
ethnicity or first language (spec §10, §11).
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Tuple


@dataclass
class LanguageDetection:
    """The detection result for a single piece of text."""
    language: str = "und"              # ISO-639-1, or "und" (undetermined)
    script: str = ""                   # dominant Unicode script name
    confidence: float = 0.0
    mixed: bool = False                # more than one script/language present
    scripts: Dict[str, float] = field(default_factory=dict)  # script -> share
    candidates: List[Tuple[str, float]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["confidence"] = round(self.confidence, 3)
        d["scripts"] = {k: round(v, 3) for k, v in self.scripts.items()}
        d["candidates"] = [[c, round(s, 3)] for c, s in self.candidates]
        return d


@dataclass
class LanguageDistribution:
    """Language mix over a window: language -> share (sums ~1.0)."""
    shares: Dict[str, float] = field(default_factory=dict)
    counts: Dict[str, int] = field(default_factory=dict)
    sample_size: int = 0
    period_start: float = 0.0
    period_end: float = 0.0

    def dominant(self) -> str:
        return (max(self.shares, key=lambda k: self.shares[k])
                if self.shares else "und")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "shares": {k: round(v, 3) for k, v in self.shares.items()},
            "counts": self.counts,
            "sample_size": self.sample_size,
            "dominant": self.dominant(),
            "period_start": self.period_start,
            "period_end": self.period_end,
        }


@dataclass
class LanguageTimelinePoint:
    period_label: str = ""
    period_start: float = 0.0
    distribution: Dict[str, float] = field(default_factory=dict)
    sample_size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"period_label": self.period_label,
                "period_start": self.period_start,
                "distribution": {k: round(v, 3) for k, v in self.distribution.items()},
                "sample_size": self.sample_size}


@dataclass
class LanguageSwitch:
    """An observed switch in dominant language between consecutive posts."""
    at: float = 0.0
    from_language: str = ""
    to_language: str = ""
    platform: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TransliterationMatch:
    """A candidate transliteration relationship between two tokens/aliases.
    Supporting evidence only — never identity proof (spec §11)."""
    source_token: str = ""
    latin_form: str = ""
    script: str = ""
    method: str = ""                   # e.g. "romanization_table"
    similarity: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["similarity"] = round(self.similarity, 3)
        return d
