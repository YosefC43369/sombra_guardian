"""
behavioral_intelligence.content.entity_extractor — named-entity and identifier
extraction from public text.

Regex-based, dependency-free extraction of the artefacts a behavioural
investigation cares about: URLs, emails, @handles, #hashtags, IPv4/IPv6, crypto
wallet addresses, and candidate proper-noun phrases (runs of capitalised words).
These feed the interaction graph, IOC correlation and topic layers. Extraction is
descriptive — it records what strings appear, not who anyone is.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from ..models.observation import Observation

_PATTERNS = {
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "url": re.compile(r"https?://[^\s<>\"')]+"),
    "handle": re.compile(r"(?<!\w)@([A-Za-z0-9_.]{2,30})"),
    "hashtag": re.compile(r"(?<!\w)#([\w฀-๿]{2,50})"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ipv6": re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"),
    "btc": re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b"),
    "eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    # proper-noun phrase: 1-4 capitalised words (Latin)
    "proper_noun": re.compile(r"\b(?:[A-Z][a-z]{2,}(?:\s+|$)){1,4}"),
}

# Very common sentence-initial words that create false proper-noun hits.
_PN_STOP = {"The", "This", "That", "These", "Those", "There", "Here", "When",
            "What", "Where", "Who", "Why", "How", "And", "But", "For", "With"}


@dataclass
class ExtractionResult:
    by_category: Dict[str, List[str]] = field(default_factory=dict)
    frequencies: Dict[str, Dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {"by_category": self.by_category, "frequencies": self.frequencies}


def _valid_ipv4(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def extract_from_text(text: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    if not text:
        return out
    for cat, pat in _PATTERNS.items():
        found = pat.findall(text)
        vals: List[str] = []
        for m in found:
            v = (m if isinstance(m, str) else m[0]).strip()
            if not v:
                continue
            if cat == "ipv4" and not _valid_ipv4(v):
                continue
            if cat == "proper_noun":
                v = v.strip()
                if v.split()[0] in _PN_STOP or len(v) < 3:
                    continue
            vals.append(v)
        if vals:
            out[cat] = vals
    return out


def extract_entities(observations: Sequence[Observation], *, top_n: int = 50
                     ) -> ExtractionResult:
    freqs: Dict[str, Counter] = {cat: Counter() for cat in _PATTERNS}
    for o in observations:
        for cat, vals in extract_from_text(o.text).items():
            for v in vals:
                freqs[cat][v] += 1
    result = ExtractionResult()
    for cat, counter in freqs.items():
        top = counter.most_common(top_n)
        if top:
            result.by_category[cat] = [t for t, _ in top]
            result.frequencies[cat] = dict(top)
    return result
