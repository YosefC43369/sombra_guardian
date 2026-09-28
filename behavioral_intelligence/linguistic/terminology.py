"""
behavioral_intelligence.linguistic.terminology — specialised terminology and
identifier extraction from public text.

Complements the keyword engine by surfacing the *technical* vocabulary an actor
uses in public: acronyms, security identifiers (CVE, CWE), tool/handle-like
tokens, version strings and file/command artefacts. Useful for red-team footprint
mapping (what technologies are discussed) and blue-team enrichment (public IOC
references), while staying purely descriptive.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Set

from ..models.observation import Observation

_PATTERNS = {
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "cwe": re.compile(r"\bCWE-\d{1,4}\b", re.IGNORECASE),
    "acronym": re.compile(r"\b[A-Z]{2,6}\b"),
    "version": re.compile(r"\b\d+\.\d+(?:\.\d+)?\b"),
    "hash": re.compile(r"\b[a-fA-F0-9]{32,64}\b"),
    "path": re.compile(r"(?:/[\w.\-]+){2,}"),
    "handle": re.compile(r"(?<!\w)@[\w.]{2,}"),
    "command": re.compile(r"\b(?:sudo|nmap|curl|wget|ssh|python3?|pip|docker|git)\b",
                          re.IGNORECASE),
}

# Common English all-caps words that are not meaningful acronyms.
_ACRONYM_STOP = {"THE", "AND", "FOR", "YOU", "ARE", "NOT", "ALL", "BUT", "WHY",
                 "HOW", "NEW", "NOW", "GET", "USA", "OK"}


@dataclass
class TerminologyResult:
    categories: Dict[str, List[str]] = field(default_factory=dict)
    frequencies: Dict[str, int] = field(default_factory=dict)
    platforms: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {"categories": self.categories, "frequencies": self.frequencies,
                "platforms": self.platforms}


def extract_terminology(observations: Sequence[Observation], *, top_n: int = 40
                        ) -> TerminologyResult:
    cat_terms: Dict[str, Counter] = {k: Counter() for k in _PATTERNS}
    term_platforms: Dict[str, Set[str]] = defaultdict(set)
    all_freq: Counter = Counter()

    for o in observations:
        text = o.text or ""
        if not text:
            continue
        for cat, pat in _PATTERNS.items():
            for m in pat.findall(text):
                term = m if isinstance(m, str) else m[0]
                term = term.strip()
                if cat == "acronym" and term.upper() in _ACRONYM_STOP:
                    continue
                if not term:
                    continue
                norm = term if cat in ("path", "handle", "command") else term.upper()
                cat_terms[cat][norm] += 1
                all_freq[norm] += 1
                if o.platform:
                    term_platforms[norm].add(o.platform)

    result = TerminologyResult()
    for cat, counter in cat_terms.items():
        top = [t for t, _ in counter.most_common(top_n) if counter[t] >= 1]
        if top:
            result.categories[cat] = top
    result.frequencies = dict(all_freq.most_common(top_n))
    result.platforms = {t: sorted(p) for t, p in term_platforms.items()
                        if t in result.frequencies}
    return result
