"""
news_intelligence.extraction.actor_extractor — threat actor name mining.

Two-track extraction:
  1. dictionary track — matches publicly-documented actor names and aliases from
     ``reference.ACTOR_ALIAS_CLUSTERS`` (APT29, Cozy Bear, Volt Typhoon, …). The
     canonical name is recorded in ``detail['canonical']`` and every *reported*
     alias is preserved as its own mention (vendor aliases are never merged into
     one identity by extraction).
  2. pattern track — high-precision structured designators: APT##, UNC####, TA###,
     FIN#, TEMP.*, DEV-####, and capitalized codenames adjacent to cue words
     ("… group", "… campaign", "… gang").

Precision over recall: a false actor name is worse than a missed one.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..models.entity import EntityMention, EntityType, normalize_value
from .base import BaseExtractor, _mk
from .reference import build_actor_index, actor_aliases_for

_DESIGNATOR_RE = re.compile(
    r"\b(APT\s?\d{1,4}|UNC\s?\d{2,5}|TA\d{2,4}|FIN\d{1,2}|TEMP\.[A-Za-z]+|"
    r"DEV-\d{3,5}|G\d{4})\b")
_CUE = r"(group|campaign|gang|actor|operation|crew|collective|threat group)"
_CODENAME_RE = re.compile(
    r"\b([A-Z][a-z]+(?:\s[A-Z][a-z]+){0,2})\s+" + _CUE + r"\b")
_STOP = {"The", "This", "A", "An", "These", "Those", "Our", "Their", "New",
         "Advanced", "Persistent", "Threat"}


class ActorExtractor(BaseExtractor):
    name = "actor"
    entity_types = [EntityType.THREAT_ACTOR]

    def __init__(self) -> None:
        self._index: Dict[str, str] = build_actor_index()

    def extract(self, text: str, *, article: Optional[Any] = None
                ) -> List[EntityMention]:
        text = text or ""
        out: List[EntityMention] = []
        seen_spans: List[tuple] = []

        # 1. dictionary track — match every reported name/alias in the clusters
        lowered = text.lower()
        for reported_lc, canonical in self._index.items():
            start = 0
            while True:
                pos = lowered.find(reported_lc, start)
                if pos < 0:
                    break
                # word-boundary guard
                before = text[pos - 1] if pos > 0 else " "
                after = (text[pos + len(reported_lc)]
                         if pos + len(reported_lc) < len(text) else " ")
                if (not before.isalnum()) and (not after.isalnum()):
                    surface = text[pos:pos + len(reported_lc)]
                    out.append(_mk(
                        EntityType.THREAT_ACTOR,
                        normalize_value(EntityType.THREAT_ACTOR, surface),
                        surface=surface, extractor=self.name + ":dict",
                        weight=0.9, text=text, span=(pos, pos + len(reported_lc)),
                        detail={"canonical": canonical,
                                "reported_as": surface,
                                "cluster_aliases": actor_aliases_for(canonical)}))
                    seen_spans.append((pos, pos + len(reported_lc)))
                start = pos + len(reported_lc)

        # 2. pattern track — structured designators
        for m in _DESIGNATOR_RE.finditer(text):
            if self._overlaps(m.span(), seen_spans):
                continue
            val = normalize_value(EntityType.THREAT_ACTOR, m.group(1))
            out.append(_mk(EntityType.THREAT_ACTOR, val, surface=m.group(1),
                           extractor=self.name + ":designator", weight=0.88,
                           text=text, span=m.span(),
                           detail={"canonical": self._index.get(val.lower(), val)}))
            seen_spans.append(m.span())

        # 3. codenames adjacent to cue words
        for m in _CODENAME_RE.finditer(text):
            cand = m.group(1).strip()
            if cand.split()[0] in _STOP or self._overlaps(m.span(1), seen_spans):
                continue
            val = normalize_value(EntityType.THREAT_ACTOR, cand)
            out.append(_mk(EntityType.THREAT_ACTOR, val, surface=cand,
                           extractor=self.name + ":codename", weight=0.62,
                           text=text, span=m.span(1),
                           detail={"canonical": self._index.get(val.lower(), val),
                                   "cue": m.group(2)}))
        return out

    @staticmethod
    def _overlaps(span, spans) -> bool:
        s, e = span
        return any(not (e <= a or s >= b) for a, b in spans)


__all__ = ["ActorExtractor"]
