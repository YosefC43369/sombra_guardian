"""
news_intelligence.extraction.location_extractor — country / city / geo mining.

Dictionary track over ``reference.COUNTRIES`` (country names + demonyms →
canonical country), plus reuse of the repository's airport/city reference data
(``airports.py``) when importable, to resolve major city names. Emits
``EntityType.COUNTRY`` / ``EntityType.CITY`` mentions that feed the Country
Intelligence Profile and the Geo-OSINT integration.

Demonyms ("Russian", "Chinese") are recorded as country mentions with a
``via_demonym`` flag so a report can distinguish "attack in Russia" from
"Russian-speaking actor" — the engine records both, asserts neither.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from ..models.entity import EntityMention, EntityType
from .base import BaseExtractor, _mk
from .reference import build_country_index, COUNTRIES


def _load_cities() -> Set[str]:
    """Best-effort major-city set from the repo's airports dataset if present."""
    cities: Set[str] = set()
    try:  # pragma: no cover - optional dependency on repo dataset
        import airports  # type: ignore
        data = getattr(airports, "AIRPORTS", None) or getattr(airports, "DATA", None)
        if isinstance(data, dict):
            for v in data.values():
                c = (v.get("city") if isinstance(v, dict) else None)
                if c and len(c) >= 4:
                    cities.add(c)
    except Exception:
        pass
    # a small always-available fallback of security-relevant major cities
    cities |= {"Moscow", "Beijing", "Washington", "London", "Tehran",
               "Pyongyang", "Kyiv", "Tel Aviv", "Berlin", "Paris", "Tokyo",
               "Seoul", "Singapore", "Shanghai", "Amsterdam", "Sydney"}
    return cities


class LocationExtractor(BaseExtractor):
    name = "location"
    entity_types = [EntityType.COUNTRY, EntityType.CITY]

    def __init__(self) -> None:
        self._country_index: Dict[str, str] = build_country_index()
        self._demonyms: Set[str] = set()
        for canonical, demonyms in COUNTRIES.items():
            self._demonyms |= {d.lower() for d in demonyms}
        self._cities: Set[str] = _load_cities()
        self._city_index = {c.lower(): c for c in self._cities}

    def extract(self, text: str, *, article: Optional[Any] = None
                ) -> List[EntityMention]:
        text = text or ""
        out: List[EntityMention] = []
        lowered = text.lower()
        seen_spans: List[tuple] = []

        for name_lc, canonical in self._country_index.items():
            start = 0
            while True:
                pos = lowered.find(name_lc, start)
                if pos < 0:
                    break
                before = text[pos - 1] if pos > 0 else " "
                after = (text[pos + len(name_lc)]
                         if pos + len(name_lc) < len(text) else " ")
                if (not before.isalnum()) and (not after.isalnum()):
                    via_demonym = name_lc in self._demonyms
                    out.append(_mk(EntityType.COUNTRY, canonical,
                                   surface=text[pos:pos + len(name_lc)],
                                   extractor=self.name + ":country",
                                   weight=0.75 if via_demonym else 0.85,
                                   text=text, span=(pos, pos + len(name_lc)),
                                   detail={"via_demonym": via_demonym}))
                    seen_spans.append((pos, pos + len(name_lc)))
                start = pos + len(name_lc)

        for name_lc, display in self._city_index.items():
            pos = lowered.find(name_lc)
            if pos < 0:
                continue
            before = text[pos - 1] if pos > 0 else " "
            after = (text[pos + len(name_lc)]
                     if pos + len(name_lc) < len(text) else " ")
            if (not before.isalnum()) and (not after.isalnum()) and \
                    not self._overlaps((pos, pos + len(name_lc)), seen_spans):
                out.append(_mk(EntityType.CITY, display,
                               surface=text[pos:pos + len(name_lc)],
                               extractor=self.name + ":city", weight=0.6,
                               text=text, span=(pos, pos + len(name_lc))))
        return out

    @staticmethod
    def _overlaps(span, spans) -> bool:
        s, e = span
        return any(not (e <= a or s >= b) for a, b in spans)


__all__ = ["LocationExtractor"]
