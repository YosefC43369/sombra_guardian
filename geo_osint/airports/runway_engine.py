"""
geo_osint.airports.runway_engine — runway metadata extraction and analysis.

Runway data, when present in the underlying database record (the mwgg schema and
OurAirports both publish a ``runways`` array), is parsed into typed
:class:`~geo_osint.models.airport.Runway` objects and summarised: longest runway,
paved vs unpaved, lighting. When the record carries no runway array the engine
reports that honestly (empty) rather than inventing dimensions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..models.airport import Airport, Runway

_PAVED = {"asp", "asphalt", "con", "concrete", "pem", "paved", "bit", "bituminous"}


@dataclass
class RunwaySummary:
    count: int
    longest_ft: Optional[int]
    paved: Optional[bool]
    lit: Optional[bool]
    surfaces: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {"count": self.count, "longest_ft": self.longest_ft,
                "paved": self.paved, "lit": self.lit, "surfaces": self.surfaces}


class RunwayEngine:
    def parse(self, airport: Airport) -> List[Runway]:
        if airport.runways:
            return list(airport.runways)
        raw = airport.metadata.get("runways")
        if not isinstance(raw, list):
            return []
        out: List[Runway] = []
        for r in raw:
            if not isinstance(r, dict):
                continue
            out.append(Runway(
                ident=str(r.get("ident", r.get("le_ident", ""))),
                length_ft=_as_int(r.get("length_ft", r.get("length"))),
                width_ft=_as_int(r.get("width_ft", r.get("width"))),
                surface=str(r.get("surface", "")),
                lit=_as_bool(r.get("lighted", r.get("lit"))),
                le_ident=str(r.get("le_ident", "")),
                he_ident=str(r.get("he_ident", "")),
            ))
        return out

    def summarize(self, airport: Airport) -> RunwaySummary:
        runways = self.parse(airport)
        if not runways:
            return RunwaySummary(0, None, None, None, [])
        lengths = [r.length_ft for r in runways if r.length_ft]
        surfaces = sorted({r.surface for r in runways if r.surface})
        paved = None
        if surfaces:
            paved = any(s.lower() in _PAVED for s in surfaces)
        lit_vals = [r.lit for r in runways if r.lit is not None]
        lit = any(lit_vals) if lit_vals else None
        return RunwaySummary(
            count=len(runways),
            longest_ft=max(lengths) if lengths else None,
            paved=paved, lit=lit, surfaces=surfaces,
        )


def _as_int(v: Any) -> Optional[int]:
    try:
        return int(float(v)) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _as_bool(v: Any) -> Optional[bool]:
    if v in (None, ""):
        return None
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "y", "lighted")
