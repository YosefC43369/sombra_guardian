"""
geo_osint.infrastructure.submarine_cable_engine — public submarine-cable refs (spec §36).

Submarine-cable systems, their operators (consortia) and their landing countries
are public knowledge (TeleGeography's public map, operator press releases). This
engine ships a small curated seed of well-known systems — names, operating
consortia and landing countries — and can be extended at runtime from any public
cable dataset. Landing *coordinates* are attached only for landing cities present
in the gazetteer as real coastal points; where an exact landing station is not
verifiable, the landing is recorded with its country and no coordinate rather than
an invented one (spec: never invent coordinates).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ..data import cities as _cities
from ..models.coordinate import Coordinate
from ..models.infrastructure import CableLanding, SubmarineCable

# Real coastal landing cities present in / addable to the gazetteer, with public
# coordinates, used to place landings we can verify.
_LANDING_COORDS: Dict[str, Coordinate] = {
    "Marseille": Coordinate(43.30, 5.37, precision=2, source="landing-city"),
    "Singapore": Coordinate(1.35, 103.82, precision=2, source="landing-city"),
    "Mumbai": Coordinate(19.08, 72.88, precision=2, source="landing-city"),
    "Alexandria": Coordinate(31.20, 29.92, precision=2, source="landing-city"),
    "Hong Kong": Coordinate(22.32, 114.17, precision=2, source="landing-city"),
    "Fortaleza": Coordinate(-3.73, -38.52, precision=2, source="landing-city"),
    "Bilbao": Coordinate(43.26, -2.93, precision=2, source="landing-city"),
    "Virginia Beach": Coordinate(36.85, -75.98, precision=2, source="landing-city"),
    "Sydney": Coordinate(-33.87, 151.21, precision=2, source="landing-city"),
}

# (name, operators, [(station, country_code)], rfs)
_SEED = [
    ("AAE-1 (Asia-Africa-Europe-1)",
     ["AAE-1 Consortium"],
     [("Hong Kong", "HK"), ("Vung Tau", "VN"), ("Songkhla", "TH"),
      ("Singapore", "SG"), ("Mumbai", "IN"), ("Fujairah", "AE"),
      ("Suez", "EG"), ("Marseille", "FR")], "2017"),
    ("SEA-ME-WE 5",
     ["SEA-ME-WE 5 Consortium"],
     [("Singapore", "SG"), ("Mumbai", "IN"), ("Colombo", "LK"),
      ("Djibouti", "DJ"), ("Alexandria", "EG"), ("Marseille", "FR")], "2016"),
    ("MAREA",
     ["Meta", "Microsoft", "Telxius"],
     [("Virginia Beach", "US"), ("Bilbao", "ES")], "2018"),
    ("Grace Hopper",
     ["Google"],
     [("New York", "US"), ("Bude", "GB"), ("Bilbao", "ES")], "2022"),
    ("Southern Cross NEXT",
     ["Southern Cross Cables"],
     [("Sydney", "AU"), ("Auckland", "NZ"), ("Los Angeles", "US")], "2022"),
]


class SubmarineCableEngine:
    def __init__(self) -> None:
        self._cables: List[SubmarineCable] = []
        self._build_seed()

    def _build_seed(self) -> None:
        for (name, operators, landings, rfs) in _SEED:
            cl = []
            for (station, cc) in landings:
                coord = _LANDING_COORDS.get(station)
                if coord is None:
                    hits = _cities.find(station, cc)
                    coord = hits[0].coordinate if hits else None
                cl.append(CableLanding(station=station, country_code=cc, coordinate=coord))
            self._cables.append(SubmarineCable(
                name=name, operators=list(operators), landings=cl,
                ready_for_service=rfs, source="curated:public-cable-refs",
                source_url="https://www.submarinecablemap.com/"))

    def register(self, cable: SubmarineCable) -> None:
        self._cables.append(cable)

    def all(self) -> List[SubmarineCable]:
        return list(self._cables)

    def by_country(self, country_code: str) -> List[SubmarineCable]:
        cc = (country_code or "").strip().upper()
        return [c for c in self._cables if cc in c.countries]

    def by_operator(self, operator: str) -> List[SubmarineCable]:
        op = (operator or "").strip().lower()
        return [c for c in self._cables
                if any(op in o.lower() for o in c.operators)]

    def landings_in_country(self, country_code: str) -> List[CableLanding]:
        cc = (country_code or "").strip().upper()
        out: List[CableLanding] = []
        for cable in self._cables:
            out.extend(l for l in cable.landings if l.country_code == cc)
        return out

    def to_feature_collection(self) -> Dict[str, object]:
        feats = [c.to_geojson_feature() for c in self._cables]
        return {"type": "FeatureCollection",
                "features": [f for f in feats if f is not None]}
