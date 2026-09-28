"""
geo_osint.models.airport — the airport record used across the aviation engines.

This adapts the normalised dict produced by the repository's existing
``airports.py`` (the mwgg/Airports schema: icao/iata/name/city/country/lat/lon/
elevation/tz) into a typed :class:`Airport` with a real :class:`Coordinate`,
distance helpers and GeoJSON export. Geo-OSINT becomes the primary *consumer* of
``airports.py`` (spec §5) without duplicating its streaming/search logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .coordinate import Coordinate


@dataclass
class Runway:
    """One runway's public metadata (length/width/surface where available)."""

    ident: str = ""
    length_ft: Optional[int] = None
    width_ft: Optional[int] = None
    surface: str = ""
    lit: Optional[bool] = None
    le_ident: str = ""
    he_ident: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"ident": self.ident, "length_ft": self.length_ft,
                "width_ft": self.width_ft, "surface": self.surface,
                "lit": self.lit, "le_ident": self.le_ident,
                "he_ident": self.he_ident}


@dataclass
class Airport:
    """A public airport/heliport/seaplane-base record."""

    icao: str = ""
    iata: str = ""
    name: str = ""
    city: str = ""
    state: str = ""
    country: str = ""              # ISO 3166-1 alpha-2 in the mwgg schema
    coordinate: Optional[Coordinate] = None
    elevation_ft: Optional[int] = None
    timezone: str = ""
    kind: str = "airport"         # airport | heliport | seaplane_base | closed
    runways: List[Runway] = field(default_factory=list)
    website: str = ""
    wikidata_id: str = ""
    source: str = "airports.json"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.icao = (self.icao or "").strip().upper()
        self.iata = (self.iata or "").strip().upper()
        self.country = (self.country or "").strip().upper()

    @property
    def code(self) -> str:
        return self.iata or self.icao or ""

    @property
    def has_fix(self) -> bool:
        return self.coordinate is not None and not self.coordinate.is_null_island

    def distance_km(self, other: "Airport") -> Optional[float]:
        if self.coordinate and other.coordinate:
            return round(self.coordinate.distance_km(other.coordinate), 3)
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "icao": self.icao, "iata": self.iata, "code": self.code,
            "name": self.name, "city": self.city, "state": self.state,
            "country": self.country,
            "coordinate": self.coordinate.to_dict() if self.coordinate else None,
            "elevation_ft": self.elevation_ft, "timezone": self.timezone,
            "kind": self.kind, "website": self.website,
            "wikidata_id": self.wikidata_id, "source": self.source,
            "runways": [r.to_dict() for r in self.runways],
            "metadata": dict(self.metadata),
        }

    def to_geojson_feature(self) -> Optional[Dict[str, Any]]:
        if not self.coordinate:
            return None
        return {
            "type": "Feature",
            "geometry": self.coordinate.to_geojson(),
            "properties": {
                "icao": self.icao, "iata": self.iata, "name": self.name,
                "city": self.city, "country": self.country, "kind": self.kind,
                "elevation_ft": self.elevation_ft, "timezone": self.timezone,
            },
        }

    @classmethod
    def from_normalized(cls, rec: Dict[str, Any]) -> "Airport":
        """Build from the dict shape ``airports.py`` yields.

        The normalised record uses keys icao/iata/name/city/country/state and,
        in the mwgg schema, ``lat``/``lon``/``elevation``/``tz``. Missing or
        junk coordinates are dropped rather than coerced to (0, 0).
        """
        coord: Optional[Coordinate] = None
        lat = rec.get("lat", rec.get("latitude"))
        lon = rec.get("lon", rec.get("longitude"))
        try:
            if lat is not None and lon is not None:
                flat, flon = float(lat), float(lon)
                if not (flat == 0.0 and flon == 0.0):
                    coord = Coordinate(flat, flon, source="airports.json")
        except (TypeError, ValueError):
            coord = None
        elev = rec.get("elevation", rec.get("elevation_ft"))
        try:
            elev = int(elev) if elev not in (None, "") else None
        except (TypeError, ValueError):
            elev = None
        return cls(
            icao=str(rec.get("icao", "")),
            iata=str(rec.get("iata", "")),
            name=str(rec.get("name", "")),
            city=str(rec.get("city", "")),
            state=str(rec.get("state", "")),
            country=str(rec.get("country", "")),
            coordinate=coord,
            elevation_ft=elev,
            timezone=str(rec.get("tz", rec.get("timezone", ""))),
            metadata={k: v for k, v in rec.items()
                      if k not in {"icao", "iata", "name", "city", "state",
                                   "country", "lat", "lon", "elevation", "tz"}},
        )
