"""
geo_osint.models.location — a resolved place with its administrative hierarchy.

Where :class:`~geo_osint.models.observation.GeoObservation` is *one source's*
statement, :class:`ResolvedLocation` is the engine's consolidated view of a place:
a name, an optional coordinate, the administrative chain (country -> region ->
district -> city), a timezone, and the set of alternate names (multilingual and
historical) by which the place is known. The geocoder and reverse geocoder both
return this type.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .coordinate import Coordinate


@dataclass
class AdministrativeLevel:
    """One rung of the admin hierarchy (level 0 = country)."""

    level: int
    name: str
    code: str = ""
    type: str = ""            # e.g. "province", "state", "district", "municipality"

    def to_dict(self) -> Dict[str, Any]:
        return {"level": self.level, "name": self.name,
                "code": self.code, "type": self.type}


@dataclass
class ResolvedLocation:
    """A place resolved to a name, hierarchy, and (optionally) a coordinate."""

    name: str
    coordinate: Optional[Coordinate] = None
    country_code: str = ""
    country_name: str = ""
    region: str = ""
    district: str = ""
    city: str = ""
    postal_code: str = ""
    timezone: str = ""
    feature_class: str = ""       # GeoNames-style class, e.g. "P" (populated place)
    feature_code: str = ""        # e.g. "PPLC" (capital)
    population: Optional[int] = None
    admin_levels: List[AdministrativeLevel] = field(default_factory=list)
    alternate_names: List[str] = field(default_factory=list)
    source: str = ""
    source_url: str = ""
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.country_code:
            self.country_code = self.country_code.strip().upper()[:2]
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    @property
    def display_name(self) -> str:
        parts = [p for p in (self.city or self.name, self.region,
                             self.country_name or self.country_code) if p]
        # avoid "Bangkok, Bangkok" style duplication
        deduped: List[str] = []
        for p in parts:
            if p and (not deduped or deduped[-1].lower() != p.lower()):
                deduped.append(p)
        return ", ".join(deduped)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "coordinate": self.coordinate.to_dict() if self.coordinate else None,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "region": self.region,
            "district": self.district,
            "city": self.city,
            "postal_code": self.postal_code,
            "timezone": self.timezone,
            "feature_class": self.feature_class,
            "feature_code": self.feature_code,
            "population": self.population,
            "admin_levels": [a.to_dict() for a in self.admin_levels],
            "alternate_names": list(self.alternate_names),
            "source": self.source,
            "source_url": self.source_url,
            "confidence": round(self.confidence, 4),
            "metadata": dict(self.metadata),
        }

    def to_geojson_feature(self) -> Optional[Dict[str, Any]]:
        if not self.coordinate:
            return None
        return {
            "type": "Feature",
            "geometry": self.coordinate.to_geojson(),
            "properties": {k: v for k, v in self.to_dict().items()
                           if k != "coordinate"},
        }
