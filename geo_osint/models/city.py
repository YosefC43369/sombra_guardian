"""
geo_osint.models.city — a populated-place record (spec, GeoNames-aligned).

A :class:`City` is a populated place with a coordinate, admin context, timezone,
population and its alternate/multilingual names. It is the unit the GeoNames
engine, the place resolver and the alias engine produce and consume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .coordinate import Coordinate


@dataclass
class City:
    """A populated place."""

    name: str
    coordinate: Optional[Coordinate] = None
    country_code: str = ""
    admin1: str = ""            # first-level admin (state/province)
    admin2: str = ""            # second-level (county/district)
    timezone: str = ""
    population: Optional[int] = None
    feature_code: str = ""      # GeoNames: PPL, PPLA, PPLC, ...
    geonames_id: Optional[int] = None
    alternate_names: List[str] = field(default_factory=list)
    source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.country_code:
            self.country_code = self.country_code.strip().upper()[:2]

    @property
    def is_capital(self) -> bool:
        return self.feature_code.upper() == "PPLC"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "coordinate": self.coordinate.to_dict() if self.coordinate else None,
            "country_code": self.country_code, "admin1": self.admin1,
            "admin2": self.admin2, "timezone": self.timezone,
            "population": self.population, "feature_code": self.feature_code,
            "geonames_id": self.geonames_id,
            "alternate_names": list(self.alternate_names),
            "source": self.source, "metadata": dict(self.metadata),
        }

    def to_geojson_feature(self) -> Optional[Dict[str, Any]]:
        if not self.coordinate:
            return None
        return {
            "type": "Feature",
            "geometry": self.coordinate.to_geojson(),
            "properties": {"name": self.name, "country_code": self.country_code,
                           "admin1": self.admin1, "population": self.population,
                           "feature_code": self.feature_code,
                           "timezone": self.timezone},
        }
