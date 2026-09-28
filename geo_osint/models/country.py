"""
geo_osint.models.country — the country metadata record (spec §15).

A :class:`Country` carries the stable public facts about a sovereign/territory:
ISO codes, capital, continent, currency, calling code, languages, a coarse
population figure, neighbouring countries and a representative point. The actual
data is a small, curated, verifiable public-domain table in
``geo_osint.data.countries`` — never invented at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .coordinate import Coordinate


@dataclass
class Country:
    """Public country metadata."""

    iso2: str
    iso3: str = ""
    name: str = ""
    official_name: str = ""
    capital: str = ""
    continent: str = ""
    region: str = ""
    currency_code: str = ""
    currency_name: str = ""
    calling_code: str = ""
    tld: str = ""
    languages: List[str] = field(default_factory=list)
    timezones: List[str] = field(default_factory=list)
    population: Optional[int] = None
    area_km2: Optional[float] = None
    neighbors: List[str] = field(default_factory=list)      # ISO2 codes
    centroid: Optional[Coordinate] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.iso2 = (self.iso2 or "").strip().upper()[:2]
        self.iso3 = (self.iso3 or "").strip().upper()[:3]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "iso2": self.iso2, "iso3": self.iso3, "name": self.name,
            "official_name": self.official_name, "capital": self.capital,
            "continent": self.continent, "region": self.region,
            "currency_code": self.currency_code, "currency_name": self.currency_name,
            "calling_code": self.calling_code, "tld": self.tld,
            "languages": list(self.languages), "timezones": list(self.timezones),
            "population": self.population, "area_km2": self.area_km2,
            "neighbors": list(self.neighbors),
            "centroid": self.centroid.to_dict() if self.centroid else None,
            "metadata": dict(self.metadata),
        }
