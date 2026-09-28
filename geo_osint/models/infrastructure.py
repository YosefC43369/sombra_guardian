"""
geo_osint.models.infrastructure — public infrastructure records (spec §9–13, §36–40).

One flexible :class:`Facility` type covers the physical-infrastructure categories
the engine inventories from *public* datasets — data centres, cloud regions,
internet exchanges, submarine-cable landing stations, government buildings,
hospitals, universities, power stations, telecom exchanges, technology parks.
A handful of thin specialisations (:class:`DataCenter`, :class:`CloudRegion`,
:class:`SubmarineCable`, :class:`InternetExchange`) add the few fields their
engines need, all serialising back to the common :class:`Facility` shape.

SCOPE: public metadata only (spec §10 "never infer sensitive internal layouts",
§38 "no private infrastructure discovery"). Every record cites a public source.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .coordinate import Coordinate


class FacilityType(str, Enum):
    DATACENTER = "datacenter"
    CLOUD_REGION = "cloud_region"
    IXP = "ixp"
    SUBMARINE_CABLE_LANDING = "submarine_cable_landing"
    GOVERNMENT = "government"
    HOSPITAL = "hospital"
    UNIVERSITY = "university"
    POWER_STATION = "power_station"
    SUBSTATION = "substation"
    TELECOM_EXCHANGE = "telecom_exchange"
    INDUSTRIAL_PARK = "industrial_park"
    TECHNOLOGY_PARK = "technology_park"
    SEAPORT = "seaport"
    RESEARCH_CENTER = "research_center"
    OTHER = "other"

    @classmethod
    def coerce(cls, raw: Any) -> "FacilityType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.OTHER


@dataclass
class Facility:
    """A public physical-infrastructure site."""

    name: str
    facility_type: FacilityType = FacilityType.OTHER
    coordinate: Optional[Coordinate] = None
    operator: str = ""
    city: str = ""
    country_code: str = ""
    website: str = ""
    asn_refs: List[int] = field(default_factory=list)
    cloud_providers: List[str] = field(default_factory=list)
    identifiers: Dict[str, str] = field(default_factory=dict)   # e.g. {"peeringdb": "12"}
    source: str = ""
    source_url: str = ""
    documents: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.facility_type = FacilityType.coerce(self.facility_type)
        if self.country_code:
            self.country_code = self.country_code.strip().upper()[:2]

    @property
    def has_fix(self) -> bool:
        return self.coordinate is not None and not self.coordinate.is_null_island

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "facility_type": self.facility_type.value,
            "coordinate": self.coordinate.to_dict() if self.coordinate else None,
            "operator": self.operator, "city": self.city,
            "country_code": self.country_code, "website": self.website,
            "asn_refs": list(self.asn_refs),
            "cloud_providers": list(self.cloud_providers),
            "identifiers": dict(self.identifiers), "source": self.source,
            "source_url": self.source_url, "documents": list(self.documents),
            "metadata": dict(self.metadata),
        }

    def to_geojson_feature(self) -> Optional[Dict[str, Any]]:
        if not self.coordinate:
            return None
        return {
            "type": "Feature",
            "geometry": self.coordinate.to_geojson(),
            "properties": {"name": self.name, "type": self.facility_type.value,
                           "operator": self.operator, "city": self.city,
                           "country_code": self.country_code,
                           "source": self.source},
        }


@dataclass
class DataCenter(Facility):
    """A public data-centre record (spec §10)."""

    peering_refs: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.facility_type = FacilityType.DATACENTER
        super().__post_init__()

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d["peering_refs"] = list(self.peering_refs)
        return d


@dataclass
class CloudRegion(Facility):
    """A public cloud region (spec §11)."""

    provider: str = ""
    region_code: str = ""          # e.g. "ap-southeast-1"
    public_endpoints: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.facility_type = FacilityType.CLOUD_REGION
        if self.provider and self.provider not in self.cloud_providers:
            self.cloud_providers.append(self.provider)
        super().__post_init__()

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({"provider": self.provider, "region_code": self.region_code,
                  "public_endpoints": list(self.public_endpoints)})
        return d


@dataclass
class InternetExchange(Facility):
    """A public internet exchange point (spec §37)."""

    peeringdb_id: str = ""
    participants: Optional[int] = None

    def __post_init__(self) -> None:
        self.facility_type = FacilityType.IXP
        super().__post_init__()

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update({"peeringdb_id": self.peeringdb_id,
                  "participants": self.participants})
        return d


@dataclass
class CableLanding:
    """One landing point of a submarine cable."""

    station: str
    country_code: str = ""
    coordinate: Optional[Coordinate] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"station": self.station, "country_code": self.country_code,
                "coordinate": self.coordinate.to_dict() if self.coordinate else None}


@dataclass
class SubmarineCable:
    """A public submarine-cable record (spec §36)."""

    name: str
    operators: List[str] = field(default_factory=list)
    landings: List[CableLanding] = field(default_factory=list)
    length_km: Optional[float] = None
    ready_for_service: str = ""     # year or date, as published
    source: str = ""
    source_url: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def countries(self) -> List[str]:
        seen: List[str] = []
        for l in self.landings:
            if l.country_code and l.country_code not in seen:
                seen.append(l.country_code)
        return seen

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "operators": list(self.operators),
            "landings": [l.to_dict() for l in self.landings],
            "countries": self.countries, "length_km": self.length_km,
            "ready_for_service": self.ready_for_service, "source": self.source,
            "source_url": self.source_url, "metadata": dict(self.metadata),
        }

    def to_geojson_feature(self) -> Optional[Dict[str, Any]]:
        coords = [[l.coordinate.longitude, l.coordinate.latitude]
                  for l in self.landings if l.coordinate]
        if len(coords) < 2:
            return None
        return {"type": "Feature",
                "geometry": {"type": "LineString", "coordinates": coords},
                "properties": {"name": self.name, "operators": self.operators,
                               "countries": self.countries}}
