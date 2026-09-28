"""
geo_osint.models.observation — the universal geographic observation schema.

This is the single record type every collector, engine and correlator in the
package emits and consumes (spec §1). One :class:`GeoObservation` says: *at this
time, this public source placed this entity at (or near) this point, with this
much precision and this much confidence, and here is the evidence.*

The field set is fixed by the specification. Two rules are enforced in code:

  * **Coordinates are never invented.** ``coordinate`` may be ``None`` (a place
    can be named without a fix), but when present it carries its own
    ``precision``. A collector that only knows "Thailand" sets
    ``country_code="TH"`` and leaves ``coordinate`` unset rather than dropping a
    guessed centroid in and pretending it is a fix.
  * **Every observation is evidence-backed.** ``evidence`` is a list of
    :class:`Evidence`; ``confidence`` is derived from it (noisy-OR) unless a
    caller overrides with a justified value.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .coordinate import Coordinate
from .evidence import ConfidenceBand, Evidence, EvidenceLedger


class LocationType(str, Enum):
    """What kind of place an observation is about (spec §1 ``location_type``)."""

    COORDINATE = "coordinate"
    CITY = "city"
    REGION = "region"
    COUNTRY = "country"
    AIRPORT = "airport"
    HELIPORT = "heliport"
    SEAPORT = "seaport"
    DATACENTER = "datacenter"
    CLOUD_REGION = "cloud_region"
    IXP = "ixp"
    FACILITY = "facility"
    GOVERNMENT = "government"
    HOSPITAL = "hospital"
    UNIVERSITY = "university"
    POWER_STATION = "power_station"
    TELECOM = "telecom"
    SUBMARINE_CABLE_LANDING = "submarine_cable_landing"
    TRANSPORT_HUB = "transport_hub"
    ROAD = "road"
    RAILWAY = "railway"
    LANDMARK = "landmark"
    ASN_REGION = "asn_region"
    IP_GEO = "ip_geo"
    DOMAIN_GEO = "domain_geo"
    SATELLITE_SCENE = "satellite_scene"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, raw: Any) -> "LocationType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN


@dataclass
class GeoObservation:
    """A single, evidence-backed geographic observation (spec §1)."""

    entity_id: str                                    # what this is about
    location_type: LocationType = LocationType.UNKNOWN
    coordinate: Optional[Coordinate] = None
    source: str = ""
    source_url: str = ""

    # identity / timing
    geo_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    observation_timestamp: float = field(default_factory=time.time)
    first_seen: float = 0.0
    last_seen: float = 0.0

    # administrative context
    country_code: str = ""                            # ISO 3166-1 alpha-2
    region: str = ""
    city: str = ""
    district: str = ""
    postal_code: str = ""
    timezone: str = ""
    administrative_levels: Dict[str, str] = field(default_factory=dict)

    # confidence / provenance
    confidence: float = -1.0                           # -1 => derive from evidence
    evidence: List[Evidence] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.location_type = LocationType.coerce(self.location_type)
        if self.country_code:
            self.country_code = self.country_code.strip().upper()[:2]
        now = self.observation_timestamp
        if not self.first_seen:
            self.first_seen = now
        if not self.last_seen:
            self.last_seen = now
        if self.confidence is None or self.confidence < 0:
            self.confidence = self._derive_confidence()
        else:
            self.confidence = max(0.0, min(1.0, float(self.confidence)))

    # -- confidence --------------------------------------------------------
    def _derive_confidence(self) -> float:
        if not self.evidence:
            return 0.0
        ledger = EvidenceLedger().extend(self.evidence)
        return ledger.combined_confidence()

    @property
    def band(self) -> ConfidenceBand:
        return ConfidenceBand.of(self.confidence)

    @property
    def coordinate_precision(self) -> int:
        return self.coordinate.precision if self.coordinate else -1

    @property
    def has_fix(self) -> bool:
        return self.coordinate is not None and not self.coordinate.is_null_island

    # -- evidence ----------------------------------------------------------
    def add_evidence(self, evidence: Evidence) -> "GeoObservation":
        self.evidence.append(evidence)
        self.confidence = self._derive_confidence()
        return self

    def observe_again(self, when: Optional[float] = None) -> None:
        """Record that the same fact was seen again; widens first/last_seen."""
        t = when if when is not None else time.time()
        self.first_seen = min(self.first_seen, t)
        self.last_seen = max(self.last_seen, t)

    # -- serialisation -----------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "geo_id": self.geo_id,
            "entity_id": self.entity_id,
            "location_type": self.location_type.value,
            "latitude": self.coordinate.latitude if self.coordinate else None,
            "longitude": self.coordinate.longitude if self.coordinate else None,
            "coordinate_precision": self.coordinate_precision,
            "coordinate": self.coordinate.to_dict() if self.coordinate else None,
            "source": self.source,
            "source_url": self.source_url,
            "observation_timestamp": self.observation_timestamp,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "confidence": round(self.confidence, 4),
            "band": self.band.value,
            "location_type_name": self.location_type.value,
            "administrative_levels": dict(self.administrative_levels),
            "timezone": self.timezone,
            "country_code": self.country_code,
            "city": self.city,
            "region": self.region,
            "district": self.district,
            "postal_code": self.postal_code,
            "evidence": [e.to_dict() for e in self.evidence],
            "metadata": dict(self.metadata),
        }

    def to_geojson_feature(self) -> Optional[Dict[str, Any]]:
        """A GeoJSON Feature, or ``None`` when there is no fix to place."""
        if not self.coordinate:
            return None
        return {
            "type": "Feature",
            "geometry": self.coordinate.to_geojson(),
            "properties": {
                "geo_id": self.geo_id,
                "entity_id": self.entity_id,
                "location_type": self.location_type.value,
                "source": self.source,
                "confidence": round(self.confidence, 4),
                "band": self.band.value,
                "city": self.city,
                "country_code": self.country_code,
                "timezone": self.timezone,
                "precision": self.coordinate_precision,
            },
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "GeoObservation":
        coord = None
        if d.get("coordinate"):
            coord = Coordinate.from_any(d["coordinate"])
        elif d.get("latitude") is not None and d.get("longitude") is not None:
            coord = Coordinate(float(d["latitude"]), float(d["longitude"]),
                               precision=int(d.get("coordinate_precision", -1)))
        obs = cls(
            entity_id=str(d.get("entity_id", "")),
            location_type=LocationType.coerce(d.get("location_type")),
            coordinate=coord,
            source=str(d.get("source", "")),
            source_url=str(d.get("source_url", "")),
            geo_id=str(d.get("geo_id") or uuid.uuid4().hex[:16]),
            observation_timestamp=float(d.get("observation_timestamp", time.time())),
            first_seen=float(d.get("first_seen", 0.0)),
            last_seen=float(d.get("last_seen", 0.0)),
            country_code=str(d.get("country_code", "")),
            region=str(d.get("region", "")),
            city=str(d.get("city", "")),
            district=str(d.get("district", "")),
            postal_code=str(d.get("postal_code", "")),
            timezone=str(d.get("timezone", "")),
            administrative_levels=dict(d.get("administrative_levels", {})),
            confidence=float(d.get("confidence", -1.0)),
            evidence=[Evidence.from_dict(e) for e in d.get("evidence", [])],
            metadata=dict(d.get("metadata", {})),
        )
        return obs


class ObservationSet:
    """An ordered, de-duplicating collection of observations for one run.

    De-duplication key is (entity_id, location_type, rounded coordinate, source):
    the same source re-asserting the same fix merely widens first/last_seen rather
    than piling up duplicate rows — the behaviour the timeline engine relies on.
    """

    def __init__(self) -> None:
        self._by_key: Dict[str, GeoObservation] = {}
        self._order: List[str] = []

    @staticmethod
    def _key(obs: GeoObservation) -> str:
        if obs.coordinate:
            lat, lon = obs.coordinate.rounded(4)
            geo = f"{lat},{lon}"
        else:
            geo = f"{obs.country_code}/{obs.region}/{obs.city}".lower()
        return f"{obs.entity_id}|{obs.location_type.value}|{geo}|{obs.source}"

    def add(self, obs: GeoObservation) -> GeoObservation:
        key = self._key(obs)
        existing = self._by_key.get(key)
        if existing is None:
            self._by_key[key] = obs
            self._order.append(key)
            return obs
        existing.observe_again(obs.observation_timestamp)
        for e in obs.evidence:
            existing.add_evidence(e)
        return existing

    def add_all(self, items: List[GeoObservation]) -> None:
        for obs in items:
            self.add(obs)

    def __len__(self) -> int:
        return len(self._by_key)

    def __iter__(self):
        for key in self._order:
            yield self._by_key[key]

    @property
    def observations(self) -> List[GeoObservation]:
        return [self._by_key[k] for k in self._order]

    def with_fix(self) -> List[GeoObservation]:
        return [o for o in self if o.has_fix]

    def by_entity(self, entity_id: str) -> List[GeoObservation]:
        return [o for o in self if o.entity_id == entity_id]

    def to_feature_collection(self) -> Dict[str, Any]:
        feats = [o.to_geojson_feature() for o in self if o.has_fix]
        return {"type": "FeatureCollection",
                "features": [f for f in feats if f is not None]}

    def to_list(self) -> List[Dict[str, Any]]:
        return [o.to_dict() for o in self]
