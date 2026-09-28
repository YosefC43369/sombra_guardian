"""
geo_osint.correlation.geo_entity_correlation — entity <-> geography (spec §29, §47).

Consolidates the geographic observations about an entity into a ranked, evidence-
backed profile: which countries and cities the entity is associated with, and how
strongly, combining *independent* public sources with noisy-OR. It also produces
the explicit entity<->country / city / airport / domain / ASN correlations the
spec enumerates.

FUSION SAFEGUARD (spec §47, enforced here): shared geography is a *weak
co-location* signal, never an identity-merge signal. :meth:`shared_geography`
returns overlaps clearly tagged ``merge_safe=False`` with the reason, so Entity
Fusion can use geography as corroboration but never merge two entities solely
because they reference the same city or country.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..models.evidence import ConfidenceBand, Evidence, EvidenceLedger
from ..models.observation import GeoObservation, LocationType


@dataclass
class GeoCorrelation:
    entity_id: str
    relation: str                 # "country" | "city" | "airport" | "domain" | "asn"
    value: str
    confidence: float
    evidence: List[Evidence] = field(default_factory=list)
    coordinate: Optional[Any] = None

    @property
    def band(self) -> ConfidenceBand:
        return ConfidenceBand.of(self.confidence)

    def to_dict(self) -> Dict[str, Any]:
        return {"entity_id": self.entity_id, "relation": self.relation,
                "value": self.value, "confidence": round(self.confidence, 4),
                "band": self.band.value,
                "coordinate": self.coordinate.to_dict() if self.coordinate else None,
                "evidence": [e.to_dict() for e in self.evidence]}


@dataclass
class EntityGeoProfile:
    entity_id: str
    countries: List[GeoCorrelation] = field(default_factory=list)
    cities: List[GeoCorrelation] = field(default_factory=list)
    other: List[GeoCorrelation] = field(default_factory=list)

    @property
    def primary_country(self) -> Optional[GeoCorrelation]:
        return self.countries[0] if self.countries else None

    @property
    def primary_city(self) -> Optional[GeoCorrelation]:
        return self.cities[0] if self.cities else None

    def to_dict(self) -> Dict[str, Any]:
        return {"entity_id": self.entity_id,
                "primary_country": self.primary_country.to_dict() if self.primary_country else None,
                "primary_city": self.primary_city.to_dict() if self.primary_city else None,
                "countries": [c.to_dict() for c in self.countries],
                "cities": [c.to_dict() for c in self.cities],
                "other": [c.to_dict() for c in self.other]}


@dataclass
class SharedGeography:
    entity_a: str
    entity_b: str
    shared_countries: List[str]
    shared_cities: List[str]
    merge_safe: bool = False
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"entity_a": self.entity_a, "entity_b": self.entity_b,
                "shared_countries": self.shared_countries,
                "shared_cities": self.shared_cities,
                "merge_safe": self.merge_safe, "reason": self.reason}


class GeoEntityCorrelator:
    def correlate(self, entity_id: str,
                  observations: Sequence[GeoObservation]) -> EntityGeoProfile:
        mine = [o for o in observations if o.entity_id == entity_id] or list(observations)
        profile = EntityGeoProfile(entity_id=entity_id)

        # Group evidence by (relation, value); combine independent sources.
        country_ledgers: Dict[str, EvidenceLedger] = {}
        country_coord: Dict[str, Any] = {}
        city_ledgers: Dict[str, EvidenceLedger] = {}
        city_coord: Dict[str, Any] = {}
        other: List[GeoCorrelation] = []

        for obs in mine:
            src_ev = obs.evidence or [Evidence(source=obs.source or "observation",
                                               claim=obs.location_type.value,
                                               confidence=obs.confidence)]
            if obs.country_code:
                led = country_ledgers.setdefault(obs.country_code, EvidenceLedger())
                self._add_unique(led, src_ev)
                if obs.coordinate is not None:
                    country_coord.setdefault(obs.country_code, obs.coordinate)
            if obs.city:
                key = f"{obs.city}|{obs.country_code}"
                led = city_ledgers.setdefault(key, EvidenceLedger())
                self._add_unique(led, src_ev)
                if obs.coordinate is not None:
                    city_coord.setdefault(key, obs.coordinate)
            if obs.location_type in (LocationType.AIRPORT, LocationType.ASN_REGION,
                                     LocationType.DOMAIN_GEO):
                other.append(GeoCorrelation(
                    entity_id=entity_id,
                    relation=self._relation_for(obs.location_type),
                    value=obs.entity_id if obs.location_type != LocationType.AIRPORT
                    else (obs.metadata.get("iata") or obs.city or "airport"),
                    confidence=obs.confidence, evidence=src_ev,
                    coordinate=obs.coordinate))

        profile.countries = self._rank(entity_id, "country", country_ledgers, country_coord)
        profile.cities = self._rank(entity_id, "city", city_ledgers, city_coord,
                                    strip_country=True)
        profile.other = other
        return profile

    def shared_geography(self, entity_a: str, obs_a: Sequence[GeoObservation],
                         entity_b: str, obs_b: Sequence[GeoObservation]) -> SharedGeography:
        ca = {o.country_code for o in obs_a if o.country_code}
        cb = {o.country_code for o in obs_b if o.country_code}
        cia = {o.city for o in obs_a if o.city}
        cib = {o.city for o in obs_b if o.city}
        shared_countries = sorted(ca & cb)
        shared_cities = sorted(cia & cib)
        return SharedGeography(
            entity_a=entity_a, entity_b=entity_b,
            shared_countries=shared_countries, shared_cities=shared_cities,
            merge_safe=False,
            reason="Shared geography is a weak co-location signal only. Per spec "
                   "§47, entities are NEVER merged solely because they reference "
                   "the same city or country; use this only as corroboration "
                   "alongside independent identity evidence.")

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _add_unique(ledger: EvidenceLedger, evidence: Sequence[Evidence]) -> None:
        existing = {e.source for e in ledger.items}
        for e in evidence:
            if e.source not in existing:      # keep sources independent for noisy-OR
                ledger.add(e)
                existing.add(e.source)

    @staticmethod
    def _relation_for(lt: LocationType) -> str:
        return {LocationType.AIRPORT: "airport",
                LocationType.ASN_REGION: "asn",
                LocationType.DOMAIN_GEO: "domain"}.get(lt, "other")

    def _rank(self, entity_id: str, relation: str,
              ledgers: Dict[str, EvidenceLedger], coords: Dict[str, Any],
              strip_country: bool = False) -> List[GeoCorrelation]:
        out: List[GeoCorrelation] = []
        for key, led in ledgers.items():
            value = key.split("|", 1)[0] if strip_country else key
            out.append(GeoCorrelation(
                entity_id=entity_id, relation=relation, value=value,
                confidence=led.combined_confidence(), evidence=led.items,
                coordinate=coords.get(key)))
        out.sort(key=lambda c: c.confidence, reverse=True)
        return out
