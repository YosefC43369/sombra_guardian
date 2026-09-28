"""
geo_osint.reports.geo_report — assemble the structured Geo-OSINT report (spec §46).

Consumes a :class:`~geo_osint.engine.GeoResult` (or a
:class:`~geo_osint.pipeline.PipelineResult`) and produces a provider-neutral report
*data structure* with the sections the spec enumerates — Executive Summary,
Geographic Inventory, Infrastructure Map, Airport Analysis, Country Timeline,
ASN/IP Geolocation, Cloud Regions, Facility Relationships, Evidence, Limitations.
The concrete renderers (JSON/Markdown/HTML/CSV) turn this structure into files, so
every format shows the same facts.

Every section is evidence-backed; the Limitations section is always present and
restates the engine's hard privacy/precision boundaries (spec §43, §50).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..engine import GeoResult
from ..models.observation import GeoObservation, LocationType

_STANDING_LIMITATIONS = [
    "Public data only: every finding derives from publicly observable geographic "
    "information. No live/device/GPS location, no private-account data, no tracking "
    "of individuals is used or possible in this engine.",
    "Coordinates carry explicit precision; IP/ASN geolocation is a provider/registry "
    "estimate (often only country-level), never a physical device location.",
    "Shared geography is a weak co-location signal only and never merges identities.",
    "Timezone is environmental metadata, not an identity or presence signal.",
]


@dataclass
class GeoReport:
    entity: str
    generated_at: float = field(default_factory=time.time)
    sections: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"entity": self.entity,
                "generated_at": self.generated_at,
                "generated_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                               time.gmtime(self.generated_at)),
                "sections": self.sections}


class GeoReportBuilder:
    def build(self, result: GeoResult,
              proximity: Optional[List[Any]] = None) -> GeoReport:
        report = GeoReport(entity=result.entity)
        obs = result.observations.observations
        s = report.sections
        s["executive_summary"] = self._exec_summary(result, obs)
        s["geographic_inventory"] = self._inventory(obs)
        s["infrastructure_map"] = result.to_feature_collection()
        s["airport_analysis"] = self._by_type(obs, LocationType.AIRPORT)
        s["country_timeline"] = self._timeline(result)
        s["ip_asn_geolocation"] = self._ip_asn(obs)
        s["cloud_regions"] = self._by_type(obs, LocationType.CLOUD_REGION)
        s["facility_relationships"] = (result.graph.to_dict()
                                       if result.graph else {"nodes": [], "edges": []})
        s["footprint_score"] = result.footprint_score
        s["evidence"] = self._evidence(obs)
        s["limitations"] = _STANDING_LIMITATIONS + (
            [f"Run note: {e}" for e in result.errors] if result.errors else [])
        return report

    # -- sections ----------------------------------------------------------
    def _exec_summary(self, result: GeoResult, obs: List[GeoObservation]) -> Dict[str, Any]:
        countries = sorted({o.country_code for o in obs if o.country_code})
        cities = sorted({o.city for o in obs if o.city})
        primary = result.profile.primary_country if result.profile else None
        return {
            "entity": result.entity, "kind": result.kind.value,
            "run_mode": result.config.mode.value,
            "observation_count": len(obs),
            "countries": countries, "cities": cities,
            "primary_country": {"value": primary.value,
                                "confidence": primary.confidence} if primary else None,
            "footprint_score": (result.footprint_score or {}).get("score"),
            "elapsed_s": result.elapsed_s,
        }

    def _inventory(self, obs: List[GeoObservation]) -> List[Dict[str, Any]]:
        rows = []
        for o in obs:
            rows.append({
                "type": o.location_type.value,
                "city": o.city, "country_code": o.country_code,
                "latitude": o.coordinate.latitude if o.coordinate else None,
                "longitude": o.coordinate.longitude if o.coordinate else None,
                "precision": o.coordinate_precision,
                "source": o.source, "confidence": round(o.confidence, 4),
                "band": o.band.value,
            })
        return rows

    def _by_type(self, obs: List[GeoObservation], lt: LocationType) -> List[Dict[str, Any]]:
        return [o.to_dict() for o in obs if o.location_type == lt]

    def _ip_asn(self, obs: List[GeoObservation]) -> List[Dict[str, Any]]:
        return [o.to_dict() for o in obs
                if o.location_type in (LocationType.IP_GEO, LocationType.ASN_REGION,
                                       LocationType.DOMAIN_GEO)]

    def _timeline(self, result: GeoResult) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in result.timeline]

    def _evidence(self, obs: List[GeoObservation]) -> List[Dict[str, Any]]:
        out = []
        for o in obs:
            for e in o.evidence:
                out.append({"entity": o.entity_id, "claim": e.claim,
                            "source": e.source, "confidence": round(e.confidence, 4),
                            "source_url": e.source_url,
                            "precision": e.precision, "limitations": e.limitations})
        return out
