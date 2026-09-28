"""
geo_osint.correlation.asn_geolocation — ASN -> geographic region (spec §12).

Maps an autonomous-system number to public geographic context — the holder's
name, registration country, RIR — by reusing the repository's existing
``osint.sources.bgpview`` source (the global BGP table, public infrastructure
metadata). The result is an evidence-backed country-level
:class:`~geo_osint.models.observation.GeoObservation` whose coordinate, when set,
is the *country centroid* from the gazetteer (clearly marked as a country-level
approximation), never a claim about where the AS's routers physically sit.

DISCIPLINE (spec §12): "do not infer exact infrastructure ownership". The engine
reports the registered holder and country as published, with the standing
limitation that registration/routing data locates an *organisation's
registration*, not its physical equipment.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..data import countries as _countries
from ..models.evidence import Evidence
from ..models.observation import GeoObservation, LocationType

logger = logging.getLogger("modbot.geo_osint.asn_geo")

try:
    from osint.utils import validators as _validators
    from osint.sources.bgpview import BGPViewASNSource
except Exception:                                # pragma: no cover
    _validators = None
    BGPViewASNSource = None

_ASN_LIMITATION = (
    "ASN geolocation reflects the registered holder's country/RIR in public "
    "routing data; it locates an organisation's registration, not the physical "
    "location of its routers or customers.")


@dataclass
class ASNGeoResult:
    asn: int
    observation: Optional[GeoObservation]
    ok: bool
    reason: str = ""
    holder: str = ""
    rir: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"asn": self.asn, "ok": self.ok, "reason": self.reason,
                "holder": self.holder, "rir": self.rir,
                "observation": self.observation.to_dict() if self.observation else None}


class ASNGeolocationEngine:
    def __init__(self, source: Any = None) -> None:
        self._source = source if source is not None else (
            BGPViewASNSource() if BGPViewASNSource else None)

    def normalize(self, raw: str) -> Optional[int]:
        if _validators is not None:
            return _validators.normalize_asn(raw)
        try:
            return int(str(raw).upper().replace("AS", "").strip())
        except ValueError:
            return None

    def _observation_from(self, asn: int, holder: str, country_code: str,
                          rir: str, url: str) -> GeoObservation:
        country = _countries.by_iso2(country_code) if country_code else None
        coord = country.centroid if country else None
        ev = Evidence(
            source="bgpview", claim=f"AS{asn} ({holder}) registered in {country_code}",
            confidence=0.55, source_url=url,
            precision="country-level (registration)", limitations=_ASN_LIMITATION,
            raw={"rir": rir, "holder": holder})
        return GeoObservation(
            entity_id=f"AS{asn}", location_type=LocationType.ASN_REGION,
            coordinate=coord, source="bgpview", source_url=url,
            country_code=country_code, evidence=[ev],
            metadata={"holder": holder, "rir": rir, "asn": asn,
                      "coordinate_note": "country centroid, not router location"})

    async def locate(self, raw_asn: str, client: Any = None) -> ASNGeoResult:
        asn = self.normalize(raw_asn)
        if asn is None:
            return ASNGeoResult(0, None, False, "not a valid ASN")
        if self._source is None or client is None:
            return ASNGeoResult(asn, None, False,
                                "offline: no BGPView source/client available")
        try:
            result = await self._source.fetch(client, str(asn))
        except Exception as exc:
            return ASNGeoResult(asn, None, False, f"lookup failed: {exc}")
        if not result.ok or not result.records:
            return ASNGeoResult(asn, None, False,
                                result.reason or "no routing data returned")
        rec = result.records[0]
        holder = str(rec.get("holder", rec.get("name", rec.get("description", ""))))
        cc = str(rec.get("country", rec.get("country_code", ""))).upper()[:2]
        rir = str(rec.get("rir", rec.get("rir_name", "")))
        url = f"https://bgpview.io/asn/{asn}"
        obs = self._observation_from(asn, holder, cc, rir, url)
        return ASNGeoResult(asn, obs, True, holder=holder, rir=rir)
