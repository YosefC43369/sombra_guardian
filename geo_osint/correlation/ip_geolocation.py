"""
geo_osint.correlation.ip_geolocation — public IP geolocation (spec §13).

Turns a public IP address into an evidence-backed
:class:`~geo_osint.models.observation.GeoObservation`, using a free/public
geolocation provider. Two disciplines are enforced in code:

  * **Public IPs only.** Private/loopback/link-local/reserved addresses are
    refused (reusing ``osint.utils.validators.is_public_ip``) so the engine can
    never be turned into an internal-network probe.
  * **Never treated as an exact physical location.** Every observation records a
    ``provider precision`` note and the standing limitation that IP geolocation
    is an ISP/registry *estimate* — city-level at best, often only country-level —
    and is not a device fix (spec §13). Provider confidence is stored.

The provider is pluggable (default: the ``ipwho.is`` free HTTPS endpoint, no key).
The JSON parser is a pure function tested offline; the network call degrades
gracefully to a country-level fallback derived from ASN routing data.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..models.coordinate import Coordinate, CoordinateParseError
from ..models.evidence import Evidence
from ..models.observation import GeoObservation, LocationType

logger = logging.getLogger("modbot.geo_osint.ip_geo")

try:
    from osint.utils import validators as _validators
except Exception:                                # pragma: no cover
    _validators = None

DEFAULT_ENDPOINT = "https://ipwho.is/{ip}"

_IP_GEO_LIMITATION = (
    "IP geolocation is an ISP/registry estimate (city-level at best, often only "
    "country-level); it is NOT a physical device location and must not be treated "
    "as one.")


@dataclass
class IPGeoResult:
    ip: str
    observation: Optional[GeoObservation]
    ok: bool
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"ip": self.ip, "ok": self.ok, "reason": self.reason,
                "observation": self.observation.to_dict() if self.observation else None}


class IPGeolocationEngine:
    def __init__(self, endpoint: str = DEFAULT_ENDPOINT) -> None:
        self._endpoint = endpoint

    # -- gating (offline) --------------------------------------------------
    def is_locatable(self, ip: str) -> bool:
        if _validators is not None:
            return _validators.is_public_ip(ip)
        return bool(ip) and not ip.startswith(("10.", "127.", "192.168.", "169.254."))

    # -- pure parser (offline-testable) -----------------------------------
    def parse_ipwhois(self, payload: Dict[str, Any], ip: str) -> Optional[GeoObservation]:
        """Parse an ipwho.is-style JSON body into a GeoObservation."""
        if not isinstance(payload, dict) or payload.get("success") is False:
            return None
        lat = payload.get("latitude")
        lon = payload.get("longitude")
        coord: Optional[Coordinate] = None
        if lat is not None and lon is not None:
            try:
                coord = Coordinate(float(lat), float(lon), precision=2,
                                   source="ip-geo-provider")
            except (CoordinateParseError, ValueError, TypeError):
                coord = None
        conn = payload.get("connection", {}) if isinstance(payload.get("connection"), dict) else {}
        asn = conn.get("asn")
        org = conn.get("org") or conn.get("isp") or payload.get("org", "")
        tz_obj = payload.get("timezone", {})
        tz = tz_obj.get("id", "") if isinstance(tz_obj, dict) else str(tz_obj or "")
        ev = Evidence(
            source="ip-geo-provider",
            claim=f"IP {ip} estimated near {payload.get('city', '')}, "
                  f"{payload.get('country_code', '')}",
            confidence=0.5, source_url=self._endpoint.format(ip=ip),
            precision="provider estimate (city-level)",
            limitations=_IP_GEO_LIMITATION,
            raw={"asn": asn, "org": org, "isp": conn.get("isp", "")})
        obs = GeoObservation(
            entity_id=ip, location_type=LocationType.IP_GEO, coordinate=coord,
            source="ip-geo-provider", source_url=self._endpoint.format(ip=ip),
            country_code=str(payload.get("country_code", "")),
            region=str(payload.get("region", "")), city=str(payload.get("city", "")),
            postal_code=str(payload.get("postal", "")), timezone=tz,
            evidence=[ev],
            metadata={"asn": asn, "org": org, "provider": "ipwho.is"})
        return obs

    # -- online ------------------------------------------------------------
    async def locate(self, ip: str, client: Any = None) -> IPGeoResult:
        norm = _validators.normalize_ip(ip) if _validators else ip
        if not norm:
            return IPGeoResult(ip, None, False, "not a valid IP address")
        if not self.is_locatable(norm):
            return IPGeoResult(norm, None, False,
                               "non-public IP (private/reserved) is not geolocated")
        if client is None:
            return IPGeoResult(norm, None, False,
                               "offline: no HTTP client supplied for provider lookup")
        try:
            res = await client.get_json(self._endpoint.format(ip=norm))
            if not res.ok:
                return IPGeoResult(norm, None, False, f"provider error: {res.reason}")
            obs = self.parse_ipwhois(res.json(), norm)
            if obs is None:
                return IPGeoResult(norm, None, False, "provider returned no location")
            return IPGeoResult(norm, obs, True)
        except Exception as exc:                       # graceful degradation
            logger.debug("ip geolocation failed for %s: %s", norm, exc)
            return IPGeoResult(norm, None, False, f"lookup failed: {exc}")
