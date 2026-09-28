"""
geo_osint.infrastructure.datacenter_engine — public data-centre & IXP intelligence
(spec §10, §37).

Consumes PeeringDB — the community, publicly-queryable registry of data-centre
facilities (``/api/fac``) and internet exchanges (``/api/ix``) — into typed
:class:`~geo_osint.models.infrastructure.DataCenter` and
:class:`~geo_osint.models.infrastructure.InternetExchange` records. PeeringDB
publishes facility name, operator, city, country and coordinates plus ASN/peering
references; the engine surfaces those and nothing more (spec §10 "never infer
sensitive internal layouts"). Offline it operates over injected records; online it
adds a bounded, cached PeeringDB query. No credentials required.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from ..models.coordinate import Coordinate
from ..models.infrastructure import DataCenter, InternetExchange
from .facility_engine import FacilityEngine

logger = logging.getLogger("modbot.geo_osint.datacenter")

_PEERINGDB = "https://www.peeringdb.com/api"


class DataCenterEngine:
    def __init__(self, base_url: str = _PEERINGDB) -> None:
        self._base = base_url
        self._facilities = FacilityEngine()
        self._datacenters: List[DataCenter] = []
        self._ixps: List[InternetExchange] = []

    # -- offline registry --------------------------------------------------
    def register(self, dc: DataCenter) -> None:
        self._datacenters.append(dc)
        self._facilities.register(dc)

    def register_ixp(self, ixp: InternetExchange) -> None:
        self._ixps.append(ixp)

    def all(self) -> List[DataCenter]:
        return list(self._datacenters)

    def all_ixps(self) -> List[InternetExchange]:
        return list(self._ixps)

    def by_country(self, country_code: str) -> List[DataCenter]:
        cc = (country_code or "").strip().upper()
        return [d for d in self._datacenters if d.country_code == cc]

    def nearest(self, coord: Coordinate, limit: int = 5,
                radius_km: float = 100.0) -> List[Tuple[DataCenter, float]]:
        out = [(d, round(coord.distance_km(d.coordinate, method="haversine"), 3))
               for d in self._datacenters if d.coordinate]
        out = [(d, dist) for d, dist in out if dist <= radius_km]
        out.sort(key=lambda t: t[1])
        return out[:limit]

    # -- PeeringDB parsers (offline-testable) -----------------------------
    def parse_peeringdb_fac(self, payload: Dict[str, Any]) -> List[DataCenter]:
        out: List[DataCenter] = []
        for rec in _records(payload):
            coord = _coord(rec.get("latitude"), rec.get("longitude"))
            out.append(DataCenter(
                name=str(rec.get("name", "")), coordinate=coord,
                operator=str(rec.get("org_name", "")),
                city=str(rec.get("city", "")),
                country_code=str(rec.get("country", "")).upper()[:2],
                website=str(rec.get("website", "")),
                identifiers={"peeringdb_fac": str(rec.get("id", ""))},
                source="peeringdb",
                source_url=f"https://www.peeringdb.com/fac/{rec.get('id', '')}",
                metadata={"clli": rec.get("clli", ""), "notes": rec.get("notes", "")}))
        return out

    def parse_peeringdb_ix(self, payload: Dict[str, Any]) -> List[InternetExchange]:
        out: List[InternetExchange] = []
        for rec in _records(payload):
            out.append(InternetExchange(
                name=str(rec.get("name", "")),
                city=str(rec.get("city", "")),
                country_code=str(rec.get("country", "")).upper()[:2],
                website=str(rec.get("website", "")),
                peeringdb_id=str(rec.get("id", "")),
                participants=_int(rec.get("net_count")),
                source="peeringdb",
                source_url=f"https://www.peeringdb.com/ix/{rec.get('id', '')}"))
        return out

    # -- online ------------------------------------------------------------
    async def facilities_in_country(self, country_code: str, client: Any = None,
                                    register: bool = True) -> List[DataCenter]:
        if client is None:
            return self.by_country(country_code)
        try:
            res = await client.get_json(f"{self._base}/fac",
                                        params={"country": country_code.upper()})
            if not res.ok:
                return []
            dcs = self.parse_peeringdb_fac(res.json())
        except Exception as exc:
            logger.debug("peeringdb fac query failed: %s", exc)
            return []
        if register:
            for d in dcs:
                self.register(d)
        return dcs

    async def ixps_in_country(self, country_code: str, client: Any = None) -> List[InternetExchange]:
        if client is None:
            return [i for i in self._ixps if i.country_code == country_code.upper()]
        try:
            res = await client.get_json(f"{self._base}/ix",
                                        params={"country": country_code.upper()})
            if not res.ok:
                return []
            ixps = self.parse_peeringdb_ix(res.json())
        except Exception as exc:
            logger.debug("peeringdb ix query failed: %s", exc)
            return []
        self._ixps.extend(ixps)
        return ixps


def _records(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("data"), list):
        return payload["data"]
    if isinstance(payload, list):
        return payload
    return []


def _coord(lat: Any, lon: Any) -> Optional[Coordinate]:
    try:
        if lat in (None, "", 0) and lon in (None, "", 0):
            return None
        return Coordinate(float(lat), float(lon), precision=5, source="peeringdb")
    except (TypeError, ValueError):
        return None


def _int(v: Any) -> Optional[int]:
    try:
        return int(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None
