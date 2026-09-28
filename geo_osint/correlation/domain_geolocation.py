"""
geo_osint.correlation.domain_geolocation — domain -> geographic signals (spec §14).

A domain has *no single* location; it has a bundle of weak, independent
geographic signals, each with different meaning and reliability. This engine
gathers them and returns one evidence-backed observation per signal, explaining
what each does and does not imply (spec §14 "explain evidence"):

  * **ccTLD** (offline): a country-code TLD associates the name with a registry,
    NOT with hosting or a physical location — many ccTLDs (.io, .co, .tv) are used
    globally. Low confidence, explicit limitation.
  * **RDAP registrant country** (online): the registrant's declared country, which
    can be a privacy-service or registrar country, not the operator's.
  * **hosting IP** (online): the A/AAAA record geolocated via
    :class:`IPGeolocationEngine` — the CDN/host edge, often not the operator.

Signals are combined by the correlation layer with noisy-OR only where they are
genuinely independent.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

from ..data import countries as _countries
from ..models.evidence import Evidence
from ..models.observation import GeoObservation, LocationType
from .ip_geolocation import IPGeolocationEngine

logger = logging.getLogger("modbot.geo_osint.domain_geo")

# Country-code TLDs that are, in practice, used as generic/global TLDs. Flagged so
# the ccTLD signal is suppressed or heavily discounted for them.
_GENERIC_CCTLDS = {".io", ".co", ".tv", ".me", ".ai", ".ly", ".fm", ".gg", ".to",
                   ".cc", ".ws", ".sh", ".is"}

_CCTLD_LIMITATION = (
    "A country-code TLD associates the domain with a registry, not with hosting "
    "or a physical location; many ccTLDs are marketed and used globally.")


@dataclass
class DomainGeoResult:
    domain: str
    observations: List[GeoObservation] = field(default_factory=list)

    @property
    def countries(self) -> List[str]:
        seen: List[str] = []
        for o in self.observations:
            if o.country_code and o.country_code not in seen:
                seen.append(o.country_code)
        return seen

    def to_dict(self) -> Dict[str, Any]:
        return {"domain": self.domain, "countries": self.countries,
                "observations": [o.to_dict() for o in self.observations]}


class DomainGeolocationEngine:
    def __init__(self, ip_engine: Optional[IPGeolocationEngine] = None) -> None:
        self._ip = ip_engine or IPGeolocationEngine()

    # -- offline signals ---------------------------------------------------
    def cctld_signal(self, domain: str) -> Optional[GeoObservation]:
        d = (domain or "").strip().lower().rstrip(".")
        if "." not in d:
            return None
        tld = "." + d.rsplit(".", 1)[1]
        country = _countries.resolve(tld)
        if country is None:
            return None
        generic = tld in _GENERIC_CCTLDS
        confidence = 0.15 if generic else 0.35
        ev = Evidence(
            source="cctld", claim=f"{d} uses the {tld} country-code TLD "
                                  f"({country.name})",
            confidence=confidence, precision="country-association (registry)",
            limitations=_CCTLD_LIMITATION + (
                f" Note: {tld} is commonly used as a generic TLD." if generic else ""))
        return GeoObservation(
            entity_id=d, location_type=LocationType.DOMAIN_GEO,
            coordinate=country.centroid, source="cctld",
            country_code=country.iso2, evidence=[ev],
            metadata={"tld": tld, "generic_cctld": generic})

    def signals_offline(self, domain: str) -> DomainGeoResult:
        result = DomainGeoResult(domain=domain)
        cc = self.cctld_signal(domain)
        if cc is not None:
            result.observations.append(cc)
        return result

    # -- online signals ----------------------------------------------------
    async def locate(self, domain: str, *, client: Any = None,
                     resolver: Optional[Callable[[str], Awaitable[List[str]]]] = None,
                     rdap: bool = True) -> DomainGeoResult:
        d = (domain or "").strip().lower().rstrip(".")
        result = self.signals_offline(d)
        if client is None:
            return result

        if rdap:
            obs = await self._rdap_country(d, client)
            if obs is not None:
                result.observations.append(obs)

        if resolver is not None:
            try:
                ips = await resolver(d)
            except Exception:
                ips = []
            for ip in ips[:3]:
                ipres = await self._ip.locate(ip, client=client)
                if ipres.ok and ipres.observation is not None:
                    ipres.observation.entity_id = d
                    ipres.observation.metadata["signal"] = "hosting_ip"
                    ipres.observation.metadata["hosting_ip"] = ip
                    result.observations.append(ipres.observation)
        return result

    async def _rdap_country(self, domain: str, client: Any) -> Optional[GeoObservation]:
        try:
            res = await client.get_json(f"https://rdap.org/domain/{domain}")
            if not res.ok:
                return None
            body = res.json()
        except Exception:
            return None
        cc = _extract_rdap_country(body)
        if not cc:
            return None
        country = _countries.by_iso2(cc)
        ev = Evidence(
            source="rdap", claim=f"{domain} registrant country {cc}",
            confidence=0.4, source_url=f"https://rdap.org/domain/{domain}",
            precision="registrant declaration",
            limitations="Registrant country may be a privacy service or registrar "
                        "country, not the operator's physical location.")
        return GeoObservation(
            entity_id=domain, location_type=LocationType.DOMAIN_GEO,
            coordinate=country.centroid if country else None, source="rdap",
            country_code=cc, evidence=[ev], metadata={"signal": "rdap_registrant"})


def _extract_rdap_country(body: Dict[str, Any]) -> str:
    """Pull a country code out of an RDAP entity vCard, if present."""
    if not isinstance(body, dict):
        return ""
    for entity in body.get("entities", []) or []:
        vcard = entity.get("vcardArray")
        if not isinstance(vcard, list) or len(vcard) < 2:
            continue
        for field in vcard[1]:
            if isinstance(field, list) and field and field[0] == "adr":
                params = field[1] if len(field) > 1 and isinstance(field[1], dict) else {}
                cc = params.get("cc")
                if cc:
                    return str(cc).upper()[:2]
                if len(field) >= 4 and isinstance(field[3], list) and field[3]:
                    tail = field[3][-1]
                    if isinstance(tail, str) and len(tail) == 2:
                        return tail.upper()
    return ""
