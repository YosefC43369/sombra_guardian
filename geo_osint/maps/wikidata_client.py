"""
geo_osint.maps.wikidata_client — geographic enrichment from Wikidata (spec §18).

Wikidata is a free, public, structured knowledge base. Given a place name or a
Q-id, this client fetches the entity and extracts the geographic facts the spec
asks for: coordinates (P625), country (P17), IATA (P238) / ICAO (P239) codes,
population (P1082), official website (P856), and the entity's aliases/labels
across languages (feeding the multilingual alias engine, spec §33). The claim
parser is a pure function tested offline against the standard entity-JSON shape;
the network layer (entity fetch + ``wbsearchentities``) degrades gracefully.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..models.coordinate import Coordinate
from ..storage.cache_store import CacheStore

logger = logging.getLogger("modbot.geo_osint.wikidata")

ENTITY_DATA = "https://www.wikidata.org/wiki/Special:EntityData/{qid}.json"
API = "https://www.wikidata.org/w/api.php"


@dataclass
class WikidataPlace:
    qid: str
    label: str = ""
    coordinate: Optional[Coordinate] = None
    country_qid: str = ""
    iata: str = ""
    icao: str = ""
    population: Optional[int] = None
    website: str = ""
    aliases: List[str] = field(default_factory=list)
    descriptions: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"qid": self.qid, "label": self.label,
                "coordinate": self.coordinate.to_dict() if self.coordinate else None,
                "country_qid": self.country_qid, "iata": self.iata,
                "icao": self.icao, "population": self.population,
                "website": self.website, "aliases": list(self.aliases),
                "descriptions": dict(self.descriptions)}


class WikidataClient:
    def __init__(self, client: Any = None, cache: Optional[CacheStore] = None) -> None:
        self._client = client
        self._cache = cache

    # -- pure parser (offline-testable) -----------------------------------
    def parse_entity(self, payload: Dict[str, Any], qid: str) -> Optional[WikidataPlace]:
        entities = payload.get("entities", {}) if isinstance(payload, dict) else {}
        ent = entities.get(qid)
        if not isinstance(ent, dict):
            # single-entity payloads sometimes come unwrapped
            ent = payload if payload.get("id") == qid else None
            if ent is None and entities:
                ent = next(iter(entities.values()))
            if not isinstance(ent, dict):
                return None
        place = WikidataPlace(qid=qid)
        labels = ent.get("labels", {})
        if isinstance(labels, dict):
            en = labels.get("en", {})
            place.label = en.get("value", "") if isinstance(en, dict) else ""
            place.aliases = [v.get("value", "") for v in
                             _flatten_aliases(ent.get("aliases", {}))]
            for lang in ("th", "ja", "zh", "ru", "ar", "he"):
                lab = labels.get(lang)
                if isinstance(lab, dict) and lab.get("value"):
                    place.aliases.append(lab["value"])
        descs = ent.get("descriptions", {})
        if isinstance(descs, dict):
            place.descriptions = {k: v.get("value", "") for k, v in descs.items()
                                  if isinstance(v, dict)}
        claims = ent.get("claims", {})
        place.coordinate = _coord_claim(claims.get("P625"))
        place.country_qid = _entity_claim(claims.get("P17"))
        place.iata = _string_claim(claims.get("P238"))
        place.icao = _string_claim(claims.get("P239"))
        place.population = _quantity_claim(claims.get("P1082"))
        place.website = _string_claim(claims.get("P856"))
        return place

    # -- network -----------------------------------------------------------
    async def get_entity(self, qid: str) -> Optional[WikidataPlace]:
        qid = qid.strip().upper()
        if self._cache is not None:
            cached = self._cache.get("wikidata_entity", qid)
            if cached is not None:
                return self.parse_entity(cached, qid)
        if self._client is None:
            return None
        try:
            res = await self._client.get_json(ENTITY_DATA.format(qid=qid))
            if not res.ok:
                return None
            body = res.json()
        except Exception as exc:
            logger.debug("wikidata entity fetch failed: %s", exc)
            return None
        if self._cache is not None:
            self._cache.set("wikidata_entity", qid, body, ttl_s=2592000)
        return self.parse_entity(body, qid)

    async def search(self, name: str, limit: int = 5) -> List[str]:
        """Return candidate Q-ids for a place name via wbsearchentities."""
        if self._client is None:
            return []
        try:
            res = await self._client.get_json(
                API, params={"action": "wbsearchentities", "search": name,
                             "language": "en", "format": "json", "limit": limit,
                             "type": "item"})
            if not res.ok:
                return []
            return [hit["id"] for hit in res.json().get("search", [])
                    if isinstance(hit, dict) and hit.get("id")]
        except Exception:
            return []


def _flatten_aliases(aliases: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if isinstance(aliases, dict):
        for lst in aliases.values():
            if isinstance(lst, list):
                out.extend(v for v in lst if isinstance(v, dict))
    return out


def _first_mainsnak(claim_list: Any) -> Optional[Dict[str, Any]]:
    if isinstance(claim_list, list) and claim_list:
        snak = claim_list[0].get("mainsnak", {})
        return snak.get("datavalue", {}).get("value") if isinstance(snak, dict) else None
    return None


def _coord_claim(claim_list: Any) -> Optional[Coordinate]:
    val = _first_mainsnak(claim_list)
    if isinstance(val, dict) and "latitude" in val and "longitude" in val:
        try:
            return Coordinate(float(val["latitude"]), float(val["longitude"]),
                              source="wikidata")
        except Exception:
            return None
    return None


def _entity_claim(claim_list: Any) -> str:
    val = _first_mainsnak(claim_list)
    if isinstance(val, dict):
        return str(val.get("id", ""))
    return ""


def _string_claim(claim_list: Any) -> str:
    val = _first_mainsnak(claim_list)
    return str(val) if isinstance(val, str) else ""


def _quantity_claim(claim_list: Any) -> Optional[int]:
    val = _first_mainsnak(claim_list)
    if isinstance(val, dict) and "amount" in val:
        try:
            return int(float(str(val["amount"]).lstrip("+")))
        except (TypeError, ValueError):
            return None
    return None
