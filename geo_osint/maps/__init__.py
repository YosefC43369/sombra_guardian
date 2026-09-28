"""
geo_osint.maps — public map/geo data clients (spec §16-20).

Online enrichment providers that plug into the geocoding engines and degrade
gracefully offline:

  * :class:`OSMClient` — OpenStreetMap Nominatim (policy-compliant, cached) +
    Overpass passthrough (§17);
  * :class:`WikidataClient` — Wikidata place enrichment: coords, IATA/ICAO,
    population, website, multilingual aliases (§18);
  * :class:`GeoNamesClient` — GeoNames gazetteer with alternate names (§19);
  * :class:`NaturalEarthLayer` — offline public-domain country boundaries (§20);
  * :class:`AdministrativeBoundaryEngine` — admin boundary resolution (§16).

Every client has a pure, offline-testable parser and never fails a run on network
error.
"""

from .osm_client import OSMClient
from .wikidata_client import WikidataClient, WikidataPlace
from .geonames_client import GeoNamesClient
from .naturalearth import NaturalEarthLayer
from .administrative_boundaries import AdministrativeBoundaryEngine

__all__ = [
    "OSMClient", "WikidataClient", "WikidataPlace", "GeoNamesClient",
    "NaturalEarthLayer", "AdministrativeBoundaryEngine",
]
