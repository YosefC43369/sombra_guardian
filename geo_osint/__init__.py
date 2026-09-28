"""
geo_osint/ — the Geo-OSINT Engine for Sombra Guardian.

WHAT THIS IS
------------
A geospatial-intelligence (GEOINT) subsystem built *entirely from publicly
available information*. Given an entity — an organization, domain, IP, ASN,
website, airport, port, city, country or a raw coordinate — it discovers,
normalises, correlates, indexes, analyses and visualises the *publicly
observable* geographic information about it, and renders an evidence-backed
report. It reuses the repository's existing ``airports.py`` database, ``osint``
HTTP backbone, and integrates its output into Entity Fusion, Behavioral
Intelligence and Web Footprint.

POSTURE — 80% RED TEAM / 20% BLUE TEAM
--------------------------------------
The engine is primarily a *passive geospatial reconnaissance* capability for
authorized red-team engagements (its 80%): public-infrastructure mapping, the
geographic attack surface, facility/cloud-region/ASN/IP geolocation, aviation and
transport intelligence, geographic pivoting and correlation. A deliberately
smaller defensive companion (its 20%) reuses the same passive output for asset
inventory, incident/IOC location enrichment, infrastructure monitoring and
defensive geographic reporting.

HARD PRIVACY LINE (enforced in code, not merely documented) — spec §50
----------------------------------------------------------------------
The engine analyses ONLY public, observable geographic information. It implements
NONE of the following, by construction — there is no code path, and no input, for
any of them:

  * live device / GPS / cell-tower / Wi-Fi / Bluetooth location collection,
  * real-time tracking of individuals or geofencing of people,
  * access to private-account location history,
  * inference of a specific private individual's precise residence,
  * permission bypass or private-map-API abuse.

Coordinates are never invented: every one carries an explicit precision and cites
a verifiable public source (:mod:`geo_osint.models.evidence`). Geofencing and
routing operate over *public areas and infrastructure topology* only. Timezone
is treated as environmental metadata, never as an identity signal.

DESIGN
------
Async- and stdlib-first, layered on the ``osint`` framework's HTTP backbone
(shared rate limiting / retry / request budget). Third-party packages are
optional: the pure core — the coordinate math, the model layer, the offline
gazetteer/geocoder, distance/proximity/clustering, GeoJSON and the reports — runs
and is fully tested with zero third-party dependencies. Network clients
(OpenStreetMap/Nominatim, Wikidata, GeoNames, RDAP, IP/ASN providers, satellite
catalogs) activate when ``httpx`` is present and degrade gracefully offline.

QUICK START
-----------
    from geo_osint.models import Coordinate, geodesic_km
    from geo_osint.geocoding import CoordinateNormalizer

    norm = CoordinateNormalizer()
    coord = norm.parse("13°45'22.7\\"N 100°30'06.5\\"E")
    print(coord.to_plus_code(), coord.to_mgrs())
"""

from __future__ import annotations

from . import models
from .models import (
    Coordinate, GeoObservation, ObservationSet, LocationType,
    Evidence, EvidenceLedger, ResolvedLocation, BoundingBox, Geofence,
    Airport, City, Country, Facility, geodesic_km, haversine_km,
)
from .configuration import GeoConfig, GeoMode, GeoLimits
from .engine import GeoOSINTEngine, GeoResult, TargetKind
from .pipeline import GeoPipeline, PipelineResult
from .orchestrator import GeoOrchestrator, OrchestrationResult
from .scoring import GeoFootprintScorer, FootprintScore

__version__ = "1.0.0"

__all__ = [
    "models",
    "Coordinate", "GeoObservation", "ObservationSet", "LocationType",
    "Evidence", "EvidenceLedger", "ResolvedLocation", "BoundingBox", "Geofence",
    "Airport", "City", "Country", "Facility", "geodesic_km", "haversine_km",
    "GeoConfig", "GeoMode", "GeoLimits",
    "GeoOSINTEngine", "GeoResult", "TargetKind",
    "GeoPipeline", "PipelineResult",
    "GeoOrchestrator", "OrchestrationResult",
    "GeoFootprintScorer", "FootprintScore",
    "__version__",
]
