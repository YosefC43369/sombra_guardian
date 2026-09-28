"""
geo_osint.models — the typed data layer of the Geo-OSINT engine.

Everything the engine discovers, correlates and renders is expressed with these
types. They are pure, serialisable dataclasses with no network or I/O
dependencies, so the whole model layer is unit-testable on its own.

  * :class:`Coordinate`     — WGS84 point + all format conversions (the core).
  * :class:`Evidence` / :class:`EvidenceLedger` — provenance for every claim.
  * :class:`GeoObservation` / :class:`ObservationSet` — the universal schema.
  * :class:`ResolvedLocation` — a consolidated place with admin hierarchy.
  * :class:`Geofence` / :class:`BoundingBox` — public-area geometry.
  * :class:`Route` / :class:`RouteLeg` — public-infrastructure paths.
  * :class:`Airport` / :class:`Runway` — aviation records.
  * :class:`City`, :class:`Country` — populated places and sovereign metadata.
  * :class:`Facility` and friends — public physical infrastructure.
"""

from .coordinate import (
    Coordinate, CoordinateParseError, UTMRef,
    haversine_km, geodesic_km, initial_bearing_deg, destination_point,
    parse_dms, format_dms, latlon_to_utm, utm_to_latlon,
    latlon_to_mgrs, mgrs_to_latlon, encode_plus_code, decode_plus_code,
    parse_wkt_point, WGS84_A, WGS84_F,
)
from .evidence import Evidence, EvidenceLedger, ConfidenceBand
from .observation import GeoObservation, ObservationSet, LocationType
from .location import ResolvedLocation, AdministrativeLevel
from .geofence import Geofence, BoundingBox
from .route import Route, RouteLeg
from .airport import Airport, Runway
from .city import City
from .country import Country
from .infrastructure import (
    Facility, FacilityType, DataCenter, CloudRegion, InternetExchange,
    SubmarineCable, CableLanding,
)

__all__ = [
    "Coordinate", "CoordinateParseError", "UTMRef",
    "haversine_km", "geodesic_km", "initial_bearing_deg", "destination_point",
    "parse_dms", "format_dms", "latlon_to_utm", "utm_to_latlon",
    "latlon_to_mgrs", "mgrs_to_latlon", "encode_plus_code", "decode_plus_code",
    "parse_wkt_point", "WGS84_A", "WGS84_F",
    "Evidence", "EvidenceLedger", "ConfidenceBand",
    "GeoObservation", "ObservationSet", "LocationType",
    "ResolvedLocation", "AdministrativeLevel",
    "Geofence", "BoundingBox",
    "Route", "RouteLeg",
    "Airport", "Runway",
    "City", "Country",
    "Facility", "FacilityType", "DataCenter", "CloudRegion",
    "InternetExchange", "SubmarineCable", "CableLanding",
]
