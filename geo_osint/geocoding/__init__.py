"""
geo_osint.geocoding — the geocoding subsystem (spec §2–4, §33–35).

Offline-first, dependency-free geocoding built on the curated gazetteer and the
WGS84 coordinate core, with optional online refinement:

  * :class:`CoordinateNormalizer` — every coordinate format -> WGS84 (§4);
  * :class:`Geocoder` — name/token -> location (§2);
  * :class:`ReverseGeocoder` — coordinate -> structured location (§3);
  * :class:`TimezoneResolver` — point/place -> IANA timezone, with method (§32);
  * :class:`PlaceResolver` — unified resolution + multilingual/historical alias
    engine (§33–35).
"""

from .coordinate_normalizer import CoordinateNormalizer, NormalizationResult
from .timezone_resolver import TimezoneResolver, TimezoneResult
from .geocoder import Geocoder
from .reverse_geocoder import ReverseGeocoder
from .place_resolver import PlaceResolver, PlaceMatch

__all__ = [
    "CoordinateNormalizer", "NormalizationResult",
    "TimezoneResolver", "TimezoneResult",
    "Geocoder", "ReverseGeocoder",
    "PlaceResolver", "PlaceMatch",
]
