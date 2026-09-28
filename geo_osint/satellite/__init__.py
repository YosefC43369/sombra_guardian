"""
geo_osint.satellite — public satellite metadata engines (spec §21-22).

Metadata-only access to public satellite catalogs — Sentinel-2 and Landsat via the
Element84 Earth Search STAC API, and NASA EarthData via the CMR granule API. Returns
:class:`SceneMetadata` (scene id, platform/sensor, capture date, cloud cover,
footprint, resolution) and a historical availability timeline. Imagery is NEVER
downloaded here; a caller may fetch a scene separately via its browse/asset URL
(spec §21).
"""

from .imagery_metadata import SceneMetadata, bbox_from_list
from .stac_base import STACClient
from .sentinel_catalog import SentinelCatalog
from .landsat_catalog import LandsatCatalog
from .nasa_catalog import NASACatalog

__all__ = [
    "SceneMetadata", "bbox_from_list", "STACClient",
    "SentinelCatalog", "LandsatCatalog", "NASACatalog",
]
