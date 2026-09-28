# Geocoding Engine

Module: `geo_osint/geocoding/` (spec §2–4, §32–35).

Offline-first, dependency-free geocoding built on the curated gazetteer
(`geo_osint.data`) and the WGS84 coordinate core, with optional online refinement.

## Components

* **`CoordinateNormalizer`** (§4) — every coordinate format → WGS84:
  Decimal Degrees, DMS, UTM, MGRS (parse/convert), Open Location Code (plus codes),
  WKT `POINT`, GeoJSON `Point`. Preserves and reports precision; never invents a
  value. `represent()` renders every form for a point.
* **`Geocoder`** (§2) — name/token → `ResolvedLocation`. Resolution order:
  coordinate → country token (ISO2/ISO3/name/TLD/calling code) → city/alias → fuzzy.
  Optional `OnlineGeocoder` (Nominatim) for misses.
* **`ReverseGeocoder`** (§3) — coordinate → structured location (nearest gazetteer
  place + country + timezone). Confidence falls off with distance; a mid-ocean point
  returns the nearest country at low confidence, never a fabricated address.
* **`TimezoneResolver`** (§32) — point/place → IANA timezone, layered
  gazetteer → country → longitude-offset, each answer stating its **method** so the
  report shows how precise it is. Timezone is environmental metadata only.
* **`PlaceResolver`** (§33–35) — unified resolution + the multilingual/historical
  **alias engine**: `canonicalize("Krung Thep") == "Bangkok"`,
  `canonicalize("Constantinople") == "Istanbul"`. `normalize_name` folds Latin
  diacritics while preserving Thai/CJK/Cyrillic/Arabic/Hebrew scripts.

## Precision honesty

The `Coordinate` primitive records `precision` (real decimal places) and derives
`precision_m`. A city centroid known to 0.01° never masquerades as a rooftop fix;
the reverse geocoder and evidence model both read this field.

## Example

```python
from geo_osint.geocoding import Geocoder, ReverseGeocoder, PlaceResolver
from geo_osint.models import Coordinate

g = Geocoder()
loc = g.geocode_offline("Bangkok")[0]           # -> ResolvedLocation
print(ReverseGeocoder().reverse_offline(Coordinate(13.70, 100.60)).display_name)
print(PlaceResolver(g).canonicalize("Saigon"))  # -> "Ho Chi Minh City"
```
