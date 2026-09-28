# Airport Engine

Module: `geo_osint/airports/` (spec §5–6, §31).

Geo-OSINT is the **primary consumer** of the repository's existing `airports.py`
Google-Drive/JSON database. This engine wraps it — *reusing* its streaming search
and normalisation, never duplicating them — and returns typed
`geo_osint.models.airport.Airport` objects with the geospatial operations the spec
requires.

## Capabilities

| Operation | Method | Notes |
|-----------|--------|-------|
| IATA lookup | `AirportEngine.by_iata` | streaming search |
| ICAO lookup | `AirportEngine.by_icao` | streaming search |
| name / city / country | `search`, `by_city`, `by_country` | |
| coordinates, elevation, timezone | typed on `Airport` | |
| nearest airports to a point | `nearest` | bounded scan |
| airport ↔ airport distance | `distance_km` | geodesic |
| geographic clusters | `cluster` | single-link within radius |
| runway metadata | `RunwayEngine.summarize` | longest/paved/lit/surfaces |
| timezone | `AirportTimezoneEngine.resolve` | database → coordinate → country |
| country aggregation | `CountryAirportsEngine.for_country` | counts, hubs, bbox |
| relationship graph | `AirlineGraphEngine.build` | same-city/country/tz/airline edges |

## Streaming (spec §5)

Lookups delegate to `airports.search_stream`, which streams the JSON database.
Whole-DB scans (nearest / cluster / country aggregation) use
`airports._stream_normalized` — a single generator pass — and are bounded by the
engine's `scan_limit`, so a very large database never fans out unbounded and is
never fully downloaded.

## Aviation GEOINT (spec §6)

`geo_osint.transport.aviation_engine.AviationEngine` is the facade over the airport
engine (airport/heliport/seaplane-base lookup, profiles, nearest). It collects
PUBLIC information only and **never** ingests live aircraft surveillance —
`collects_live_surveillance` is always `False` and there is no ADS-B/flight-tracking
code path.

## Example

```python
from geo_osint.airports import AirportEngine
e = AirportEngine()
bkk = e.by_iata("BKK")
print(bkk.city, bkk.coordinate.to_dms())
print(e.distance_km("BKK", "NRT"), "km")
for ap, km in e.nearest(bkk.coordinate, limit=5):
    print(ap.code, km)
```
