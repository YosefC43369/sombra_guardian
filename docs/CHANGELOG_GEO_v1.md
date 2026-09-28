# Changelog — Geo-OSINT Engine v1.0

First release of the Geo-OSINT (GEOINT) subsystem (`geo_osint/`). Public data only;
passive; 80% red team / 20% blue team. 110 offline unit tests; no existing repo
files modified.

## Added

### Core
- **WGS84 coordinate primitive** with dependency-free format conversion: Decimal
  Degrees, DMS, UTM, MGRS, Open Location Code, WKT, GeoJSON; geodesic (Vincenty) and
  Haversine distance, bearing, destination. Explicit, never-invented precision.
- **Universal model layer**: `Evidence`/`EvidenceLedger` (noisy-OR), the
  `GeoObservation` schema + `ObservationSet`, `ResolvedLocation`, `Geofence`/
  `BoundingBox` (point-in-polygon), `Route`, `Airport`, `City`, `Country`,
  `Facility`/`DataCenter`/`CloudRegion`/`InternetExchange`/`SubmarineCable`.

### Data (curated public-domain)
- 123-country table (ISO/capital/calling/currency/TLD/centroid/neighbours).
- 189-place gazetteer (capitals + metros) with IANA timezones and multilingual/
  historical aliases.
- 108 cloud-region locations across 8 providers; 30 major seaports.

### Subsystems
- **Geocoding**: coordinate normalizer, forward/reverse geocoders, layered timezone
  resolver, unified place resolver + alias engine (offline-first, optional online).
- **Airports**: typed access over `airports.py` (streaming), runway/timezone/country
  aggregation, airport relationship graph.
- **Correlation**: distance, DBSCAN + k-means clustering, proximity, timeline with
  location-change detection, IP/ASN/domain geolocation, entity↔geography correlation
  (with the §47 anti-merge safeguard), infrastructure graph.
- **Infrastructure**: cloud regions, PeeringDB data centres/IXPs, OSM facilities,
  government, telecom, submarine cables.
- **Transport**: seaports, aviation facade, OSM road/rail/transit.
- **Satellite**: Sentinel/Landsat (STAC) + NASA CMR metadata (metadata only).
- **Maps**: Nominatim, Wikidata, GeoNames, Natural Earth, admin boundaries.
- **Visualization**: GeoJSON, Leaflet maps, cluster/heatmap/timeline builders.
- **Storage**: grid spatial index, SQLite R*Tree store, TTL disk cache.
- **Reports**: JSON / Markdown / HTML / CSV with all ten spec sections.
- **Telegram**: 14 commands + callbacks + keyboards.
- **Engine / pipeline / orchestrator / scheduler** and the explainable
  geographic-footprint score (explicitly **not** a risk score).

## Privacy & safety
- No live/GPS/device/cell/Wi-Fi/Bluetooth location; no individual tracking or
  geofencing; no private-account access; no residence inference; no map-API abuse —
  enforced by construction (no code path or input exists).
- Every coordinate carries precision and cites a public source; every conclusion is
  evidence-backed with explicit limitations; a Limitations section is always present
  in reports.

## Integration
- Entity Fusion (geo as corroborating, never merging, evidence), Behavioral
  Intelligence (timeline visualisation, no inference from location alone), Web
  Footprint (geolocation of discovered domains/IPs/ASNs).

## Notes
- Third-party packages are optional; the pure core runs and is fully tested with
  zero third-party dependencies. Network clients degrade gracefully offline.
