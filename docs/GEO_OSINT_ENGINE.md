# Geo-OSINT Engine

Module: `geo_osint/` (spec §1–54).

A geospatial-intelligence (GEOINT) subsystem built **entirely from publicly
available information**. Given an entity — an organization, domain, IP, ASN,
website, airport, port, city, country or a raw coordinate — it discovers,
normalises, correlates, indexes, analyses and visualises the *publicly observable*
geographic information about it, and renders an evidence-backed report.

It reuses the repository's existing `airports.py` database, the `osint` HTTP
backbone, and integrates its output with Entity Fusion, Behavioral Intelligence and
Web Footprint.

## Posture — 80% red team / 20% blue team

Primarily a **passive geospatial reconnaissance** capability for authorized
red-team engagements: public-infrastructure mapping, the geographic attack surface,
facility/cloud-region/ASN/IP geolocation, aviation and transport intelligence,
geographic pivoting and correlation. A smaller defensive companion reuses the same
passive output for asset inventory, incident/IOC location enrichment, monitoring
(the scheduler) and defensive geographic reporting.

## Hard privacy line (enforced in code — spec §50)

The engine analyses ONLY public, observable geographic information. It implements
**none** of the following — there is no code path and no input for any of them:

* live device / GPS / cell-tower / Wi-Fi / Bluetooth location collection;
* real-time tracking of individuals or geofencing of people;
* access to private-account location history;
* inference of a specific private individual's precise residence;
* permission bypass or private-map-API abuse.

Coordinates are **never invented**: every one carries explicit precision and cites
a verifiable public source (`geo_osint.models.evidence`). Geofencing and routing
operate over *public areas and infrastructure topology* only. Timezone is
environmental metadata, never an identity signal (spec §32). Shared geography is a
weak co-location signal and **never** merges identities (spec §47).

## Run modes (`geo_osint.configuration`)

| Mode | Network | What runs |
|------|---------|-----------|
| `LOCAL` | none | offline gazetteer, coordinate math, curated datasets, airports DB |
| `PASSIVE` | public sources | + Nominatim / Wikidata / GeoNames / RDAP / IP-ASN providers |
| `DEEP` | public sources | + recursive public pivots + cross-source correlation |

No mode ever unlocks a private or active capability — only more *public* breadth.
`GeoLimits` bounds every run (request budget, wall-clock cap, entity/observation
caps, proximity radius, polite per-host rate).

## Architecture

```
geo_osint/
  configuration.py   run modes + hard limits
  engine.py          classify entity -> run subsystems -> GeoResult
  pipeline.py        + proximity enrichment, multi-entity correlation
  orchestrator.py    concurrent multi-entity runs
  scheduler.py       blue-team monitoring re-runs
  scoring.py         explainable geographic-footprint score (NOT a risk score)
  models/            Coordinate (WGS84 core), Evidence, GeoObservation, ...
  data/              curated public-domain gazetteer (countries, cities, cloud, ports)
  geocoding/         normalizer, forward/reverse geocoder, timezone, place/alias
  airports/          typed access over airports.py + runway/tz/country/graph
  infrastructure/    cloud regions, data centres/IXP, facilities, gov, telecom, cables
  transport/         seaports, aviation, road/rail/transit (OSM)
  satellite/         Sentinel/Landsat (STAC) + NASA CMR metadata (no imagery)
  correlation/       distance, cluster (DBSCAN), proximity, timeline,
                     ip/asn/domain geolocation, entity correlation, infra graph
  maps/              OSM/Nominatim, Wikidata, GeoNames, Natural Earth, admin bounds
  visualization/     GeoJSON, map (Leaflet), clusters, heatmaps, timelines
  storage/           grid index, SQLite R*Tree store, disk cache
  reports/           JSON / Markdown / HTML / CSV
  telegram/          14 commands + callbacks + keyboards
  tests/             110 offline unit tests
```

## Data flow

1. **Classify** the entity (`coordinate | ip | asn | domain | airport | country |
   place`).
2. **Local stage** (always): resolve via the offline gazetteer / coordinate math /
   airports DB into evidence-backed `GeoObservation`s.
3. **Network stage** (PASSIVE/DEEP): add public-source enrichment; every path
   degrades gracefully so a run always returns a result.
4. **Finalize**: entity↔geography profile (noisy-OR over independent sources),
   timeline, infrastructure graph, DBSCAN clusters, footprint score.
5. **Pipeline enrichment**: attach nearest public airports / cloud regions /
   seaports as additional observations.
6. **Report**: assemble the ten-section report; render JSON/Markdown/HTML/CSV.

## Quick start

```python
from geo_osint import GeoPipeline, GeoConfig, GeoMode
from geo_osint.reports import GeoReportBuilder, html_report

pipe = GeoPipeline(GeoConfig.build(GeoMode.LOCAL))   # fully offline
pres = pipe.run_sync("Bangkok")
report = GeoReportBuilder().build(pres.result, pres.proximity)
html_report.write(report, "bangkok.html")
```

```python
import asyncio
from geo_osint import GeoOSINTEngine, GeoConfig, GeoMode

engine = GeoOSINTEngine(GeoConfig.build(GeoMode.PASSIVE))   # + public sources
result = asyncio.run(engine.investigate("8.8.8.8"))
print(result.footprint_score)          # explainable; NOT a risk score
```

## Evidence & confidence (spec §43)

Every geographic conclusion carries `Evidence` (source, URL, timestamp,
confidence, precision, **limitations**). Confidence over independent sources is
combined with **noisy-OR** (`1 - Π(1 - cᵢ)`), so corroboration raises confidence
and never averages it away. The `Limitations` field is where the meaning of a weak
signal is written down — e.g. "IP geolocation is a provider estimate, not a device
location" — and it is carried into every report.

## Integration

* **Entity Fusion** — geo observations are corroborating evidence; `shared_geography`
  is `merge_safe=False` by construction (spec §47).
* **Behavioral Intelligence** — the timeline/timeline-map feed temporal
  visualisation; no behavioural inference is drawn from location alone (spec §48).
* **Web Footprint** — domains/IPs/ASNs/websites it discovers are geolocated here.

## Tests

```
python -m unittest discover -s geo_osint/tests -v      # 110 tests, offline
```

See also: `AIRPORT_ENGINE.md`, `GEOCODING_ENGINE.md`, `INFRASTRUCTURE_ENGINE.md`,
`ASN_GEOLOCATION.md`, `MAP_VISUALIZATION.md`, `CHANGELOG_GEO_v1.md`.
