# Infrastructure Engine

Module: `geo_osint/infrastructure/` (spec §9–13, §36–40).

Public physical-infrastructure intelligence. **Public datasets only; no
private-infrastructure discovery; no internal layouts are inferred** (spec §10, §38).

## Engines

| Engine | Spec | Source | Notes |
|--------|------|--------|-------|
| `CloudRegionEngine` | §11 | provider docs | 108 curated region locations across AWS/GCP/Azure/Oracle/Cloudflare/DigitalOcean/Linode/Vultr; nearest, by-provider/country/city, coverage |
| `DataCenterEngine` | §10, §37 | PeeringDB | data-centre facilities & IXPs (name/operator/city/country/coords, ASN refs) |
| `FacilityEngine` | §9 | OSM / injected | generic public facilities; offline registry + spatial index; read-only Overpass query builder |
| `GovernmentFacilityEngine` | §39 | OSM / injected | publicly-listed government buildings only |
| `TelecomInfrastructureEngine` | §38 | OSM / injected | public telecom metadata only |
| `SubmarineCableEngine` | §36 | curated / public | cable systems, operators, landing countries |

## Cloud region mapping (§11)

Cloud providers publish region locations in their own documentation. The dataset
(`geo_osint.data.cloud_regions`) encodes those published metropolitan areas at
**city precision** — a region spans multiple undisclosed physical data centres, so a
region coordinate is never a rooftop fix, and observations carry that limitation.

```python
from geo_osint.infrastructure import CloudRegionEngine
from geo_osint.models import Coordinate
e = CloudRegionEngine()
print(e.by_code("ap-southeast-1").city)              # Singapore
for r, km in e.nearest(Coordinate(13.75, 100.52), 3):
    print(r.provider, r.region_code, r.city, km)
```

## Data centres & IXPs (§10, §37)

Consumes PeeringDB (`/api/fac`, `/api/ix`) — the community, publicly-queryable
registry. Pure parsers (`parse_peeringdb_fac`, `parse_peeringdb_ix`) are
offline-testable; the network layer is bounded and cached, no credentials.

## Facilities via OpenStreetMap (§9, §39–40)

`FacilityEngine.build_overpass_query` builds a single bounded, read-only Overpass
query for a category's public OSM tags; `parse_overpass` turns results into
`Facility` records. OSM usage policy is respected — one bounded query of
already-public map data, attribution recorded, no bulk scraping.

## Submarine cables (§36)

Seeded with real systems (name, operating consortium, landing countries). Landing
**coordinates** are attached only for landing cities present in the gazetteer as
real coastal points; unverifiable landings are recorded with country and no
coordinate rather than an invented one.
