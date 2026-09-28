# Map Visualization

Module: `geo_osint/visualization/` (spec §23–24). All pure stdlib — no shapely/numpy.

## GeoJSON (§23)

`GeoJSONBuilder` is the output backbone. RFC 7946, longitude-first axis order,
closed rings. Supports `Point`, `LineString`, `Polygon`, `MultiPolygon`,
`FeatureCollection`; converts any model object exposing `to_geojson_feature()`
(observations, airports, cities, facilities, cables, routes, geofences). Streams
large collections (`stream_collection`) without buffering the whole document, and
validates structure (`is_valid`).

## Map builder (§24)

`MapBuilder` assembles a serialisable multi-layer **map spec** (markers, routes,
boundaries, clusters, heatmaps) that any GeoJSON-aware front-end renders, plus a
self-contained **Leaflet HTML** export (`to_html`) using the public Leaflet CDN and
OpenStreetMap tiles (attribution included, no bulk tile scraping). Auto-computes
viewport bounds/center.

## Clusters, heatmaps, timelines

* `ClusterMapBuilder` — renders a `ClusterResult` as centroids (sized by count),
  member points, convex hulls (pure Graham-scan) and noise.
* `HeatmapBuilder` — weighted-point list (`[lat, lon, weight]`) for a heat plugin,
  and a binned-grid GeoJSON aggregation with an intensity property. Weights default
  to observation confidence.
* `TimelineMapBuilder` — time-tagged features (`time`/`end_time` properties) for a
  time-slider, and a chronological path LineString. A visualisation of *observations
  about places over time*, never a movement track of a person (spec §48).

## Example

```python
from geo_osint.visualization import MapBuilder
from geo_osint.models import Airport, Coordinate

mb = MapBuilder()
mb.add_markers("airports", [Airport(iata="BKK", coordinate=Coordinate(13.68, 100.75))])
open("map.html", "w").write(mb.to_html("Airports"))
spec = mb.to_spec()          # or hand the JSON to any renderer
```

The report engine's HTML output embeds a Leaflet map of the run's infrastructure
GeoJSON automatically.
