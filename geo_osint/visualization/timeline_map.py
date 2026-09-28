"""
geo_osint.visualization.timeline_map — time-tagged geographic features (spec §24, §28).

Renders a geographic timeline as GeoJSON where each Feature carries a ``time``
property (and start/end where known), suitable for a time-slider map control, plus
an ordered LineString connecting the placed events in time order (the "path" of
public references over time). This is a visualisation of *observations about
places over time*, never a movement track of a person (spec §48).
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Sequence

from ..models.observation import GeoObservation
from .geojson_builder import GeoJSONBuilder


class TimelineMapBuilder:
    def __init__(self) -> None:
        self._geojson = GeoJSONBuilder()

    def features(self, observations: Sequence[GeoObservation]) -> Dict[str, Any]:
        feats: List[Dict[str, Any]] = []
        for obs in sorted(observations, key=lambda o: o.first_seen or o.observation_timestamp):
            if not obs.coordinate:
                continue
            ts = obs.first_seen or obs.observation_timestamp
            feat = obs.to_geojson_feature()
            if feat is None:
                continue
            feat["properties"]["time"] = _iso(ts)
            feat["properties"]["timestamp"] = ts
            if obs.last_seen and obs.last_seen != ts:
                feat["properties"]["end_time"] = _iso(obs.last_seen)
            feats.append(feat)
        return {"type": "FeatureCollection", "features": feats}

    def path(self, observations: Sequence[GeoObservation]) -> Dict[str, Any]:
        placed = sorted([o for o in observations if o.coordinate],
                        key=lambda o: o.first_seen or o.observation_timestamp)
        coords = [[o.coordinate.longitude, o.coordinate.latitude] for o in placed]
        if len(coords) < 2:
            return {"type": "FeatureCollection", "features": []}
        return {"type": "FeatureCollection", "features": [{
            "type": "Feature",
            "geometry": {"type": "LineString", "coordinates": coords},
            "properties": {"role": "timeline_path", "points": len(coords),
                           "note": "chronological path of public references, "
                                   "not a movement track"}}]}


def _iso(ts: float) -> str:
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
    except (OSError, ValueError, OverflowError):
        return ""
