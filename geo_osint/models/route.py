"""
geo_osint.models.route — an ordered path across *public* infrastructure.

A :class:`Route` is a sequence of legs between named public locations — airports
on a public airline network, ports on a public shipping lane, stations on a rail
line. It is used to reason about connectivity ("is city A reachable from city B on
the public airport network?") and to render polylines on a map.

HARD LINE (spec §30, §50): a route is a static analysis of *public
infrastructure topology*. It is never a track of a person or vehicle in motion,
and the engine has no live-position input to build one from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .coordinate import Coordinate, geodesic_km


@dataclass
class RouteLeg:
    """One hop between two waypoints."""

    origin_id: str
    dest_id: str
    origin: Optional[Coordinate] = None
    dest: Optional[Coordinate] = None
    mode: str = "unknown"          # "air", "sea", "rail", "road"
    label: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def distance_km(self) -> Optional[float]:
        if self.origin and self.dest:
            return round(self.origin.distance_km(self.dest), 3)
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "origin_id": self.origin_id, "dest_id": self.dest_id,
            "mode": self.mode, "label": self.label,
            "distance_km": self.distance_km,
            "origin": self.origin.to_dict() if self.origin else None,
            "dest": self.dest.to_dict() if self.dest else None,
            "metadata": dict(self.metadata),
        }


@dataclass
class Route:
    """An ordered set of legs forming a path across public infrastructure."""

    name: str
    legs: List[RouteLeg] = field(default_factory=list)
    mode: str = "mixed"
    source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_leg(self, leg: RouteLeg) -> "Route":
        self.legs.append(leg)
        return self

    @property
    def total_distance_km(self) -> float:
        return round(sum(l.distance_km or 0.0 for l in self.legs), 3)

    @property
    def waypoint_ids(self) -> List[str]:
        ids: List[str] = []
        for leg in self.legs:
            if not ids or ids[-1] != leg.origin_id:
                ids.append(leg.origin_id)
            ids.append(leg.dest_id)
        return ids

    def to_geojson_feature(self) -> Dict[str, Any]:
        coords: List[List[float]] = []
        for leg in self.legs:
            if leg.origin:
                coords.append([leg.origin.longitude, leg.origin.latitude])
            if leg.dest:
                coords.append([leg.dest.longitude, leg.dest.latitude])
        return {
            "type": "Feature",
            "geometry": {"type": "LineString", "coordinates": coords},
            "properties": {"name": self.name, "mode": self.mode,
                           "total_distance_km": self.total_distance_km,
                           "hops": len(self.legs), "source": self.source},
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "mode": self.mode, "source": self.source,
            "total_distance_km": self.total_distance_km,
            "waypoint_ids": self.waypoint_ids,
            "legs": [l.to_dict() for l in self.legs],
            "metadata": dict(self.metadata),
        }
