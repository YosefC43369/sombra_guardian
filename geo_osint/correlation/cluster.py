"""
geo_osint.correlation.cluster — geographic clustering of observations (spec §27).

A dependency-free **DBSCAN** on the sphere (Haversine metric, ``eps`` in
kilometres) is the primary algorithm: it needs no cluster count up front, finds
arbitrarily-shaped clusters and labels sparse points as noise — exactly right for
"where does this entity's public infrastructure concentrate?". A simple k-means
(Lloyd's algorithm, great-circle assignment) is offered as an optional secondary
when a fixed number of centres is wanted. Both operate on anything exposing a
``.coordinate`` (observations, facilities, airports, cities) via an accessor.

numpy/scikit-learn are intentionally *not* required; the implementations are the
standard published algorithms in pure stdlib so the whole module is unit-testable.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ..models.coordinate import Coordinate, haversine_km

NOISE = -1


def _default_accessor(item: Any) -> Optional[Coordinate]:
    if isinstance(item, Coordinate):
        return item
    return getattr(item, "coordinate", None)


@dataclass
class Cluster:
    label: int
    members: List[Any] = field(default_factory=list)
    centroid: Optional[Coordinate] = None

    @property
    def size(self) -> int:
        return len(self.members)

    def to_dict(self) -> Dict[str, Any]:
        return {"label": self.label, "size": self.size,
                "centroid": self.centroid.to_dict() if self.centroid else None}


@dataclass
class ClusterResult:
    clusters: List[Cluster]
    noise: List[Any]
    algorithm: str
    params: Dict[str, Any]

    @property
    def cluster_count(self) -> int:
        return len(self.clusters)

    def to_dict(self) -> Dict[str, Any]:
        return {"algorithm": self.algorithm, "params": self.params,
                "cluster_count": self.cluster_count,
                "noise_count": len(self.noise),
                "clusters": [c.to_dict() for c in self.clusters]}


class ClusterEngine:
    def __init__(self, accessor: Callable[[Any], Optional[Coordinate]] = _default_accessor) -> None:
        self._coord = accessor

    # -- DBSCAN ------------------------------------------------------------
    def dbscan(self, items: Sequence[Any], eps_km: float = 50.0,
               min_samples: int = 3) -> ClusterResult:
        pts: List[Tuple[Any, Coordinate]] = [
            (it, c) for it in items if (c := self._coord(it)) is not None]
        n = len(pts)
        labels = [None] * n            # None=unvisited, NOISE, or cluster id
        cluster_id = -1

        def region_query(i: int) -> List[int]:
            ci = pts[i][1]
            out = []
            for j in range(n):
                if i == j:
                    continue
                if haversine_km(ci.latitude, ci.longitude,
                                pts[j][1].latitude, pts[j][1].longitude) <= eps_km:
                    out.append(j)
            return out

        for i in range(n):
            if labels[i] is not None:
                continue
            neighbors = region_query(i)
            if len(neighbors) < min_samples - 1:
                labels[i] = NOISE
                continue
            cluster_id += 1
            labels[i] = cluster_id
            seeds = list(neighbors)
            k = 0
            while k < len(seeds):
                j = seeds[k]
                if labels[j] == NOISE:
                    labels[j] = cluster_id
                elif labels[j] is None:
                    labels[j] = cluster_id
                    jn = region_query(j)
                    if len(jn) >= min_samples - 1:
                        seeds.extend(x for x in jn if x not in seeds)
                k += 1

        return self._assemble(pts, labels, "dbscan",
                              {"eps_km": eps_km, "min_samples": min_samples})

    # -- k-means (optional) ------------------------------------------------
    def kmeans(self, items: Sequence[Any], k: int = 3,
               iterations: int = 50, seed: int = 42) -> ClusterResult:
        pts: List[Tuple[Any, Coordinate]] = [
            (it, c) for it in items if (c := self._coord(it)) is not None]
        if not pts:
            return ClusterResult([], [], "kmeans", {"k": k})
        k = max(1, min(k, len(pts)))
        rnd = random.Random(seed)
        centers = [pts[i][1] for i in rnd.sample(range(len(pts)), k)]
        assignment = [0] * len(pts)
        for _ in range(iterations):
            changed = False
            for idx, (_, c) in enumerate(pts):
                best, best_d = 0, float("inf")
                for ci, center in enumerate(centers):
                    d = haversine_km(c.latitude, c.longitude,
                                     center.latitude, center.longitude)
                    if d < best_d:
                        best_d, best = d, ci
                if assignment[idx] != best:
                    assignment[idx] = best
                    changed = True
            for ci in range(k):
                members = [pts[i][1] for i in range(len(pts)) if assignment[i] == ci]
                if members:
                    centers[ci] = _centroid(members)
            if not changed:
                break
        return self._assemble(pts, assignment, "kmeans", {"k": k})

    # -- helpers -----------------------------------------------------------
    def _assemble(self, pts, labels, algo, params) -> ClusterResult:
        buckets: Dict[int, List[Any]] = {}
        coords: Dict[int, List[Coordinate]] = {}
        noise: List[Any] = []
        for (item, coord), label in zip(pts, labels):
            if label is None or label == NOISE:
                noise.append(item)
                continue
            buckets.setdefault(label, []).append(item)
            coords.setdefault(label, []).append(coord)
        clusters = [Cluster(label=lbl, members=buckets[lbl],
                            centroid=_centroid(coords[lbl]))
                    for lbl in sorted(buckets)]
        clusters.sort(key=lambda c: c.size, reverse=True)
        return ClusterResult(clusters, noise, algo, params)


def _centroid(coords: List[Coordinate]) -> Optional[Coordinate]:
    """Spherical mean of coordinates (correct across the antimeridian)."""
    if not coords:
        return None
    x = y = z = 0.0
    for c in coords:
        lat, lon = math.radians(c.latitude), math.radians(c.longitude)
        x += math.cos(lat) * math.cos(lon)
        y += math.cos(lat) * math.sin(lon)
        z += math.sin(lat)
    n = len(coords)
    x, y, z = x / n, y / n, z / n
    lon = math.atan2(y, x)
    hyp = math.sqrt(x * x + y * y)
    lat = math.atan2(z, hyp)
    return Coordinate(math.degrees(lat), math.degrees(lon), source="centroid")
