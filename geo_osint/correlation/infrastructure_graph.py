"""
geo_osint.correlation.infrastructure_graph — the geographic relationship graph.

Builds a typed node/edge graph tying entities to the places and public
infrastructure they touch: ``entity --located_in--> country``,
``entity --located_in--> city``, ``facility --in--> country``,
``a --near--> b`` (within a radius), ``entity --hosts_on--> asn``. It is the
structure the visualization layer and the geographic-pivoting logic walk. Pure
stdlib adjacency (no networkx dependency); exports the node/edge JSON shape shared
with the airport graph and the report layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ..models.coordinate import Coordinate
from ..models.infrastructure import Facility
from ..models.observation import GeoObservation


@dataclass
class GraphNode:
    node_id: str
    kind: str                    # entity | country | city | facility | asn | domain | airport
    label: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.node_id, "kind": self.kind, "label": self.label or self.node_id,
                "lat": self.latitude, "lon": self.longitude, **({"meta": self.metadata} if self.metadata else {})}


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str
    weight: float = 1.0

    def key(self) -> Tuple[str, str, str]:
        return (self.source, self.target, self.relation)

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "target": self.target,
                "relation": self.relation, "weight": round(self.weight, 4)}


class InfrastructureGraph:
    def __init__(self) -> None:
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[Tuple[str, str, str], GraphEdge] = {}

    # -- mutation ----------------------------------------------------------
    def add_node(self, node: GraphNode) -> GraphNode:
        existing = self._nodes.get(node.node_id)
        if existing is None:
            self._nodes[node.node_id] = node
            return node
        if node.latitude is not None and existing.latitude is None:
            existing.latitude, existing.longitude = node.latitude, node.longitude
        return existing

    def add_edge(self, source: str, target: str, relation: str,
                 weight: float = 1.0) -> None:
        if source == target:
            return
        key = (source, target, relation)
        edge = self._edges.get(key)
        if edge is None:
            self._edges[key] = GraphEdge(source, target, relation, weight)
        else:
            edge.weight += weight

    # -- construction ------------------------------------------------------
    def add_observation(self, obs: GeoObservation) -> None:
        entity = self.add_node(GraphNode(obs.entity_id, "entity", obs.entity_id))
        if obs.coordinate is not None and entity.latitude is None \
                and obs.location_type.value in ("coordinate", "ip_geo"):
            entity.latitude, entity.longitude = obs.coordinate.latitude, obs.coordinate.longitude
        if obs.country_code:
            self.add_node(GraphNode(f"country:{obs.country_code}", "country",
                                    obs.country_code))
            self.add_edge(obs.entity_id, f"country:{obs.country_code}",
                          "located_in", obs.confidence)
        if obs.city:
            cid = f"city:{obs.city}|{obs.country_code}"
            lat = obs.coordinate.latitude if obs.coordinate else None
            lon = obs.coordinate.longitude if obs.coordinate else None
            self.add_node(GraphNode(cid, "city", obs.city, lat, lon))
            self.add_edge(obs.entity_id, cid, "located_in", obs.confidence)
        asn = obs.metadata.get("asn")
        if asn:
            self.add_node(GraphNode(f"asn:AS{asn}", "asn", f"AS{asn}"))
            self.add_edge(obs.entity_id, f"asn:AS{asn}", "hosts_on", obs.confidence)

    def add_facility(self, facility: Facility) -> None:
        fid = f"facility:{facility.name}"
        lat = facility.coordinate.latitude if facility.coordinate else None
        lon = facility.coordinate.longitude if facility.coordinate else None
        self.add_node(GraphNode(fid, "facility", facility.name, lat, lon,
                                {"type": facility.facility_type.value}))
        if facility.country_code:
            self.add_node(GraphNode(f"country:{facility.country_code}", "country",
                                    facility.country_code))
            self.add_edge(fid, f"country:{facility.country_code}", "in")
        for asn in facility.asn_refs:
            self.add_node(GraphNode(f"asn:AS{asn}", "asn", f"AS{asn}"))
            self.add_edge(fid, f"asn:AS{asn}", "references")

    def link_proximity(self, radius_km: float = 25.0) -> int:
        """Add ``near`` edges between placed nodes within ``radius_km``."""
        placed = [(nid, n) for nid, n in self._nodes.items()
                  if n.latitude is not None and n.longitude is not None]
        added = 0
        for (aid, a), (bid, b) in combinations(placed, 2):
            d = Coordinate(a.latitude, a.longitude).distance_km(
                Coordinate(b.latitude, b.longitude), method="haversine")
            if d <= radius_km:
                self.add_edge(aid, bid, "near", weight=1.0 / (1.0 + d))
                added += 1
        return added

    # -- access ------------------------------------------------------------
    @property
    def nodes(self) -> List[GraphNode]:
        return list(self._nodes.values())

    @property
    def edges(self) -> List[GraphEdge]:
        return list(self._edges.values())

    def neighbors(self, node_id: str) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        for (s, t, r) in self._edges:
            if s == node_id:
                out.append((t, r))
            elif t == node_id:
                out.append((s, r))
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {"nodes": [n.to_dict() for n in self._nodes.values()],
                "edges": [e.to_dict() for e in self._edges.values()],
                "node_count": len(self._nodes), "edge_count": len(self._edges)}
