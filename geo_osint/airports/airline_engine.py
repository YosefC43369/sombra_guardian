"""
geo_osint.airports.airline_engine — airport relationship graph + public airline refs.

Builds the airport relationship graph the spec asks for (§31), with edges for:

  * **same_city** — airports sharing a city (e.g. BKK + DMK in Bangkok);
  * **same_country** — a coarse national grouping;
  * **same_timezone** — operational grouping;
  * **airline_ref** — when the database record carries public airline references
    in its metadata, airports sharing an airline are linked. No airline data is
    invented: the edge type simply does not appear when the source lacks it.

The graph is a plain adjacency structure (no third-party graph dependency); it
exports to the node/edge shape the visualization and correlation layers use.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Dict, Iterable, List, Set, Tuple

from ..models.airport import Airport


@dataclass
class AirportGraph:
    nodes: Dict[str, Airport] = field(default_factory=dict)
    edges: List[Tuple[str, str, str]] = field(default_factory=list)  # (a, b, type)

    def neighbors(self, code: str) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        for a, b, t in self.edges:
            if a == code:
                out.append((b, t))
            elif b == code:
                out.append((a, t))
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [{"id": code, "name": ap.name, "city": ap.city,
                       "country": ap.country,
                       "lat": ap.coordinate.latitude if ap.coordinate else None,
                       "lon": ap.coordinate.longitude if ap.coordinate else None}
                      for code, ap in self.nodes.items()],
            "edges": [{"source": a, "target": b, "type": t}
                      for a, b, t in self.edges],
        }


class AirlineGraphEngine:
    """Construct the airport relationship graph from a set of airports."""

    def build(self, airports: Iterable[Airport], *,
              same_city: bool = True, same_country: bool = False,
              same_timezone: bool = False, airline_refs: bool = True) -> AirportGraph:
        graph = AirportGraph()
        aps = [a for a in airports if a.code]
        for ap in aps:
            graph.nodes[ap.code] = ap
        seen: Set[Tuple[str, str, str]] = set()

        def link(a: str, b: str, t: str) -> None:
            key = (min(a, b), max(a, b), t)
            if a != b and key not in seen:
                seen.add(key)
                graph.edges.append((a, b, t))

        if same_city:
            self._group_link(aps, lambda a: (a.country, a.city.lower()) if a.city else None,
                             "same_city", link)
        if same_country:
            self._group_link(aps, lambda a: a.country or None, "same_country", link)
        if same_timezone:
            self._group_link(aps, lambda a: a.timezone or None, "same_timezone", link)
        if airline_refs:
            self._airline_link(aps, link)
        return graph

    @staticmethod
    def _group_link(aps: List[Airport], keyfn, edge_type: str, link) -> None:
        buckets: Dict[Any, List[str]] = {}
        for ap in aps:
            k = keyfn(ap)
            if k is not None:
                buckets.setdefault(k, []).append(ap.code)
        for codes in buckets.values():
            for a, b in combinations(sorted(set(codes)), 2):
                link(a, b, edge_type)

    @staticmethod
    def _airline_link(aps: List[Airport], link) -> None:
        by_airline: Dict[str, List[str]] = {}
        for ap in aps:
            refs = ap.metadata.get("airlines") or ap.metadata.get("airline_refs")
            if isinstance(refs, list):
                for airline in refs:
                    by_airline.setdefault(str(airline).lower(), []).append(ap.code)
        for codes in by_airline.values():
            for a, b in combinations(sorted(set(codes)), 2):
                link(a, b, "airline_ref")
