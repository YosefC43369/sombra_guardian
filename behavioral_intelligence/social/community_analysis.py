"""
behavioral_intelligence.social.community_analysis — community detection on the
public interaction graph (spec §23).

Three algorithms over the undirected projection of the interaction edges:

  * connected_components — pure-stdlib union-find; the always-available baseline.
  * label_propagation — pure-stdlib near-linear community detection.
  * louvain — modularity optimisation via ``networkx`` when it is installed;
    falls back to label propagation with a recorded note when it is not.

Communities are only reported when the graph clears minimum-sample thresholds
(too small a graph produces meaningless partitions). Each community reports its
members, internal/external edge counts, density and a sample-size-aware
confidence. Membership is a structural grouping of interaction, never a claimed
real-world affiliation.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from ..models.behavior import InteractionEdge
from .. import util

try:
    import networkx as nx
    HAVE_NETWORKX = True
except Exception:  # pragma: no cover
    nx = None
    HAVE_NETWORKX = False

MIN_NODES = 4
MIN_EDGES = 4


@dataclass
class CommunityResult:
    algorithm: str = ""
    communities: List[Dict[str, object]] = field(default_factory=list)
    modularity: Optional[float] = None
    node_count: int = 0
    edge_count: int = 0
    note: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {"algorithm": self.algorithm, "communities": self.communities,
                "modularity": (round(self.modularity, 3)
                               if self.modularity is not None else None),
                "node_count": self.node_count, "edge_count": self.edge_count,
                "note": self.note}


def _undirected(edges: Sequence[InteractionEdge]
                ) -> Tuple[Set[str], Dict[str, Set[str]], Dict[frozenset, int]]:
    nodes: Set[str] = set()
    adj: Dict[str, Set[str]] = defaultdict(set)
    weight: Dict[frozenset, int] = defaultdict(int)
    for e in edges:
        if not e.source or not e.target or e.source == e.target:
            continue
        nodes.add(e.source)
        nodes.add(e.target)
        adj[e.source].add(e.target)
        adj[e.target].add(e.source)
        weight[frozenset((e.source, e.target))] += e.count
    return nodes, adj, weight


def connected_components(edges: Sequence[InteractionEdge]) -> List[Set[str]]:
    nodes, adj, _ = _undirected(edges)
    parent: Dict[str, str] = {n: n for n in nodes}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for n in nodes:
        for m in adj[n]:
            ra, rb = find(n), find(m)
            if ra != rb:
                parent[ra] = rb

    groups: Dict[str, Set[str]] = defaultdict(set)
    for n in nodes:
        groups[find(n)].add(n)
    return list(groups.values())


def label_propagation(edges: Sequence[InteractionEdge], *, max_iter: int = 50
                      ) -> List[Set[str]]:
    nodes, adj, _ = _undirected(edges)
    labels: Dict[str, str] = {n: n for n in nodes}
    ordered = sorted(nodes)
    for _ in range(max_iter):
        changed = False
        for n in ordered:
            if not adj[n]:
                continue
            counts: Dict[str, int] = defaultdict(int)
            for m in adj[n]:
                counts[labels[m]] += 1
            if not counts:
                continue
            # deterministic tie-break: highest count, then lexicographically
            best = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
            if labels[n] != best:
                labels[n] = best
                changed = True
        if not changed:
            break
    groups: Dict[str, Set[str]] = defaultdict(set)
    for n, lab in labels.items():
        groups[lab].add(n)
    return list(groups.values())


def _describe(communities: List[Set[str]], adj: Dict[str, Set[str]]
              ) -> List[Dict[str, object]]:
    node_comm: Dict[str, int] = {}
    for cid, members in enumerate(communities):
        for m in members:
            node_comm[m] = cid
    out: List[Dict[str, object]] = []
    for cid, members in enumerate(communities):
        if len(members) < 2:
            continue
        internal = external = 0
        for n in members:
            for m in adj[n]:
                if node_comm.get(m) == cid:
                    internal += 1
                else:
                    external += 1
        internal //= 2   # each internal edge counted twice
        possible = len(members) * (len(members) - 1) / 2
        density = util.safe_div(internal, possible)
        out.append({
            "community_id": cid,
            "size": len(members),
            "members": sorted(members)[:50],
            "internal_edges": internal,
            "external_edges": external,
            "density": round(density, 3),
            "confidence": round(1.0 - 1.0 / len(members), 3),
        })
    out.sort(key=lambda d: d["size"], reverse=True)  # type: ignore[arg-type,return-value]
    return out


def detect_communities(edges: Sequence[InteractionEdge], *,
                       algorithm: str = "louvain") -> CommunityResult:
    nodes, adj, weight = _undirected(edges)
    result = CommunityResult(algorithm=algorithm, node_count=len(nodes),
                             edge_count=len(weight))
    if len(nodes) < MIN_NODES or len(weight) < MIN_EDGES:
        result.note = (f"graph too small for community detection "
                       f"(need ≥{MIN_NODES} nodes and ≥{MIN_EDGES} edges)")
        return result

    if algorithm == "connected_components":
        comms = connected_components(edges)
    elif algorithm == "label_propagation":
        comms = label_propagation(edges)
    elif algorithm == "louvain":
        if HAVE_NETWORKX:
            g = nx.Graph()
            for fs, w in weight.items():
                a, b = tuple(fs)
                g.add_edge(a, b, weight=w)
            try:
                partition = nx.community.louvain_communities(g, weight="weight",
                                                             seed=42)
                comms = [set(c) for c in partition]
                result.modularity = nx.community.modularity(g, partition,
                                                            weight="weight")
            except Exception:
                comms = label_propagation(edges)
                result.note = "louvain unavailable in networkx build; used label propagation"
        else:
            comms = label_propagation(edges)
            result.note = "networkx not installed; used label propagation fallback"
            result.algorithm = "label_propagation"
    else:
        comms = connected_components(edges)
        result.algorithm = "connected_components"

    result.communities = _describe(comms, adj)
    return result
