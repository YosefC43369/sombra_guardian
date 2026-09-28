"""
web_footprint.graph — the attack-surface relationship graph.

The central red-team artefact (spec §39): a graph whose nodes are discovered
assets (domains, subdomains, websites, certificates, IPs, DNS records,
repositories, documents, cloud references, emails, technologies) and whose edges
are the *passive* relationships between them —

    domain      --HAS_SUBDOMAIN-->  subdomain
    subdomain   --SECURED_BY------>  certificate
    certificate --COVERS----------->  domain (via its SAN set)
    subdomain   --RESOLVES_TO------>  ip
    host        --USES_NAMESERVER-->  nameserver
    website     --RUNS------------->  technology
    website     --REFERENCES------->  repository / cloud_reference / document
    document    --AUTHORED_BY------>  author
    repository  --REFERENCES------->  domain
    asset       --HISTORICAL_OF---->  asset

These support the passive pivots the spec calls for (§40): certificate→SAN→domain,
DNS→nameserver→related-domain, website→technology→repository, document→author→
repository, repository→domain. The pivot walk is depth-bounded so recursive
correlation can never fan out without a ceiling (spec §59).

DELIBERATE LINE. Every edge is a passive, observed relationship. The graph does
NOT model, suggest, or pivot into any active step — there is no "exploit" edge,
no "next attack" edge. It maps what is publicly observable and how it connects.

``networkx`` is optional: the pure-Python core (add nodes/edges, neighbours,
depth-bounded pivots, dict/DOT export) runs with zero dependencies; a networkx
export activates when the library is present.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger("modbot.web_footprint.graph")

try:
    import networkx as nx
    HAVE_NETWORKX = True
except Exception:  # pragma: no cover
    nx = None
    HAVE_NETWORKX = False


# Canonical edge kinds (all passive, observed relationships).
EDGE_HAS_SUBDOMAIN = "has_subdomain"
EDGE_SECURED_BY = "secured_by"
EDGE_COVERS = "covers"
EDGE_RESOLVES_TO = "resolves_to"
EDGE_USES_NAMESERVER = "uses_nameserver"
EDGE_USES_MX = "uses_mx"
EDGE_RUNS = "runs"
EDGE_REFERENCES = "references"
EDGE_AUTHORED_BY = "authored_by"
EDGE_HISTORICAL_OF = "historical_of"
EDGE_HOSTS = "hosts"


@dataclass
class GraphNode:
    node_id: str
    kind: str                         # asset type or 'technology'/'author'/'nameserver'
    label: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.node_id, "kind": self.kind,
                "label": self.label or self.node_id, "attributes": self.attributes}


@dataclass
class GraphEdge:
    src: str
    dst: str
    kind: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.src, self.dst, self.kind)

    def to_dict(self) -> Dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "kind": self.kind,
                "attributes": self.attributes}


class AttackSurfaceGraph:
    """A directed, typed multigraph of the passive attack surface."""

    def __init__(self, target: str = "") -> None:
        self.target = target
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[Tuple[str, str, str], GraphEdge] = {}
        self._adj: Dict[str, Set[str]] = {}

    # -- construction ------------------------------------------------------ #

    def add_node(self, node_id: str, kind: str, label: str = "",
                 **attrs: Any) -> GraphNode:
        node_id = (node_id or "").strip()
        if not node_id:
            raise ValueError("node_id required")
        node = self._nodes.get(node_id)
        if node is None:
            node = GraphNode(node_id, kind, label or node_id, dict(attrs))
            self._nodes[node_id] = node
            self._adj.setdefault(node_id, set())
        else:
            node.attributes.update(attrs)
            if label and not node.label:
                node.label = label
        return node

    def add_edge(self, src: str, dst: str, kind: str, **attrs: Any) -> Optional[GraphEdge]:
        if not src or not dst or src == dst:
            return None
        if src not in self._nodes:
            self.add_node(src, "unknown")
        if dst not in self._nodes:
            self.add_node(dst, "unknown")
        key = (src, dst, kind)
        edge = self._edges.get(key)
        if edge is None:
            edge = GraphEdge(src, dst, kind, dict(attrs))
            self._edges[key] = edge
            self._adj[src].add(dst)
        else:
            edge.attributes.update(attrs)
        return edge

    # -- queries ----------------------------------------------------------- #

    def __len__(self) -> int:
        return len(self._nodes)

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def neighbors(self, node_id: str) -> List[str]:
        return sorted(self._adj.get(node_id, set()))

    def edges_from(self, node_id: str) -> List[GraphEdge]:
        return [e for (s, _, _), e in self._edges.items() if s == node_id]

    def nodes(self) -> List[GraphNode]:
        return list(self._nodes.values())

    def edges(self) -> List[GraphEdge]:
        return list(self._edges.values())

    def nodes_of_kind(self, kind: str) -> List[GraphNode]:
        return [n for n in self._nodes.values() if n.kind == kind]

    def pivot(self, start: str, *, max_depth: int = 2,
              edge_kinds: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
        """Depth-bounded breadth-first walk of passive relationships from
        ``start``. Returns reachable nodes with the depth and the path taken.
        ``max_depth`` is clamped to ``[0, 6]`` so a pivot can never run away."""
        max_depth = max(0, min(6, int(max_depth)))
        allowed = set(edge_kinds) if edge_kinds else None
        start = (start or "").strip()
        if start not in self._nodes:
            return []
        seen = {start}
        frontier: List[Tuple[str, List[str]]] = [(start, [start])]
        out: List[Dict[str, Any]] = []
        depth = 0
        while frontier and depth < max_depth:
            depth += 1
            nxt: List[Tuple[str, List[str]]] = []
            for node_id, path in frontier:
                for edge in self.edges_from(node_id):
                    if allowed is not None and edge.kind not in allowed:
                        continue
                    if edge.dst in seen:
                        continue
                    seen.add(edge.dst)
                    new_path = path + [edge.dst]
                    node = self._nodes.get(edge.dst)
                    out.append({"node": edge.dst,
                                "kind": node.kind if node else "unknown",
                                "depth": depth, "via": edge.kind, "path": new_path})
                    nxt.append((edge.dst, new_path))
            frontier = nxt
        return out

    # -- export ------------------------------------------------------------ #

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "nodes": [n.to_dict() for n in sorted(self._nodes.values(),
                                                   key=lambda x: (x.kind, x.node_id))],
            "edges": [e.to_dict() for e in sorted(self._edges.values(),
                                                  key=lambda x: (x.src, x.kind, x.dst))],
        }

    def to_dot(self) -> str:
        """Render Graphviz DOT (no dependency needed to produce the text)."""
        lines = ["digraph attack_surface {", '  rankdir=LR;',
                 '  node [shape=box, fontsize=10];']
        for n in sorted(self._nodes.values(), key=lambda x: x.node_id):
            label = n.label.replace('"', '\\"')
            lines.append(f'  "{n.node_id}" [label="{label}", group="{n.kind}"];')
        for e in sorted(self._edges.values(), key=lambda x: (x.src, x.dst)):
            lines.append(f'  "{e.src}" -> "{e.dst}" [label="{e.kind}"];')
        lines.append("}")
        return "\n".join(lines)

    def to_networkx(self):  # pragma: no cover - exercised only when nx present
        """Return a ``networkx.MultiDiGraph`` when networkx is installed."""
        if not HAVE_NETWORKX:
            raise RuntimeError("networkx is not installed")
        g = nx.MultiDiGraph()
        for n in self._nodes.values():
            g.add_node(n.node_id, kind=n.kind, label=n.label, **n.attributes)
        for e in self._edges.values():
            g.add_edge(e.src, e.dst, key=e.kind, kind=e.kind, **e.attributes)
        return g
