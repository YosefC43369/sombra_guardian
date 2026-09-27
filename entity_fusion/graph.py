"""
entity_fusion.graph — build and export the relationship graph of correlated
entities.

Nodes are entities (typed, coloured by type); edges are the typed relationships
from ``entity.Relationship`` plus the ``same_as`` edges emitted by fusion. The
graph is the spatial view of an investigation: who owns what, which accounts
share an avatar, which domains resolve where.

DEPENDENCY POSTURE. ``networkx`` is *optional*. When it is installed the graph is
backed by ``networkx.MultiDiGraph`` and every networkx exporter (GraphML, GEXF,
node-link JSON) is available for free. When it is not, a small pure-stdlib
in-memory graph provides the same add/query surface and the same exporters
(JSON, GraphViz DOT, and hand-rolled GraphML/GEXF), so the engine — and its
tests — run with zero third-party dependencies. Raster/vector rendering (PNG /
SVG) is delegated to the Graphviz ``dot`` binary when present; the DOT source is
always available regardless.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import xml.sax.saxutils as _xml
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .entity import Entity, EntityType, RelationType

try:
    import networkx as nx
    HAVE_NETWORKX = True
except Exception:  # pragma: no cover - optional dependency
    nx = None
    HAVE_NETWORKX = False


# Type → colour, used by DOT/GEXF renderers to make graphs readable at a glance.
_TYPE_COLORS: Dict[str, str] = {
    "person": "#e15759", "organization": "#4e79a7", "domain": "#59a14f",
    "subdomain": "#8cd17d", "ip": "#f28e2b", "asn": "#b07aa1",
    "email": "#76b7b2", "phone": "#edc948", "username": "#ff9da7",
    "website": "#9c755f", "repository": "#bab0ac", "certificate": "#d37295",
    "wallet": "#fabfd2", "document": "#b6992d", "image": "#86bcb6",
    "location": "#499894", "unknown": "#bbbbbb",
}


@dataclass
class _Edge:
    src: str
    dst: str
    type: str
    weight: float = 1.0
    attrs: Dict[str, Any] = None  # type: ignore

    def __post_init__(self):
        if self.attrs is None:
            self.attrs = {}


class _StdlibGraph:
    """Minimal directed multigraph used when networkx is absent."""

    def __init__(self) -> None:
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: List[_Edge] = []

    def add_node(self, node_id: str, **attrs: Any) -> None:
        self._nodes.setdefault(node_id, {}).update(attrs)

    def add_edge(self, src: str, dst: str, *, type: str = "mentions",
                 weight: float = 1.0, **attrs: Any) -> None:
        self.add_node(src)
        self.add_node(dst)
        self._edges.append(_Edge(src, dst, type, weight, dict(attrs)))

    @property
    def nodes(self) -> Dict[str, Dict[str, Any]]:
        return self._nodes

    @property
    def edges(self) -> List[_Edge]:
        return self._edges

    def number_of_nodes(self) -> int:
        return len(self._nodes)

    def number_of_edges(self) -> int:
        return len(self._edges)

    def neighbors(self, node_id: str) -> List[str]:
        out = {e.dst for e in self._edges if e.src == node_id}
        out |= {e.src for e in self._edges if e.dst == node_id}
        return sorted(out)


class IdentityGraph:
    """A relationship graph over entities with multi-format export.

    Backed by networkx when available, otherwise by ``_StdlibGraph``. The public
    surface (``add_entity``, ``add_relationship``, ``to_json``, ``to_dot`` …) is
    identical in both cases so callers never branch on the backend.
    """

    def __init__(self) -> None:
        self.backend = "networkx" if HAVE_NETWORKX else "stdlib"
        self._g = nx.MultiDiGraph() if HAVE_NETWORKX else _StdlibGraph()

    # -- construction ------------------------------------------------------ #

    def add_entity(self, entity: Entity) -> None:
        self._g.add_node(
            entity.id,
            label=entity.value or entity.id[:8],
            type=entity.type.value,
            color=_TYPE_COLORS.get(entity.type.value, "#bbbbbb"),
            confidence=entity.confidence,
            aliases="|".join(sorted(entity.aliases)),
            providers="|".join(sorted(entity.providers)),
        )

    def add_relationship(self, src_id: str, dst_id: str,
                         rel_type: Any = RelationType.MENTIONS,
                         *, weight: float = 1.0, **attrs: Any) -> None:
        rt = rel_type.value if isinstance(rel_type, RelationType) else str(rel_type)
        self._g.add_edge(src_id, dst_id, type=rt, weight=weight, **attrs)

    def build_from_entities(self, entities: Iterable[Entity]) -> "IdentityGraph":
        """Add every entity and its declared relationships. Relationship targets
        that are not themselves in the set are added as bare nodes so no edge
        dangles."""
        ents = list(entities)
        for e in ents:
            self.add_entity(e)
        known = {e.id for e in ents}
        for e in ents:
            for rel in e.relationships:
                if rel.target_id not in known:
                    self._g.add_node(rel.target_id, label=rel.target_id[:8],
                                     type="unknown", color=_TYPE_COLORS["unknown"])
                self.add_relationship(e.id, rel.target_id, rel.type,
                                      weight=rel.weight)
        return self

    def link_cluster(self, member_ids: List[str], rel_type=RelationType.SAME_AS,
                     weight: float = 1.0) -> None:
        """Wire a fused cluster together with ``same_as`` edges (star topology
        from the first member, keeping edge count linear in cluster size)."""
        if len(member_ids) < 2:
            return
        hub = member_ids[0]
        for other in member_ids[1:]:
            self.add_relationship(hub, other, rel_type, weight=weight)

    # -- introspection ----------------------------------------------------- #

    def stats(self) -> Dict[str, Any]:
        return {
            "backend": self.backend,
            "nodes": self._g.number_of_nodes(),
            "edges": self._g.number_of_edges(),
        }

    def _iter_nodes(self) -> List[Tuple[str, Dict[str, Any]]]:
        if HAVE_NETWORKX:
            return list(self._g.nodes(data=True))
        return [(nid, attrs) for nid, attrs in self._g.nodes.items()]

    def _iter_edges(self) -> List[Tuple[str, str, Dict[str, Any]]]:
        if HAVE_NETWORKX:
            return [(u, v, d) for u, v, d in self._g.edges(data=True)]
        return [(e.src, e.dst, {"type": e.type, "weight": e.weight, **e.attrs})
                for e in self._g.edges]

    # -- exporters --------------------------------------------------------- #

    def to_node_link(self) -> Dict[str, Any]:
        """A stable node-link dict (the JSON graph interchange shape)."""
        return {
            "directed": True,
            "multigraph": True,
            "nodes": [{"id": nid, **attrs} for nid, attrs in
                      sorted(self._iter_nodes(), key=lambda x: x[0])],
            "links": [{"source": u, "target": v, **d} for u, v, d in
                      sorted(self._iter_edges(), key=lambda x: (x[0], x[1]))],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_node_link(), ensure_ascii=False,
                          sort_keys=True, indent=indent)

    def to_dot(self) -> str:
        """GraphViz DOT source. Always available (no dependency)."""
        lines = ["digraph identity {", '  graph [rankdir=LR, overlap=false];',
                 '  node [style=filled, fontname="Helvetica"];']
        for nid, attrs in sorted(self._iter_nodes(), key=lambda x: x[0]):
            label = _xml.escape(str(attrs.get("label", nid[:8])))
            color = attrs.get("color", "#bbbbbb")
            ntype = attrs.get("type", "unknown")
            lines.append(
                f'  "{nid}" [label="{label}\\n({ntype})", fillcolor="{color}"];')
        for u, v, d in sorted(self._iter_edges(), key=lambda x: (x[0], x[1])):
            etype = _xml.escape(str(d.get("type", "")))
            lines.append(f'  "{u}" -> "{v}" [label="{etype}"];')
        lines.append("}")
        return "\n".join(lines)

    def to_graphml(self) -> str:
        """GraphML. Uses networkx's writer when available (richer, schema-valid),
        else a minimal hand-rolled document."""
        if HAVE_NETWORKX:
            import io
            buf = io.BytesIO()
            nx.write_graphml(self._g, buf)
            return buf.getvalue().decode("utf-8")
        keys = ('  <key id="d0" for="node" attr.name="label" attr.type="string"/>\n'
                '  <key id="d1" for="node" attr.name="type" attr.type="string"/>\n'
                '  <key id="d2" for="edge" attr.name="type" attr.type="string"/>\n')
        parts = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
                 keys.rstrip("\n"),
                 '  <graph edgedefault="directed">']
        for nid, attrs in sorted(self._iter_nodes(), key=lambda x: x[0]):
            parts.append(f'    <node id="{_xml.quoteattr(nid)[1:-1]}">'
                         f'<data key="d0">{_xml.escape(str(attrs.get("label","")))}</data>'
                         f'<data key="d1">{_xml.escape(str(attrs.get("type","")))}</data></node>')
        for i, (u, v, d) in enumerate(sorted(self._iter_edges(), key=lambda x: (x[0], x[1]))):
            parts.append(f'    <edge id="e{i}" source="{_xml.quoteattr(u)[1:-1]}" '
                         f'target="{_xml.quoteattr(v)[1:-1]}">'
                         f'<data key="d2">{_xml.escape(str(d.get("type","")))}</data></edge>')
        parts += ["  </graph>", "</graphml>"]
        return "\n".join(parts)

    def to_gexf(self) -> str:
        """GEXF (Gephi). networkx writer when available, else minimal document."""
        if HAVE_NETWORKX:
            import io
            buf = io.BytesIO()
            nx.write_gexf(self._g, buf)
            return buf.getvalue().decode("utf-8")
        parts = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<gexf xmlns="http://gexf.net/1.3" version="1.3">',
                 '  <graph mode="static" defaultedgetype="directed">',
                 "    <nodes>"]
        for nid, attrs in sorted(self._iter_nodes(), key=lambda x: x[0]):
            parts.append(f'      <node id="{_xml.quoteattr(nid)[1:-1]}" '
                         f'label="{_xml.quoteattr(str(attrs.get("label","")))[1:-1]}"/>')
        parts.append("    </nodes>")
        parts.append("    <edges>")
        for i, (u, v, d) in enumerate(sorted(self._iter_edges(), key=lambda x: (x[0], x[1]))):
            parts.append(f'      <edge id="{i}" source="{_xml.quoteattr(u)[1:-1]}" '
                         f'target="{_xml.quoteattr(v)[1:-1]}" '
                         f'label="{_xml.quoteattr(str(d.get("type","")))[1:-1]}"/>')
        parts += ["    </edges>", "  </graph>", "</gexf>"]
        return "\n".join(parts)

    # -- rendering (optional, needs the `dot` binary) ---------------------- #

    def render(self, fmt: str = "svg") -> Optional[bytes]:
        """Render via the Graphviz ``dot`` binary if it is on PATH. Returns the
        rendered bytes, or None if ``dot`` is unavailable (the DOT source from
        ``to_dot`` is the always-available fallback)."""
        dot_bin = shutil.which("dot")
        if not dot_bin:
            return None
        try:
            proc = subprocess.run(
                [dot_bin, f"-T{fmt}"], input=self.to_dot().encode("utf-8"),
                capture_output=True, timeout=30, check=True)
            return proc.stdout
        except Exception:  # pragma: no cover - environment dependent
            return None
