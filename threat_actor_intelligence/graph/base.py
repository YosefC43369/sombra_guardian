"""
threat_actor_intelligence.graph.base — the CTI relationship graph + exporters.

Nodes are CTI objects (actor/campaign/malware/technique/infrastructure/ioc/report/
country/industry), typed and coloured; edges are the explainable
``Relationship`` objects (signal + confidence on every edge). Following the
posture of ``entity_fusion.graph``, ``networkx`` is *optional*: when present the
graph is backed by ``MultiDiGraph`` and its exporters are used; when absent a
small pure-stdlib graph provides the same add/query surface and hand-rolled
GraphML / GEXF / node-link JSON exporters, so the engine and its tests run with
zero third-party dependencies.
"""

from __future__ import annotations

import json
import xml.sax.saxutils as _xml
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..models.relation import Relationship

try:
    import networkx as nx
    HAVE_NETWORKX = True
except Exception:  # pragma: no cover
    nx = None
    HAVE_NETWORKX = False

TYPE_COLORS: Dict[str, str] = {
    "actor": "#e15759", "campaign": "#4e79a7", "malware": "#f28e2b",
    "technique": "#b07aa1", "tactic": "#9c6bae", "infrastructure": "#59a14f",
    "ioc": "#edc948", "report": "#76b7b2", "software": "#ff9da7",
    "country": "#9c755f", "industry": "#bab0ac", "victim": "#d37295",
    "unknown": "#bbbbbb",
}


@dataclass
class Node:
    node_id: str
    node_type: str
    label: str = ""
    attrs: Dict[str, Any] = field(default_factory=dict)

    @property
    def color(self) -> str:
        return TYPE_COLORS.get(self.node_type, TYPE_COLORS["unknown"])

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.node_id, "type": self.node_type, "label": self.label,
                "color": self.color, **self.attrs}


@dataclass
class Edge:
    src: str
    dst: str
    rel_type: str
    signal: str = ""
    weight: float = 1.0
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.src, "target": self.dst, "type": self.rel_type,
                "signal": self.signal, "weight": round(self.weight, 4),
                "confidence": round(self.confidence, 4)}


class CTIGraph:
    def __init__(self, *, name: str = "cti"):
        self.name = name
        self._nodes: Dict[str, Node] = {}
        self._edges: List[Edge] = []
        self._edge_keys: set = set()

    # -- construction ------------------------------------------------------ #

    def add_node(self, node_id: str, node_type: str, label: str = "", **attrs
                 ) -> None:
        if not node_id:
            return
        if node_id in self._nodes:
            self._nodes[node_id].attrs.update(attrs)
            if label and not self._nodes[node_id].label:
                self._nodes[node_id].label = label
            return
        self._nodes[node_id] = Node(node_id=node_id, node_type=node_type,
                                    label=label or node_id, attrs=attrs)

    def add_edge(self, src: str, dst: str, rel_type: str, *, signal: str = "",
                 weight: float = 1.0, confidence: float = 0.0) -> None:
        if not src or not dst:
            return
        key = (src, dst, rel_type)
        if key in self._edge_keys:
            for e in self._edges:
                if (e.src, e.dst, e.rel_type) == key:
                    e.weight = max(e.weight, weight)
                    e.confidence = max(e.confidence, confidence)
            return
        self._edge_keys.add(key)
        self._edges.append(Edge(src=src, dst=dst, rel_type=rel_type, signal=signal,
                                weight=weight, confidence=confidence))

    def add_relationship(self, rel: Relationship, *, labels: Optional[Dict[str, str]] = None
                         ) -> None:
        labels = labels or {}
        self.add_node(rel.src_id, rel.src_type.value,
                      labels.get(rel.src_id, rel.src_id))
        self.add_node(rel.dst_id, rel.dst_type.value,
                      labels.get(rel.dst_id, rel.dst_id))
        self.add_edge(rel.src_id, rel.dst_id, rel.rel_type.value,
                      signal=rel.signal, weight=rel.weight, confidence=rel.score)

    # -- queries ----------------------------------------------------------- #

    def order(self) -> int:
        return len(self._nodes)

    def size(self) -> int:
        return len(self._edges)

    def neighbors(self, node_id: str) -> List[str]:
        out = set()
        for e in self._edges:
            if e.src == node_id:
                out.add(e.dst)
            elif e.dst == node_id:
                out.add(e.src)
        return sorted(out)

    def degree(self) -> Dict[str, int]:
        deg: Dict[str, int] = {n: 0 for n in self._nodes}
        for e in self._edges:
            deg[e.src] = deg.get(e.src, 0) + 1
            deg[e.dst] = deg.get(e.dst, 0) + 1
        return deg

    def central_nodes(self, top: int = 10) -> List[Tuple[str, int]]:
        return sorted(self.degree().items(), key=lambda kv: -kv[1])[:top]

    def components(self) -> List[List[str]]:
        parent = {n: n for n in self._nodes}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for e in self._edges:
            if e.src in parent and e.dst in parent:
                parent[find(e.src)] = find(e.dst)
        comps: Dict[str, List[str]] = {}
        for n in self._nodes:
            comps.setdefault(find(n), []).append(n)
        return sorted((sorted(v) for v in comps.values()), key=lambda c: -len(c))

    # -- networkx bridge --------------------------------------------------- #

    def to_networkx(self):  # pragma: no cover
        if not HAVE_NETWORKX:
            raise RuntimeError("networkx not installed")
        g = nx.MultiDiGraph(name=self.name)
        for n in self._nodes.values():
            g.add_node(n.node_id, **n.to_dict())
        for e in self._edges:
            g.add_edge(e.src, e.dst, **e.to_dict())
        return g

    # -- exporters --------------------------------------------------------- #

    def to_json(self) -> Dict[str, Any]:
        return {"name": self.name,
                "nodes": [n.to_dict() for n in self._nodes.values()],
                "edges": [e.to_dict() for e in self._edges],
                "stats": {"nodes": self.order(), "edges": self.size()}}

    def to_json_str(self) -> str:
        return json.dumps(self.to_json(), ensure_ascii=False, sort_keys=True)

    def to_dot(self) -> str:
        lines = [f'digraph "{self.name}" {{', '  rankdir=LR;',
                 '  node [style=filled,fontname="Helvetica"];']
        for n in self._nodes.values():
            lbl = _dot_escape(n.label)
            lines.append(f'  "{n.node_id}" [label="{lbl}",fillcolor="{n.color}",'
                         f'tooltip="{n.node_type}"];')
        for e in self._edges:
            lines.append(f'  "{e.src}" -> "{e.dst}" '
                         f'[label="{_dot_escape(e.rel_type)}",'
                         f'penwidth={1 + 2 * e.weight:.1f}];')
        lines.append("}")
        return "\n".join(lines)

    def to_graphml(self) -> str:
        if HAVE_NETWORKX:  # pragma: no cover
            import io
            buf = io.BytesIO()
            nx.write_graphml(self.to_networkx(), buf)
            return buf.getvalue().decode("utf-8")
        out = ['<?xml version="1.0" encoding="UTF-8"?>',
               '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
               '<key id="type" for="node" attr.name="type" attr.type="string"/>',
               '<key id="label" for="node" attr.name="label" attr.type="string"/>',
               '<key id="rel" for="edge" attr.name="rel" attr.type="string"/>',
               '<key id="weight" for="edge" attr.name="weight" attr.type="double"/>',
               f'<graph id="{_xml.escape(self.name)}" edgedefault="directed">']
        for n in self._nodes.values():
            out.append(f'<node id="{_xml.escape(n.node_id)}">'
                       f'<data key="type">{_xml.escape(n.node_type)}</data>'
                       f'<data key="label">{_xml.escape(n.label)}</data></node>')
        for i, e in enumerate(self._edges):
            out.append(f'<edge id="e{i}" source="{_xml.escape(e.src)}" '
                       f'target="{_xml.escape(e.dst)}">'
                       f'<data key="rel">{_xml.escape(e.rel_type)}</data>'
                       f'<data key="weight">{e.weight}</data></edge>')
        out.append("</graph></graphml>")
        return "\n".join(out)

    def to_gexf(self) -> str:
        if HAVE_NETWORKX:  # pragma: no cover
            import io
            buf = io.BytesIO()
            nx.write_gexf(self.to_networkx(), buf)
            return buf.getvalue().decode("utf-8")
        node_lines, edge_lines = [], []
        for n in self._nodes.values():
            node_lines.append(
                f'<node id="{_xml.escape(n.node_id)}" label="{_xml.escape(n.label)}">'
                f'<attvalues><attvalue for="0" value="{_xml.escape(n.node_type)}"/>'
                f'</attvalues></node>')
        for i, e in enumerate(self._edges):
            edge_lines.append(
                f'<edge id="{i}" source="{_xml.escape(e.src)}" '
                f'target="{_xml.escape(e.dst)}" label="{_xml.escape(e.rel_type)}" '
                f'weight="{e.weight}"/>')
        return ('<?xml version="1.0" encoding="UTF-8"?>\n'
                '<gexf xmlns="http://gexf.net/1.3" version="1.3">'
                f'<graph mode="static" defaultedgetype="directed">'
                '<attributes class="node"><attribute id="0" title="type" '
                'type="string"/></attributes>'
                f'<nodes>{"".join(node_lines)}</nodes>'
                f'<edges>{"".join(edge_lines)}</edges></graph></gexf>')

    def export(self, fmt: str) -> str:
        fmt = (fmt or "json").lower()
        if fmt == "json":
            return self.to_json_str()
        if fmt in ("dot", "graphviz"):
            return self.to_dot()
        if fmt == "graphml":
            return self.to_graphml()
        if fmt == "gexf":
            return self.to_gexf()
        raise ValueError(f"unknown graph format: {fmt}")


def _dot_escape(s: str) -> str:
    return (s or "").replace("\\", "\\\\").replace('"', '\\"')


__all__ = ["CTIGraph", "Node", "Edge", "TYPE_COLORS", "HAVE_NETWORKX"]
