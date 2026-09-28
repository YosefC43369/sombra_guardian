"""
news_intelligence.graph.base — the provenance-carrying graph model + exporters.

A ``NewsGraph`` is nodes (articles, sources, actors, malware, CVEs, orgs, countries,
IOCs, techniques, campaigns) and edges that always carry *provenance*: the article
ids and shared signals that justify the edge, plus a weight. Exports to JSON,
GraphML, GEXF and DOT with stdlib only (no networkx required), matching the CTI
graph exporter's formats so downstream Graph Engine tooling can consume either.
"""

from __future__ import annotations

import html
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple
from xml.sax.saxutils import escape as _xml_escape


@dataclass
class GraphNode:
    node_id: str
    node_type: str
    label: str = ""
    weight: float = 1.0
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.node_id, "type": self.node_type,
                "label": self.label or self.node_id, "weight": self.weight,
                **({"detail": self.detail} if self.detail else {})}


@dataclass
class GraphEdge:
    src: str
    dst: str
    rel_type: str
    weight: float = 1.0
    article_ids: List[str] = field(default_factory=list)
    signals: List[str] = field(default_factory=list)
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "rel": self.rel_type,
                "weight": self.weight, "article_ids": self.article_ids,
                "signals": self.signals,
                **({"detail": self.detail} if self.detail else {})}


class NewsGraph:
    def __init__(self, name: str = "news_graph"):
        self.name = name
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self._edge_index: Dict[Tuple[str, str, str], GraphEdge] = {}

    def add_node(self, node_id: str, node_type: str, *, label: str = "",
                 weight: float = 1.0, **detail) -> GraphNode:
        n = self.nodes.get(node_id)
        if n is None:
            n = GraphNode(node_id=node_id, node_type=node_type,
                          label=label or node_id, weight=weight, detail=detail)
            self.nodes[node_id] = n
        else:
            n.weight += weight
            if detail:
                n.detail.update(detail)
        return n

    def add_edge(self, src: str, dst: str, rel_type: str, *, weight: float = 1.0,
                 article_ids: Optional[List[str]] = None,
                 signals: Optional[List[str]] = None, **detail) -> GraphEdge:
        key = (src, dst, rel_type)
        e = self._edge_index.get(key)
        if e is None:
            e = GraphEdge(src=src, dst=dst, rel_type=rel_type, weight=weight,
                          article_ids=list(article_ids or []),
                          signals=list(signals or []), detail=detail)
            self._edge_index[key] = e
            self.edges.append(e)
        else:
            e.weight += weight
            for aid in (article_ids or []):
                if aid not in e.article_ids:
                    e.article_ids.append(aid)
            for s in (signals or []):
                if s not in e.signals:
                    e.signals.append(s)
        return e

    def neighbors(self, node_id: str) -> List[GraphEdge]:
        return [e for e in self.edges if node_id in (e.src, e.dst)]

    def stats(self) -> Dict[str, Any]:
        types: Dict[str, int] = {}
        for n in self.nodes.values():
            types[n.node_type] = types.get(n.node_type, 0) + 1
        return {"nodes": len(self.nodes), "edges": len(self.edges),
                "node_types": types}

    # -- exporters -------------------------------------------------------- #
    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name,
                "nodes": [n.to_dict() for n in self.nodes.values()],
                "edges": [e.to_dict() for e in self.edges],
                "stats": self.stats()}

    def to_json(self, *, indent: int = 2) -> str:
        import json
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_dot(self) -> str:
        lines = [f'digraph "{self.name}" {{', '  rankdir=LR;',
                 '  node [style=filled, fontname="Helvetica"];']
        for n in self.nodes.values():
            lbl = html.escape(n.label).replace('"', "'")
            lines.append(f'  "{n.node_id}" [label="{lbl}", '
                         f'tooltip="{n.node_type}"];')
        for e in self.edges:
            lines.append(f'  "{e.src}" -> "{e.dst}" '
                         f'[label="{e.rel_type}", weight={e.weight:.2f}];')
        lines.append("}")
        return "\n".join(lines)

    def to_graphml(self) -> str:
        out = ['<?xml version="1.0" encoding="UTF-8"?>',
               '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
               '<key id="type" for="node" attr.name="type" attr.type="string"/>',
               '<key id="label" for="node" attr.name="label" attr.type="string"/>',
               '<key id="rel" for="edge" attr.name="rel" attr.type="string"/>',
               '<key id="weight" for="edge" attr.name="weight" attr.type="double"/>',
               f'<graph id="{_xml_escape(self.name)}" edgedefault="directed">']
        for n in self.nodes.values():
            out.append(f'<node id="{_xml_escape(n.node_id)}">'
                       f'<data key="type">{_xml_escape(n.node_type)}</data>'
                       f'<data key="label">{_xml_escape(n.label)}</data></node>')
        for i, e in enumerate(self.edges):
            out.append(f'<edge id="e{i}" source="{_xml_escape(e.src)}" '
                       f'target="{_xml_escape(e.dst)}">'
                       f'<data key="rel">{_xml_escape(e.rel_type)}</data>'
                       f'<data key="weight">{e.weight:.4f}</data></edge>')
        out.append('</graph></graphml>')
        return "\n".join(out)

    def to_gexf(self) -> str:
        out = ['<?xml version="1.0" encoding="UTF-8"?>',
               '<gexf xmlns="http://gexf.net/1.3" version="1.3">',
               f'<graph mode="static" defaultedgetype="directed">', '<nodes>']
        for n in self.nodes.values():
            out.append(f'<node id="{_xml_escape(n.node_id)}" '
                       f'label="{_xml_escape(n.label)}"/>')
        out.append('</nodes>')
        out.append('<edges>')
        for i, e in enumerate(self.edges):
            out.append(f'<edge id="{i}" source="{_xml_escape(e.src)}" '
                       f'target="{_xml_escape(e.dst)}" weight="{e.weight:.4f}"/>')
        out.append('</edges></graph></gexf>')
        return "\n".join(out)

    def export(self, fmt: str = "json") -> str:
        fmt = (fmt or "json").lower()
        return {"json": self.to_json, "dot": self.to_dot,
                "graphml": self.to_graphml, "gexf": self.to_gexf}.get(
                    fmt, self.to_json)()


class BaseGraphBuilder:
    def __init__(self, store):
        self.store = store


__all__ = ["GraphNode", "GraphEdge", "NewsGraph", "BaseGraphBuilder"]
