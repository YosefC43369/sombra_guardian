"""
behavioral_intelligence.visualization.network_chart — interaction-graph rendering
(spec §42).

Three outputs from an ``InteractionNetwork``:
  * a GraphViz DOT string (always; render with `dot` if installed);
  * a self-contained inline SVG using a deterministic circular layout (always);
  * an optional matplotlib+networkx PNG when both are installed.

Node labels are the observed account handles; edges are directed public
interactions with their counts. No relationship type is asserted — the graph
shows who publicly interacted with whom, nothing more.
"""

from __future__ import annotations

import math
from typing import Any, Dict, Optional

from ..models.behavior import InteractionNetwork
from ._svg import open_svg, close_svg, esc, ACCENT, MUTED, FG

try:
    import networkx as nx
    HAVE_NETWORKX = True
except Exception:  # pragma: no cover
    nx = None
    HAVE_NETWORKX = False

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAVE_MATPLOTLIB = True
except Exception:  # pragma: no cover
    plt = None
    HAVE_MATPLOTLIB = False


def to_dot(net: InteractionNetwork, *, max_edges: int = 100) -> str:
    lines = ["digraph interactions {", '  rankdir=LR;',
             '  node [shape=ellipse,fontsize=10];']
    for e in net.edges[:max_edges]:
        lines.append(f'  "{_esc_dot(e.source)}" -> "{_esc_dot(e.target)}" '
                     f'[label="{e.count}"];')
    lines.append("}")
    return "\n".join(lines)


def _esc_dot(s: str) -> str:
    return str(s).replace('"', '\\"')


def to_svg(net: InteractionNetwork, *, width: int = 480, max_nodes: int = 40) -> str:
    # collect top nodes by degree
    deg: Dict[str, int] = {}
    for e in net.edges:
        deg[e.source] = deg.get(e.source, 0) + e.count
        deg[e.target] = deg.get(e.target, 0) + e.count
    nodes = [n for n, _ in sorted(deg.items(), key=lambda kv: kv[1],
                                  reverse=True)[:max_nodes]]
    if not nodes:
        return "<svg width='1' height='1'></svg>"
    cx = cy = width / 2
    r = width / 2 - 40
    pos = {}
    for i, n in enumerate(nodes):
        ang = 2 * math.pi * i / len(nodes)
        pos[n] = (cx + r * math.cos(ang), cy + r * math.sin(ang))
    parts = [open_svg(width, width, "interaction network")]
    for e in net.edges:
        if e.source in pos and e.target in pos:
            x1, y1 = pos[e.source]
            x2, y2 = pos[e.target]
            parts.append(f"<line x1='{x1:.1f}' y1='{y1:.1f}' x2='{x2:.1f}' "
                         f"y2='{y2:.1f}' stroke='{MUTED}' stroke-opacity='0.4' "
                         f"stroke-width='{min(4, 0.5+e.count/5):.1f}'/>")
    for n in nodes:
        x, y = pos[n]
        size = 3 + min(10, deg[n] ** 0.5)
        parts.append(f"<circle cx='{x:.1f}' cy='{y:.1f}' r='{size:.1f}' "
                     f"fill='{ACCENT}'><title>{esc(n)}: degree {deg[n]}</title>"
                     f"</circle>")
        parts.append(f"<text x='{x:.1f}' y='{y-size-2:.1f}' font-size='8' "
                     f"text-anchor='middle' fill='{FG}'>{esc(str(n)[:12])}</text>")
    parts.append(close_svg())
    return "".join(parts)


def to_png(net: InteractionNetwork, path: str) -> Optional[str]:  # pragma: no cover
    if not (HAVE_NETWORKX and HAVE_MATPLOTLIB) or not net.edges:
        return None
    g = nx.DiGraph()
    for e in net.edges:
        g.add_edge(e.source, e.target, weight=e.count)
    fig, ax = plt.subplots(figsize=(7, 7))
    pos = nx.spring_layout(g, seed=42)
    nx.draw_networkx(g, pos, ax=ax, node_size=200, font_size=7,
                     node_color="#0969da", edge_color="#88888855", arrows=True)
    ax.set_title("Public interaction network")
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return path


def to_dict(net: InteractionNetwork) -> Dict[str, Any]:
    return net.to_dict()
