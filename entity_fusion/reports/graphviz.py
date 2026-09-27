"""entity_fusion.reports.graphviz — thin report wrapper over the graph engine's
GraphViz output. Returns DOT source (always available) and, when the ``dot``
binary is installed, rendered SVG/PNG bytes."""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..orchestrator import FusionResult
    from ..graph import IdentityGraph


def render(result: "FusionResult") -> str:
    """GraphViz DOT source for the result's relationship graph."""
    if result.graph is None:
        return "digraph identity {}"
    return result.graph.to_dot()


def render_svg(result: "FusionResult") -> Optional[bytes]:
    """Rendered SVG bytes if Graphviz ``dot`` is on PATH, else None."""
    if result.graph is None:
        return None
    return result.graph.render("svg")


def render_png(result: "FusionResult") -> Optional[bytes]:
    if result.graph is None:
        return None
    return result.graph.render("png")
