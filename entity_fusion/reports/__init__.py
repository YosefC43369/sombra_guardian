"""
entity_fusion.reports — render a FusionResult / identity set into an
investigation dossier in several formats (JSON, Markdown, CSV, HTML, GraphViz).

``render(result, fmt=...)`` is the one-call entry; the per-format modules are
also importable directly. A ``bundle`` helper writes every format to a directory
as a ZIP-ready dossier.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from . import json as json_report
from . import markdown as markdown_report
from . import csv as csv_report
from . import html as html_report
from . import graphviz as graphviz_report

if TYPE_CHECKING:
    from ..orchestrator import FusionResult

__all__ = ["json_report", "markdown_report", "csv_report", "html_report",
           "graphviz_report", "render", "bundle"]

_RENDERERS = {
    "json": json_report.render,
    "markdown": markdown_report.render,
    "md": markdown_report.render,
    "csv": csv_report.render,
    "html": html_report.render,
    "dot": graphviz_report.render,
    "graphviz": graphviz_report.render,
}


def render(result: "FusionResult", fmt: str = "markdown") -> str:
    renderer = _RENDERERS.get(fmt.lower())
    if renderer is None:
        raise ValueError(f"unknown report format: {fmt!r} "
                         f"(choose from {sorted(_RENDERERS)})")
    return renderer(result)


def bundle(result: "FusionResult", directory: str, *,
           basename: str = "dossier") -> list:
    """Write JSON, Markdown, CSV, HTML and DOT reports into ``directory``.
    Returns the list of written paths (ready to zip into an export bundle)."""
    os.makedirs(directory, exist_ok=True)
    written = []
    for fmt, ext in (("json", "json"), ("markdown", "md"), ("csv", "csv"),
                     ("html", "html"), ("dot", "dot")):
        path = os.path.join(directory, f"{basename}.{ext}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render(result, fmt))
        written.append(path)
    return written
