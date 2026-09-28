"""
behavioral_intelligence.visualization — chart rendering.

Every chart renders as a self-contained inline SVG with no external dependency
(theme-aware, embeddable in the HTML report), exposes its underlying data as a
JSON-able dict, and offers an optional matplotlib PNG / GraphViz DOT when those
tools are available. Covers activity heatmaps, activity-over-time, keyword/hashtag
bars, language distribution, event timelines and interaction networks.
"""

from . import (heatmap, timeline, activity_chart, topic_chart, language_chart,
               network_chart)
from .heatmap import HAVE_MATPLOTLIB
from .network_chart import HAVE_NETWORKX

__all__ = [
    "heatmap", "timeline", "activity_chart", "topic_chart", "language_chart",
    "network_chart", "HAVE_MATPLOTLIB", "HAVE_NETWORKX",
]
