"""
web_footprint.reports — render a ReconResult to a red-team Markdown report or to
machine-readable JSON.
"""

from . import red_team, json_report

__all__ = ["red_team", "json_report"]
