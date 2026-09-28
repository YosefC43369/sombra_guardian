"""
web_footprint.reports.json_report — machine-readable recon output.

A thin, stable serializer: it returns the :class:`ReconResult`'s ``to_dict``
(the full evidence-backed structure) and can emit it as a JSON string. Kept
separate from the Markdown report so pipelines can consume structured output
without parsing prose.
"""

from __future__ import annotations

import json
from typing import Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from ..pipeline import ReconResult


def to_dict(result: "ReconResult") -> Dict[str, Any]:
    return result.to_dict()


def render(result: "ReconResult", *, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, sort_keys=False, default=str)
