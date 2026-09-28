"""
geo_osint.reports.json_report — render a GeoReport as JSON (spec §46).

Machine-readable, lossless serialisation of the full report structure — the format
other Sombra Guardian subsystems (Entity Fusion, Behavioral Intelligence) ingest.
"""

from __future__ import annotations

import json
from typing import Any

from .geo_report import GeoReport


def render(report: GeoReport, *, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=indent)


def write(report: GeoReport, path: str, *, indent: int = 2) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(report, indent=indent))
    return path
