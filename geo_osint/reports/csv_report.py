"""
geo_osint.reports.csv_report — render the geographic inventory as CSV (spec §46).

Flattens the report's geographic-inventory rows into CSV for spreadsheets/GIS
import. One row per observation, with type/place/coordinate/precision/source/
confidence columns.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from .geo_report import GeoReport

_COLUMNS = ["type", "city", "country_code", "latitude", "longitude",
            "precision", "source", "confidence", "band"]


def render(report: GeoReport) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for row in report.sections.get("geographic_inventory", []):
        writer.writerow(row)
    return buf.getvalue()


def write(report: GeoReport, path: str) -> str:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(render(report))
    return path
