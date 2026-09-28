"""
geo_osint.reports — the report engine (spec §46).

:class:`GeoReportBuilder` assembles a provider-neutral report structure with every
spec section (Executive Summary, Geographic Inventory, Infrastructure Map, Airport
Analysis, Country Timeline, ASN/IP Geolocation, Cloud Regions, Facility
Relationships, Evidence, Limitations). The renderer modules turn that one structure
into JSON, Markdown, HTML (with an embedded map) and CSV, so every format shows the
same evidence-backed facts. A Limitations section is always present.
"""

from .geo_report import GeoReportBuilder, GeoReport
from . import json_report, markdown_report, html_report, csv_report

__all__ = ["GeoReportBuilder", "GeoReport",
           "json_report", "markdown_report", "html_report", "csv_report"]
