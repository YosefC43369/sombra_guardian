"""group_soc.reporting — assemble + render SOC reports (executive/technical) and export."""

from .report_builder import ReportBuilder
from .executive import format_executive
from .technical import format_technical
from .exporters import export_json

__all__ = ["ReportBuilder", "format_executive", "format_technical", "export_json"]
