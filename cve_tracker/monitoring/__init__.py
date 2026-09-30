"""
cve_tracker.monitoring — observability: metrics, health, audit, diagnostics.

Structured, secret-free observability (rules §29, §30, §49, §50). The engine
threads a shared :class:`MetricsRegistry` and :class:`AuditLogger` through the
pipeline; :class:`HealthTracker` and :class:`DiagnosticsService` render the state
for the status/diagnostic commands.
"""

from .metrics import MetricsRegistry, Timer
from .health import HealthTracker, HealthReport, evaluate_source
from .audit import AuditLogger
from .diagnostics import DiagnosticsService
from .reporting import ReportBuilder, StatsReport

__all__ = [
    "MetricsRegistry", "Timer",
    "HealthTracker", "HealthReport", "evaluate_source",
    "AuditLogger", "DiagnosticsService",
    "ReportBuilder", "StatsReport",
]
