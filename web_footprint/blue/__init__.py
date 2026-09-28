"""
web_footprint.blue — the defensive (blue-team) 20% of the engine.

Reuses the passive recon output to give defenders an asset inventory, exposure
-change monitoring, brand/impersonation detection, IOC enrichment hand-off and
factual posture signals. Intentionally smaller than the red-team surface.
"""

from .monitor import BlueTeamMonitor, Alert, AlertKind

__all__ = ["BlueTeamMonitor", "Alert", "AlertKind"]
