"""group_soc.incidents — SOC incident aggregation, classification, containment, lifecycle."""

from .incident_manager import IncidentManager
from .classification import classify, aggregate_dimensions
from .lifecycle import transition

__all__ = ["IncidentManager", "classify", "aggregate_dimensions", "transition"]
