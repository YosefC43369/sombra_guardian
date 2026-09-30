"""group_soc.cases — SOC operational casework (assignment, notes, evidence, lifecycle)."""

from .case_manager import CaseManager
from .lifecycle import transition

__all__ = ["CaseManager", "transition"]
