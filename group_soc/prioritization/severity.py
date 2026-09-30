"""
group_soc/prioritization/severity.py — severity-label helpers for prioritization.

Thin, focused wrappers over models.severity used when turning a computed score/dims
back into a human severity label for an alert.
"""

from __future__ import annotations

from ..models.severity import float_to_severity, RiskDimensions
from ..constants import SEVERITY_ORDER, SEVERITY_RANK


def effective_severity_label(dims: RiskDimensions) -> str:
    """Blend the severity magnitude with confidence: a high-severity but low-confidence
    signal reads one band lower than a high-confidence one."""
    blended = dims.severity * (0.6 + 0.4 * dims.confidence)
    return float_to_severity(blended)


def escalate_label(label: str, steps: int = 1) -> str:
    idx = min(len(SEVERITY_ORDER) - 1, SEVERITY_RANK.get(label, 0) + max(0, steps))
    return SEVERITY_ORDER[idx]
