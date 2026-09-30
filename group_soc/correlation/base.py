"""
group_soc/correlation/base.py — the correlator contract + shared helpers.

A correlator inspects the just-persisted event against a bounded window of recent
history and, when it finds a *relationship*, returns a SecuritySignal describing it.
Correlation never returns a verdict: signals carry an analytic_state of CORRELATED
or SUSPICIOUS at most (never CONFIRMED) and confidence is explicitly an analytic
measure, not proof of intent (rule §8).

All history access is bounded (windowed + LIMIT) and uses the migration-0006 indexes.
"""

from __future__ import annotations

from typing import List, Optional, Protocol, runtime_checkable

from ..models.event import SecurityEvent
from ..models.signal import SecuritySignal
from ..util import now


@runtime_checkable
class Correlator(Protocol):
    name: str

    def correlate(self, event: SecurityEvent, storage, config) -> Optional[SecuritySignal]:
        ...


def window_start(config, attr: str = "correlation_window_s") -> int:
    return now() - int(getattr(config, attr, 300))
