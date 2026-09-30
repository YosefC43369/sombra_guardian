"""
group_soc/correlation/temporal.py — temporal clustering of elevated activity.

Rather than firing on ordinary chatter, this links *elevated* events (high/critical
severity or a suspicious state) that occur close together in time into one cluster —
the grouping a timeline/story is built from. It is deliberately conservative so a
busy-but-benign group does not generate temporal noise.
"""

from __future__ import annotations

from typing import Optional

from ..models.event import SecurityEvent
from ..models.signal import SecuritySignal
from ..models.severity import RiskDimensions
from ..constants import CorrelationKind, AnalyticState, SEVERITY_RANK, Severity
from ..util import now
from .base import window_start


class TemporalCorrelator:
    name = "temporal"

    def correlate(self, event: SecurityEvent, storage, config) -> Optional[SecuritySignal]:
        # only anchor on an elevated event; otherwise there is nothing to cluster around
        elevated_now = (SEVERITY_RANK.get(event.severity, 0) >= SEVERITY_RANK[Severity.HIGH.value]
                        or event.analytic_state == AnalyticState.SUSPICIOUS.value)
        if not elevated_now:
            return None
        since = window_start(config)
        elevated = storage.events.elevated_in_window(event.chat_id, since, limit=50)
        # include the current event id even if it isn't persisted yet
        ids = {e.event_id for e in elevated}
        ids.add(event.event_id)
        if len(ids) < 2:
            return None
        conf = min(0.85, 0.4 + 0.08 * len(ids))
        dims = RiskDimensions(severity=0.6, confidence=conf, impact=0.5,
                              urgency=0.65, exposure=0.5, persistence=0.4)
        return SecuritySignal(
            signal_type=CorrelationKind.TEMPORAL.value,
            producer="correlation:temporal:elevated_cluster",
            chat_id=event.chat_id,
            title="Cluster of elevated events in a short window",
            summary=f"{len(ids)} elevated events occurred within "
                    f"{int(getattr(config, 'correlation_window_s', 300))}s.",
            dimensions=dims,
            analytic_state=AnalyticState.CORRELATED.value,
            event_ids=list(ids)[:50],
            dedup_key=f"{event.chat_id}:temporal:cluster",
            metadata={"cluster_size": len(ids)},
        )
