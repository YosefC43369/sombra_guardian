"""
group_soc/detection/anomaly.py — a simple, explainable activity-spike detector.

Compares event volume in the current short window to the immediately preceding window
of the same length. A large ratio increase is flagged as an anomaly. This is
deliberately a transparent window-over-window comparison (two bounded COUNT queries),
not an opaque model — a SOC analyst can reason about why it fired. It is a clean seam:
a richer baseline/EWMA model can replace ``_ratio`` later without touching callers.
"""

from __future__ import annotations

from typing import List

from ..models.event import SecurityEvent
from ..models.signal import SecuritySignal
from ..models.severity import RiskDimensions
from ..constants import DetectorKind, AnalyticState
from ..util import now


class ActivitySpikeDetector:
    name = "activity_spike"

    #: minimum events in the current window before a spike is meaningful
    MIN_CURRENT = 10
    #: current/previous ratio that counts as a spike
    SPIKE_RATIO = 3.0

    def detect(self, event: SecurityEvent, storage, config) -> List[SecuritySignal]:
        window = int(getattr(config, "correlation_window_s", 300))
        t = now()
        current = storage.events.count_all_since(event.chat_id, t - window)
        if current < self.MIN_CURRENT:
            return []
        previous = storage.events.count_all_since(event.chat_id, t - 2 * window) - current
        previous = max(previous, 0)
        # avoid div-by-zero: treat an empty previous window as a baseline of 1
        ratio = current / max(previous, 1)
        if ratio < self.SPIKE_RATIO:
            return []
        conf = min(0.85, 0.4 + 0.1 * (ratio - self.SPIKE_RATIO))
        dims = RiskDimensions(severity=0.5, confidence=conf, impact=0.5,
                              urgency=0.7, exposure=0.5, persistence=0.3)
        return [SecuritySignal(
            signal_type=DetectorKind.ANOMALY.value,
            producer="detection:anomaly:activity_spike",
            chat_id=event.chat_id,
            title="Activity spike",
            summary=(f"{current} events in the last {window}s vs {previous} in the prior "
                     f"window (~{ratio:.1f}x)."),
            dimensions=dims,
            analytic_state=AnalyticState.CORRELATED.value,
            event_ids=[event.event_id],
            dedup_key=f"{event.chat_id}:anomaly:activity_spike",
            metadata={"current": current, "previous": previous, "ratio": round(ratio, 2)},
        )]
