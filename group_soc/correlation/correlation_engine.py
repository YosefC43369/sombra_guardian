"""
group_soc/correlation/correlation_engine.py — runs the correlators, dedups output.

Given the just-persisted event, runs every registered correlator (each isolated) and
returns the signals they produced, de-duplicated by dedup_key within this batch so a
single event never yields two identical correlation signals. New correlators register
here without touching the pipeline.
"""

from __future__ import annotations

import logging
from typing import List

from ..models.event import SecurityEvent
from ..models.signal import SecuritySignal
from .base import Correlator
from .temporal import TemporalCorrelator
from .entity import EntityCorrelator
from .behavioral import BehavioralCorrelator
from .event_chain import SequenceCorrelator
from .clustering import CampaignClusterer

logger = logging.getLogger("modbot.group_soc.correlation")


class CorrelationEngine:
    def __init__(self, correlators: List[Correlator] = None):
        self.correlators: List[Correlator] = list(correlators) if correlators else [
            CampaignClusterer(),
            SequenceCorrelator(),
            BehavioralCorrelator(),
            EntityCorrelator(),
            TemporalCorrelator(),
        ]

    def register(self, correlator: Correlator) -> None:
        self.correlators.append(correlator)

    def correlate(self, event: SecurityEvent, storage, config) -> List[SecuritySignal]:
        out: List[SecuritySignal] = []
        seen = set()
        for c in self.correlators:
            try:
                signal = c.correlate(event, storage, config)
            except Exception:
                logger.exception("correlator %s failed (isolated)",
                                 getattr(c, "name", type(c).__name__))
                continue
            if signal is not None and signal.dedup_key not in seen:
                out.append(signal)
                seen.add(signal.dedup_key)
        return out
