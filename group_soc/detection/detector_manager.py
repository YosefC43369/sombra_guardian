"""
group_soc/detection/detector_manager.py — runs all detectors, isolates failures, dedups.

Gathers the signals every registered detector produced for the current event,
de-duplicating by dedup_key. Detectors are added here (or at runtime) without touching
the pipeline. Each detector runs isolated so one failure never suppresses the others.
"""

from __future__ import annotations

import logging
from typing import List

from ..models.event import SecurityEvent
from ..models.signal import SecuritySignal
from .base import Detector
from .threshold import JoinBurstDetector, RepeatedContentDetector
from .rule_engine import RuleEngine
from .anomaly import ActivitySpikeDetector
from .sequence import default_sequence_detectors

logger = logging.getLogger("modbot.group_soc.detection")


class DetectorManager:
    def __init__(self, detectors: List[Detector] = None):
        if detectors is not None:
            self.detectors = list(detectors)
        else:
            self.detectors = [
                RuleEngine(),
                JoinBurstDetector(),
                RepeatedContentDetector(),
                ActivitySpikeDetector(),
                *default_sequence_detectors(),
            ]

    def register(self, detector: Detector) -> None:
        self.detectors.append(detector)

    def detect(self, event: SecurityEvent, storage, config) -> List[SecuritySignal]:
        out: List[SecuritySignal] = []
        seen = set()
        for d in self.detectors:
            try:
                signals = d.detect(event, storage, config) or []
            except Exception:
                logger.exception("detector %s failed (isolated)",
                                 getattr(d, "name", type(d).__name__))
                continue
            for s in signals:
                if s.dedup_key not in seen:
                    out.append(s)
                    seen.add(s.dedup_key)
        return out
