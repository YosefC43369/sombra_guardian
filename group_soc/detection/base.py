"""
group_soc/detection/base.py — the detector contract.

A detector evaluates the current event (and bounded history) against a rule,
threshold, sequence or anomaly model and returns zero or more SecuritySignals.
Detection is second-order: it consumes SOC events (including upstream signals already
normalized into events) and never re-implements the primary detectors.
"""

from __future__ import annotations

from typing import List, Protocol, runtime_checkable

from ..models.event import SecurityEvent
from ..models.signal import SecuritySignal


@runtime_checkable
class Detector(Protocol):
    name: str

    def detect(self, event: SecurityEvent, storage, config) -> List[SecuritySignal]:
        ...
