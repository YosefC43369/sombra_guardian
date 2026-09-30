"""
group_soc/pipeline/backpressure.py — bounded-queue accounting.

The SOC must never let a burst of events grow memory without bound. The queue is
size-capped; when it is full the oldest pending item is dropped and counted. These
counters feed /soc metrics so an operator can see when the SOC is shedding load.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class BackpressureStats:
    submitted: int = 0
    processed: int = 0
    dropped_overflow: int = 0
    dropped_error: int = 0
    max_depth_seen: int = 0

    def as_dict(self) -> dict:
        return {
            "submitted": self.submitted,
            "processed": self.processed,
            "dropped_overflow": self.dropped_overflow,
            "dropped_error": self.dropped_error,
            "max_depth_seen": self.max_depth_seen,
            "in_flight": max(0, self.submitted - self.processed
                             - self.dropped_overflow - self.dropped_error),
        }
