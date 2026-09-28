"""blueteam/platform/clock.py — injectable clock so time-dependent logic
(scheduler, aggregation windows, decay) is deterministic in tests."""

from __future__ import annotations

import time
from typing import Callable


class Clock:
    """Wall-clock by default; tests inject a fake via ``Clock(fake_fn)``."""

    def __init__(self, now_fn: Callable[[], float] = time.time):
        self._now = now_fn

    def now(self) -> float:
        return self._now()

    def now_ms(self) -> int:
        return int(self._now() * 1000)


class FakeClock:
    """Deterministic clock for tests: ``fc.advance(30)`` moves time forward."""

    def __init__(self, start: float = 0.0):
        self._t = float(start)

    def __call__(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += seconds

    def set(self, value: float) -> None:
        self._t = float(value)


__all__ = ["Clock", "FakeClock"]
