"""
blueteam/platform/circuit_breaker.py — per-source circuit breaker (A6).

closed → (failures >= threshold) → open → (after cooldown) → half-open →
(success) → closed | (failure) → open. Injectable clock for deterministic tests.
Guards external feeds and any slow/failing dependency so one bad source cannot
stall the scheduler or event loop.
"""

from __future__ import annotations

from typing import Callable


class CircuitBreaker:
    CLOSED, OPEN, HALF_OPEN = "closed", "open", "half_open"

    def __init__(self, name: str, *, failure_threshold: int = 5,
                 cooldown_s: float = 300.0, clock: Callable[[], float] = None):
        self.name = name
        self._threshold = failure_threshold
        self._cooldown = cooldown_s
        self._clock = clock or (lambda: __import__("time").time())
        self._failures = 0
        self._state = self.CLOSED
        self._opened_at = 0.0

    @property
    def state(self) -> str:
        if self._state == self.OPEN and (self._clock() - self._opened_at) >= self._cooldown:
            self._state = self.HALF_OPEN
        return self._state

    def allow(self) -> bool:
        """True if a call may proceed now."""
        return self.state in (self.CLOSED, self.HALF_OPEN)

    def record_success(self) -> None:
        self._failures = 0
        self._state = self.CLOSED

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self._threshold or self._state == self.HALF_OPEN:
            self._state = self.OPEN
            self._opened_at = self._clock()

    def snapshot(self) -> dict:
        return {"name": self.name, "state": self.state, "failures": self._failures}


__all__ = ["CircuitBreaker"]
