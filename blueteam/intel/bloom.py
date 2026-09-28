"""
blueteam/intel/bloom.py — a small self-written Bloom filter (pure; stdlib only).

A **negative fast path** for the lookup engine: ``maybe_contains`` returns False
with certainty (the value was never added) or True with a bounded false-positive
rate (the value *might* be present -> fall through to the exact structures). It
never yields false negatives, which is exactly the guarantee a pre-filter needs.

Sizing is derived from a target item count ``n`` and false-positive rate ``p`` by
the standard formulas ``m = -n·ln p / (ln 2)^2`` and ``k = (m/n)·ln 2``. The bit
array is a stdlib ``bytearray``; hashing is double-hashing over a single
blake2b digest (Kirsch–Mitzenmacher), so we pay one hash per probe, not k.
"""

from __future__ import annotations

import hashlib
import math
from typing import Iterable


class BloomFilter:
    __slots__ = ("m", "k", "_bits", "_added")

    def __init__(self, capacity: int = 100_000, error_rate: float = 0.001):
        n = max(1, int(capacity))
        p = min(0.5, max(1e-9, float(error_rate)))
        m = int(math.ceil(-n * math.log(p) / (math.log(2) ** 2)))
        m = max(8, m)
        # round up to a whole byte
        m = ((m + 7) // 8) * 8
        k = max(1, int(round((m / n) * math.log(2))))
        self.m = m
        self.k = k
        self._bits = bytearray(m // 8)
        self._added = 0

    def _indices(self, value: str):
        # one digest -> two 64-bit halves -> k indices by double hashing
        d = hashlib.blake2b(value.encode("utf-8"), digest_size=16).digest()
        h1 = int.from_bytes(d[:8], "big")
        h2 = int.from_bytes(d[8:], "big") | 1  # odd, so it strides the whole ring
        for i in range(self.k):
            yield (h1 + i * h2) % self.m

    def add(self, value: str) -> None:
        for idx in self._indices(value):
            self._bits[idx >> 3] |= (1 << (idx & 7))
        self._added += 1

    def add_all(self, values: Iterable[str]) -> None:
        for v in values:
            self.add(v)

    def maybe_contains(self, value: str) -> bool:
        for idx in self._indices(value):
            if not (self._bits[idx >> 3] & (1 << (idx & 7))):
                return False           # certain: never added
        return True                    # probable: verify against exact set

    def __contains__(self, value: str) -> bool:
        return self.maybe_contains(value)

    @property
    def added(self) -> int:
        return self._added

    def fill_ratio(self) -> float:
        set_bits = sum(bin(b).count("1") for b in self._bits)
        return set_bits / self.m if self.m else 0.0


__all__ = ["BloomFilter"]
