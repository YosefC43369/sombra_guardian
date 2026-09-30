"""
group_soc/pipeline/queue.py — a synchronous bounded ring buffer.

Not every consumer wants an asyncio.Queue: the correlation window buffers (per chat)
need a small, fixed-size, thread-free ring the detectors can scan. This is that —
a deque-backed bounded buffer with O(1) append and eviction of the oldest item.
The async ingest queue lives in dispatcher.PipelineWorker; this is for in-memory
windows.
"""

from __future__ import annotations

from collections import deque
from typing import Deque, Generic, Iterable, List, TypeVar

T = TypeVar("T")


class BoundedRing(Generic[T]):
    def __init__(self, maxlen: int = 512):
        self._dq: Deque[T] = deque(maxlen=max(1, int(maxlen)))

    def append(self, item: T) -> None:
        self._dq.append(item)

    def extend(self, items: Iterable[T]) -> None:
        self._dq.extend(items)

    def snapshot(self) -> List[T]:
        return list(self._dq)

    def clear(self) -> None:
        self._dq.clear()

    def __len__(self) -> int:
        return len(self._dq)

    def __iter__(self):
        return iter(list(self._dq))
