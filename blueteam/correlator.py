"""
blueteam/correlator.py — cross-module correlation in a time window.

Individual signals are stronger together. The correlator remembers a little recent
context per (chat, user) — chiefly *when they joined* — so that when Link Guard or
Scam Guard flags them shortly after, it can raise a high-confidence, correlated
incident (spec example: "a new member posts a malicious link within 60s of joining").

Memory is bounded: a single LRU keyed by (chat_id, user_id) holds only a join
timestamp and a tiny recent-flag list, capped at ``max_entries`` entries and pruned
by age. It never stores message content — only timestamps and signal kinds. It ties
correlated events to the workflow engine via a ``correlation_id``.
"""

from __future__ import annotations

import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass(slots=True)
class _Ctx:
    join_ts: float = 0.0
    flags: List[Tuple[str, float]] = field(default_factory=list)  # (kind, ts)


@dataclass(slots=True)
class Correlation:
    kind: str
    chat_id: int
    user_id: int
    correlation_id: str
    detail: str
    boost: int
    evidence: Dict[str, object] = field(default_factory=dict)

    def to_event_payload(self, base: Optional[dict] = None) -> dict:
        payload = dict(base or {})
        payload.update({
            "chat_id": self.chat_id, "user_id": self.user_id,
            "correlation_kind": self.kind, "reason": self.detail,
            "severity": "high", "category": "CORRELATED_ABUSE",
            "detection_type": self.kind, "subject": self.correlation_id,
        })
        payload.update(self.evidence)
        return payload


class Correlator:
    def __init__(self, window_seconds: int = 60, max_entries: int = 20000,
                 flag_history: int = 5):
        self.window = window_seconds
        self.max_entries = max_entries
        self.flag_history = flag_history
        self._ctx: "OrderedDict[Tuple[int, int], _Ctx]" = OrderedDict()

    def _get(self, chat_id: int, user_id: int) -> _Ctx:
        key = (chat_id, user_id)
        ctx = self._ctx.get(key)
        if ctx is None:
            ctx = _Ctx()
            self._ctx[key] = ctx
        self._ctx.move_to_end(key)
        while len(self._ctx) > self.max_entries:
            self._ctx.popitem(last=False)
        return ctx

    def note_join(self, chat_id: int, user_id: int, now: Optional[float] = None) -> None:
        ctx = self._get(chat_id, user_id)
        ctx.join_ts = now if now is not None else time.time()
        ctx.flags = []

    def note_flag(self, chat_id: int, user_id: int, kind: str, score: int,
                  now: Optional[float] = None) -> Optional[Correlation]:
        """Record a Link/Scam flag and return a Correlation when it lines up with a
        recent join (new-member malicious activity) or repeated flags in-window."""
        now = now if now is not None else time.time()
        ctx = self._get(chat_id, user_id)
        ctx.flags.append((kind, now))
        if len(ctx.flags) > self.flag_history:
            ctx.flags = ctx.flags[-self.flag_history:]

        # (1) malicious activity shortly after joining
        if ctx.join_ts and (now - ctx.join_ts) <= self.window:
            age = round(now - ctx.join_ts, 1)
            return Correlation(
                kind="new_member_malicious", chat_id=chat_id, user_id=user_id,
                correlation_id=uuid.uuid4().hex,
                detail=f"สมาชิกใหม่ (เข้ากลุ่ม {age}s ก่อน) ถูกจับสัญญาณ {kind}",
                boost=25, evidence={"join_age_s": age, "trigger": kind, "score": score})

        # (2) multiple distinct flag kinds in-window (link + scam together)
        recent = [(k, t) for (k, t) in ctx.flags if now - t <= self.window]
        kinds = {k for (k, _t) in recent}
        if len(kinds) >= 2:
            return Correlation(
                kind="multi_signal", chat_id=chat_id, user_id=user_id,
                correlation_id=uuid.uuid4().hex,
                detail=f"หลายสัญญาณในช่วงเวลาสั้น: {sorted(kinds)}",
                boost=20, evidence={"kinds": sorted(kinds)})
        return None

    def size(self) -> int:
        return len(self._ctx)
