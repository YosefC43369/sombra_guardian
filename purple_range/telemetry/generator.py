"""
purple_range/telemetry/generator.py — deterministic synthetic telemetry.

Given a technique (and the telemetry types expected for it), emit a bounded, deterministic
list of TelemetryEvents. Deterministic = seeded by (base_seed, technique, event_type), so
a tuning cycle can regenerate the exact same fixtures. Nothing here touches a host,
process, file, or network — it only constructs dicts.
"""

from __future__ import annotations

import hashlib
import random
from typing import List, Optional

from ..models import TelemetryEvent, PlanStep, Plan
from ..constants import TelemetryEventType, VALID_TELEMETRY_TYPES, SYNTHETIC_SOURCE
from ..util import normalize_technique
from .templates import build_fields


class TelemetrySynthesizer:
    def __init__(self, base_seed: int = 1337, max_events: int = 200):
        self.base_seed = int(base_seed)
        self.max_events = max(1, int(max_events))

    def _seed_for(self, technique_id: str, event_type: str) -> int:
        # stable across processes (unlike hash(), which is salted by PYTHONHASHSEED)
        key = f"{self.base_seed}|{technique_id}|{event_type}".encode("utf-8")
        return int.from_bytes(hashlib.sha256(key).digest()[:4], "big")

    def for_technique(self, technique_id: str, event_types: List[str],
                      per_type: int = 1) -> List[TelemetryEvent]:
        tid = normalize_technique(technique_id)
        if not tid:
            return []
        types = [t for t in (event_types or []) if t in VALID_TELEMETRY_TYPES]
        if not types:
            types = [TelemetryEventType.SIMULATION_EVENT.value]
        out: List[TelemetryEvent] = []
        seq = 0
        for et in types:
            rng = random.Random(self._seed_for(tid, et))
            for i in range(max(1, int(per_type))):
                if len(out) >= self.max_events:
                    return out
                seq += 1
                out.append(TelemetryEvent(
                    event_type=et, technique_id=tid, seq=seq,
                    fields=build_fields(et, tid, rng, i), source=SYNTHETIC_SOURCE))
        return out

    def for_step(self, step: PlanStep, per_type: int = 1) -> List[TelemetryEvent]:
        return self.for_technique(step.technique_id,
                                  step.expectation.expected_telemetry, per_type)

    def for_plan(self, plan: Plan, per_type: int = 1) -> List[TelemetryEvent]:
        out: List[TelemetryEvent] = []
        for step in plan.steps:
            for ev in self.for_step(step, per_type):
                if len(out) >= self.max_events:
                    return out
                out.append(ev)
        return out
