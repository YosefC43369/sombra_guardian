"""Pipeline: gate, ordering, PII-safe persist, correlate/detect/alert, backpressure."""

from __future__ import annotations

import asyncio
import dataclasses

from group_soc.pipeline import Pipeline, PipelineContext, PipelineWorker, BoundedRing
from group_soc.pipeline.soc_stages import (
    GateStage, EnrichStage, PersistStage, CorrelateStage, DetectStage,
    PersistSignalsStage, AlertStage,
)
from group_soc.correlation import CorrelationEngine
from group_soc.detection import DetectorManager
from group_soc.alerts import AlertManager
from group_soc.collector import EventRouter
from group_soc.normalization import Normalizer

from .conftest import CHAT, run_async


def _pipeline(storage, config):
    return Pipeline([
        GateStage(), EnrichStage(), PersistStage(),
        CorrelateStage(CorrelationEngine()), DetectStage(DetectorManager()),
        PersistSignalsStage(), AlertStage(AlertManager(storage, config)),
    ])


def _ctx(storage, config, bus_type, payload, emitted):
    raw = EventRouter().route(bus_type, payload)
    ev = Normalizer().normalize(raw)
    return PipelineContext(event=ev, storage=storage, config=config,
                           emit=lambda t, p: emitted.append(t))


def test_gate_stops_when_group_inactive(storage, config):
    # group NOT activated → gate stops, nothing persisted
    emitted = []
    pipe = _pipeline(storage, config)
    ctx = _ctx(storage, config, "member.joined",
               {"chat_id": CHAT, "user_id": 1, "is_bot": False}, emitted)
    run_async(pipe.run(ctx))
    assert ctx.stop is True and storage.events.total(CHAT) == 0


def test_full_flow_join_burst(storage, config):
    storage.set_policy(CHAT, enabled=True, mode="alert")
    emitted = []
    pipe = _pipeline(storage, config)

    async def go():
        last = None
        for uid in range(3):
            ctx = _ctx(storage, config, "member.joined",
                       {"chat_id": CHAT, "user_id": uid, "is_bot": False}, emitted)
            last = await pipe.run(ctx)
        return last

    last = run_async(go())
    assert storage.events.total(CHAT) == 3
    assert any("join_burst" in s.producer for s in last.signals)
    assert last.alerts, "expected an alert"
    assert "soc.alert.created" in emitted and "soc.event.recorded" in emitted


def test_duplicate_event_short_circuits(storage, config):
    storage.set_policy(CHAT, enabled=True, mode="alert")
    emitted = []
    pipe = _pipeline(storage, config)
    payload = {"chat_id": CHAT, "user_id": 1, "is_bot": False}
    raw = EventRouter().route("member.joined", payload)
    ev = Normalizer().normalize(raw)
    from group_soc.pipeline import PipelineContext as PC
    c1 = PC(event=ev, storage=storage, config=config, emit=lambda t, p: emitted.append(t))
    c2 = PC(event=ev, storage=storage, config=config, emit=lambda t, p: emitted.append(t))
    run_async(pipe.run(c1))
    run_async(pipe.run(c2))
    assert storage.events.total(CHAT) == 1     # idempotent
    assert c2.stop is True


def test_worker_backpressure_drops_oldest():
    async def go():
        pipe = Pipeline([])          # no-op pipeline
        worker = PipelineWorker(pipe, maxsize=16)
        # submit more than maxsize without draining
        accepted = 0
        for _ in range(40):
            if worker.submit(PipelineContext(event=None, storage=None, config=None)):
                accepted += 1
        assert worker.stats.dropped_overflow > 0
        assert worker.depth() <= 16
    run_async(go())


def test_bounded_ring_evicts_oldest():
    ring = BoundedRing(maxlen=3)
    for i in range(5):
        ring.append(i)
    assert ring.snapshot() == [2, 3, 4]
