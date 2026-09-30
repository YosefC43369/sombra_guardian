"""
group_soc/pipeline/soc_stages.py — the concrete SOC pipeline stages.

Wires the domain engines into ordered stages. Assembled once by the runtime:

    Gate → Enrich → Persist → Correlate → Detect → PersistSignals → Alert

Ordering rationale:
  * the event is persisted BEFORE correlation/detection so their windowed COUNTs
    include it (e.g. the 5th join triggers the burst),
  * enrichment runs before persist so the stored event already carries watchlist
    context,
  * signals are persisted before alerting so an alert can reference a stored signal.

Every stage is isolated by the pipeline runner; a stage failure degrades that step,
never the event.
"""

from __future__ import annotations

import logging

from ..constants import (
    SOC_EVENT_RECORDED, SOC_SIGNAL_CREATED, SOC_ALERT_CREATED, SOC_ALERT_ESCALATED,
)
from ..normalization.enrichment import enrich_with_watchlist
from .stages import PipelineContext

logger = logging.getLogger("modbot.group_soc.stages")


def _emit(ctx: PipelineContext, event_type: str, payload: dict) -> None:
    if ctx.emit is None or not ctx.config.capability_enabled("emit_events"):
        return
    try:
        ctx.emit(event_type, payload)
    except Exception:
        logger.debug("soc emit failed for %s", event_type, exc_info=True)


class GateStage:
    """Stop processing early when ingest is globally off or the group is inactive."""
    name = "gate"

    async def process(self, ctx: PipelineContext) -> PipelineContext:
        if not ctx.config.capability_enabled("ingest"):
            ctx.stop = True
            ctx.note("gate: ingest disabled")
            return ctx
        if not ctx.storage.is_group_active(ctx.event.chat_id):
            ctx.stop = True
            ctx.note("gate: group inactive")
        return ctx


class EnrichStage:
    name = "enrich"

    async def process(self, ctx: PipelineContext) -> PipelineContext:
        ctx.event = enrich_with_watchlist(ctx.event, ctx.storage.watchlist)
        return ctx


class PersistStage:
    name = "persist_event"

    async def process(self, ctx: PipelineContext) -> PipelineContext:
        inserted = ctx.storage.events.add(ctx.event)
        ctx.meta["event_inserted"] = inserted
        if inserted:
            _emit(ctx, SOC_EVENT_RECORDED, ctx.event.to_payload())
        else:
            # duplicate delivery — nothing more to do
            ctx.stop = True
            ctx.note("persist: duplicate event ignored")
        return ctx


class CorrelateStage:
    name = "correlate"

    def __init__(self, engine):
        self.engine = engine

    async def process(self, ctx: PipelineContext) -> PipelineContext:
        if not ctx.config.capability_enabled("correlation"):
            return ctx
        for sig in self.engine.correlate(ctx.event, ctx.storage, ctx.config):
            ctx.add_signal(sig)
        return ctx


class DetectStage:
    name = "detect"

    def __init__(self, manager):
        self.manager = manager

    async def process(self, ctx: PipelineContext) -> PipelineContext:
        if not ctx.config.capability_enabled("detection"):
            return ctx
        for sig in self.manager.detect(ctx.event, ctx.storage, ctx.config):
            ctx.add_signal(sig)
        return ctx


class PersistSignalsStage:
    name = "persist_signals"

    async def process(self, ctx: PipelineContext) -> PipelineContext:
        for sig in ctx.signals:
            try:
                if ctx.storage.signals.add(sig):
                    _emit(ctx, SOC_SIGNAL_CREATED, sig.to_payload())
            except Exception:
                logger.debug("signal persist failed", exc_info=True)
        return ctx


class AlertStage:
    name = "alert"

    def __init__(self, alert_manager):
        self.alerts = alert_manager

    async def process(self, ctx: PipelineContext) -> PipelineContext:
        if not ctx.config.capability_enabled("alerting"):
            return ctx
        for sig in ctx.signals:
            try:
                outcome = self.alerts.process_signal(sig)
            except Exception:
                logger.exception("alert processing failed for signal %s", sig.signal_id)
                continue
            if outcome.alert is None:
                continue
            if outcome.action == "created":
                ctx.alerts.append(outcome.alert)
                _emit(ctx, SOC_ALERT_CREATED, outcome.alert.to_payload())
            if outcome.escalated:
                _emit(ctx, SOC_ALERT_ESCALATED, outcome.alert.to_payload())
        return ctx
