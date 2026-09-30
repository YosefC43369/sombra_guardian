"""
group_soc/pipeline/pipeline.py — the ordered stage runner.

Runs a list of stages against a PipelineContext in order. Each stage is isolated:
a stage that raises is logged and skipped, so a single detector bug never drops the
event or breaks the ones after it (rule §15 / §21). A stage may set ``ctx.stop`` to
halt the remaining stages deliberately (e.g. ingest disabled).
"""

from __future__ import annotations

import logging
from typing import List

from .stages import PipelineStage, PipelineContext

logger = logging.getLogger("modbot.group_soc.pipeline")


class Pipeline:
    def __init__(self, stages: List[PipelineStage]):
        self.stages = list(stages)

    def stage_names(self) -> List[str]:
        return [getattr(s, "name", type(s).__name__) for s in self.stages]

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        for stage in self.stages:
            if ctx.stop:
                break
            name = getattr(stage, "name", type(stage).__name__)
            try:
                ctx = await stage.process(ctx)
            except Exception:
                logger.exception("pipeline stage %s failed (isolated)", name)
                ctx.note(f"stage {name} error")
        return ctx
