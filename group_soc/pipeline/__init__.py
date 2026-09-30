"""group_soc.pipeline — bounded async ingest + ordered, isolated processing stages."""

from .stages import PipelineStage, PipelineContext
from .pipeline import Pipeline
from .dispatcher import PipelineWorker
from .backpressure import BackpressureStats
from .queue import BoundedRing

__all__ = [
    "PipelineStage", "PipelineContext", "Pipeline", "PipelineWorker",
    "BackpressureStats", "BoundedRing",
]
