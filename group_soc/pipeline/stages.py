"""
group_soc/pipeline/stages.py — the pipeline stage contract and shared context.

A stage is a small, single-purpose async step. Stages are ordered and composable;
a new detector is a new stage (or a detector registered with the DetectStage),
never an edit to the pipeline runner. Each stage reads/writes the shared
:class:`PipelineContext`. Failures are isolated by the runner, so one bad stage
degrades that step to a no-op rather than dropping the event.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from ..models.event import SecurityEvent
from ..models.signal import SecuritySignal
from ..models.alert import Alert


@dataclass
class PipelineContext:
    event: SecurityEvent
    storage: Any                       # StorageBundle
    config: Any                        # SocConfig
    emit: Optional[Any] = None         # callable(event_type: str, payload: dict) or None

    signals: List[SecuritySignal] = field(default_factory=list)
    alerts: List[Alert] = field(default_factory=list)
    stop: bool = False                 # a stage may set this to halt the pipeline
    log: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def note(self, msg: str) -> None:
        self.log.append(msg)

    def add_signal(self, signal: SecuritySignal) -> None:
        if signal is not None:
            self.signals.append(signal)


@runtime_checkable
class PipelineStage(Protocol):
    name: str

    async def process(self, ctx: PipelineContext) -> PipelineContext:
        ...
