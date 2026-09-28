"""
threat_actor_intelligence.scheduler — incremental scheduled ingestion.

A thin, dependency-free scheduler that drives the orchestrator on an interval,
honouring the incremental-only posture (conditional requests via the store's
``provider_state``). It is deliberately transport-agnostic: it exposes
``tick()`` (run one cycle now) and ``run_forever()`` (loop with sleep), so it can
be driven by ``app.py``'s existing background-task machinery, a cron, or a test
calling ``tick()`` directly. ``due_providers`` decides which providers are due
based on their last-run marker and the configured interval.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .configuration import TAIConfig, get_config
from .orchestrator import Orchestrator, OrchestrationResult


@dataclass
class SchedulerState:
    last_run: Dict[str, float] = field(default_factory=dict)
    runs: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"last_run": self.last_run, "runs": self.runs}


class IngestionScheduler:
    def __init__(self, orchestrator: Optional[Orchestrator] = None, *,
                 config: Optional[TAIConfig] = None):
        self.config = config or (orchestrator.config if orchestrator else get_config())
        self.orchestrator = orchestrator or Orchestrator(config=self.config)
        self.state = self._load_state()

    def _load_state(self) -> SchedulerState:
        raw = self.orchestrator.store.kv_get("scheduler", "state", {})
        return SchedulerState(last_run=dict(raw.get("last_run", {}) or {}),
                              runs=int(raw.get("runs", 0) or 0))

    def _save_state(self) -> None:
        self.orchestrator.store.kv_set("scheduler", "state", self.state.to_dict())

    def due_providers(self, *, now: Optional[float] = None) -> List[str]:
        now = now if now is not None else time.time()
        interval = self.config.poll_interval_seconds
        due = []
        for provider in self.config.available_providers():
            last = self.state.last_run.get(provider, 0.0)
            if now - last >= interval:
                due.append(provider)
        return due

    def tick(self, *, providers: Optional[List[str]] = None,
             correlate: bool = True, now: Optional[float] = None
             ) -> OrchestrationResult:  # pragma: no cover
        now = now if now is not None else time.time()
        providers = providers if providers is not None else self.due_providers(now=now)
        if not providers:
            return OrchestrationResult()
        result = self.orchestrator.run_all(providers=providers, correlate=correlate)
        for p in result.providers_run:
            self.state.last_run[p] = now
        self.state.runs += 1
        self._save_state()
        return result

    def run_forever(self, *, sleep: Callable[[float], None] = time.sleep,
                    max_cycles: int = 0) -> None:  # pragma: no cover
        cycles = 0
        while True:
            self.tick()
            cycles += 1
            if max_cycles and cycles >= max_cycles:
                return
            sleep(self.config.poll_interval_seconds)

    def status(self) -> Dict[str, Any]:
        return {"runs": self.state.runs, "last_run": self.state.last_run,
                "due_now": self.due_providers(),
                "interval_seconds": self.config.poll_interval_seconds,
                "incremental_only": self.config.incremental_only}


__all__ = ["IngestionScheduler", "SchedulerState"]
