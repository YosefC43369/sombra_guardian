"""
group_soc/runtime.py — the SOC orchestration seam.

One runtime per database (cached via :func:`get_runtime`, mirroring blueteam.runtime).
It owns the storage bundle, the engines, the pipeline + background worker, and the
manager objects the commands delegate to. Plugins stay thin: they subscribe
``on_event`` and register commands, all of which route here.

FAILURE ISOLATION: ``on_event`` never raises into the bus — a SOC error can never break
the moderation/event flow that produced the event (rule §15/§21).
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

from .config import SocConfig, get_config
from .storage import StorageBundle
from .collector import EventRouter
from .normalization import Normalizer
from .correlation import CorrelationEngine
from .detection import DetectorManager
from .prioritization import PriorityEngine
from .alerts import AlertManager
from .cases import CaseManager
from .incidents import IncidentManager
from .investigation import Investigator
from .watchlist import WatchlistManager
from .metrics import SocMetrics, DetectionMetrics, performance_snapshot
from .reporting import ReportBuilder
from .stories import StoryGenerator
from .timeline import TimelineBuilder
from .pipeline import Pipeline, PipelineWorker, PipelineContext
from .pipeline.soc_stages import (
    GateStage, EnrichStage, PersistStage, CorrelateStage, DetectStage,
    PersistSignalsStage, AlertStage,
)
from .integrations import MemberIncidentAdapter, IntegrityAnchor, ThreatIntelAdapter
from .integrations.event_bus import bind_emit

logger = logging.getLogger("modbot.group_soc.runtime")


class SocRuntime:
    def __init__(self, db_path: str = "bot.db", *, config: Optional[SocConfig] = None,
                 emit: Optional[Callable[[str, dict], None]] = None):
        self.db_path = db_path
        self.config = config or get_config()

        # storage + normalization
        self.storage = StorageBundle(db_path)
        self.router = EventRouter()
        self.normalizer = Normalizer(redact_text=self.config.redact_message_text)

        # engines
        self.correlation = CorrelationEngine()
        self.detection = DetectorManager()
        self.priority = PriorityEngine()

        # integrations (defensive, reuse existing systems)
        self.member_bridge = MemberIncidentAdapter()
        self.integrity = IntegrityAnchor()
        self.intel = ThreatIntelAdapter(self.config)

        # managers
        self.alerts = AlertManager(self.storage, self.config, self.priority)
        self.cases = CaseManager(self.storage)
        self.incidents = IncidentManager(
            self.storage,
            member_bridge=self.member_bridge.create_member_incident,
            containment=self._containment_hook)
        self.investigator = Investigator(self.storage)
        self.watchlist = WatchlistManager(self.storage)

        # presentation / metrics
        self.metrics = SocMetrics(self.storage)
        self.detection_metrics = DetectionMetrics(self.storage)
        self.reports = ReportBuilder(self.storage)
        self.story = StoryGenerator(self.storage)
        self.timeline = TimelineBuilder(self.storage)

        # emit binding
        self.emit = emit

        # pipeline + worker
        self.pipeline = Pipeline([
            GateStage(), EnrichStage(), PersistStage(),
            CorrelateStage(self.correlation), DetectStage(self.detection),
            PersistSignalsStage(), AlertStage(self.alerts),
        ])
        self.worker = PipelineWorker(
            self.pipeline, maxsize=self.config.queue_maxsize,
            poll_interval=self.config.worker_poll_interval_s)
        self._started = False

    # ---- emit rebinding (set once the bus/platform exists) ----
    def set_emit(self, emit: Optional[Callable[[str, dict], None]]) -> None:
        self.emit = emit

    def bind_host(self, host: Any) -> None:
        self.emit = bind_emit(host)

    # ---- lifecycle ----
    def start(self) -> None:
        if self._started:
            return
        self.worker.start()
        self._started = True
        logger.info("SOC runtime started for %s", self.db_path)

    async def stop(self) -> None:
        await self.worker.stop()
        self._started = False

    # ---- containment hook (records intent; TG side-effects belong to blueteam actions) ----
    def _containment_hook(self, incident) -> str:
        # The SOC does not itself restrict/ban — that authority lives with the existing
        # moderation/blueteam layer. It records a containment recommendation for the audit
        # trail; an operator (or a wired action) carries it out.
        return f"containment recommended for {incident.classification}"

    # ---- the bus handler (subscribed by the plugin) ----
    async def on_event(self, event) -> None:
        """Bus subscriber. ``event`` is a workflows.models.Event (type + payload)."""
        try:
            if not self.config.capability_enabled("ingest"):
                return
            # lazily start the background worker the first time we run inside a loop
            if not self._started:
                self.start()
            raw = self.router.route(
                getattr(event, "type", ""), getattr(event, "payload", {}) or {},
                correlation_id=getattr(event, "correlation_id", None))
            if raw is None:
                return
            sev = self.normalizer.normalize(raw)
            ctx = PipelineContext(event=sev, storage=self.storage, config=self.config,
                                  emit=self.emit)
            if self._started:
                self.worker.submit(ctx)      # off the handler path
            else:
                await self.worker.process_now(ctx)
        except Exception:
            logger.exception("SOC on_event failed (isolated)")

    # ---- health ----
    def health(self) -> Dict[str, Any]:
        return {
            "db": self.db_path,
            "enabled": self.config.enabled,
            "worker_started": self._started,
            "performance": performance_snapshot(self.worker),
            "integrations": {
                "member_incident": self.member_bridge.available,
                "integrity_ledger": self.integrity.available,
                "intel_enrichment": self.intel.enabled,
            },
        }


# ---- per-db cache (mirrors blueteam.get_runtime) ----
_RUNTIMES: Dict[str, SocRuntime] = {}


def get_runtime(db_path: str = "bot.db", *,
                emit: Optional[Callable[[str, dict], None]] = None,
                config: Optional[SocConfig] = None) -> SocRuntime:
    rt = _RUNTIMES.get(db_path)
    if rt is None:
        rt = SocRuntime(db_path, config=config, emit=emit)
        _RUNTIMES[db_path] = rt
    elif emit is not None:
        rt.set_emit(emit)
    return rt


def reset_runtimes() -> None:
    """Test helper: drop cached runtimes."""
    _RUNTIMES.clear()
