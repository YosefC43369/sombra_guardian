"""
purple_range/service.py — the facade the commands and runtime call.

Wires the plan registry, purpleteam bridge, telemetry synthesizer, expectation catalog,
coverage analytics and the (opt-in) bus replay into one object. Pure Python; no Telegram.
Every method fails closed and surfaces a clear error.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Tuple

from .config import PurpleRangeConfig, get_config
from .models import Plan, TelemetryEvent, Expectation, CoverageCell
from .storage import PurpleRangeStore
from .plans import PlanRegistry
from .integrations import PurpleteamBridge, InstantiationResult, SocBridge
from .telemetry import TelemetrySynthesizer
from .expectations import expectation_for, merge_expectation
from .coverage import CoverageAnalytics
from .attack import get_catalog

logger = logging.getLogger("modbot.purple_range.service")


class PurpleRangeService:
    def __init__(self, db_path: str = "bot.db", *,
                 config: Optional[PurpleRangeConfig] = None, emit=None):
        self.db_path = db_path
        self.config = config or get_config()
        self.store = PurpleRangeStore(db_path)
        self.registry = PlanRegistry(store=self.store)
        self.bridge = PurpleteamBridge(store=self.store)
        self.soc_bridge = SocBridge(self.config, emit=emit)
        self.coverage = CoverageAnalytics(store=self.store, plan_registry=self.registry)
        self.synth = TelemetrySynthesizer(base_seed=self.config.default_seed,
                                          max_events=self.config.telemetry_max_events)
        self.catalog = get_catalog()

    def set_emit(self, emit) -> None:
        self.soc_bridge.emit = emit

    # ---- plans ----
    def list_plans(self) -> List[Plan]:
        return self.registry.list_all()

    def get_plan(self, code: str) -> Plan:
        return self.registry.require(code)

    def instantiate_plan(self, plan_code: str, chat_id: int, engagement_id: int,
                         operator_id: int) -> InstantiationResult:
        plan = self.registry.require(plan_code)
        return self.bridge.instantiate(plan, chat_id, engagement_id, operator_id)

    def list_instantiations(self, chat_id: int):
        return self.store.list_instantiations(chat_id)

    # ---- telemetry ----
    def generate_telemetry(self, technique_id: str, per_type: int = 1) -> List[TelemetryEvent]:
        exp = expectation_for(technique_id)
        return self.synth.for_technique(technique_id, exp.expected_telemetry, per_type)

    def generate_plan_telemetry(self, plan_code: str, per_type: int = 1) -> List[TelemetryEvent]:
        return self.synth.for_plan(self.registry.require(plan_code), per_type)

    def replay_to_bus(self, chat_id: int, exercise_id: Optional[int],
                      events: List[TelemetryEvent]) -> int:
        return self.soc_bridge.replay(chat_id, exercise_id, events)

    # ---- expectations ----
    def expectations(self, technique_id: str) -> Expectation:
        return expectation_for(technique_id)

    # ---- coverage ----
    def coverage_matrix(self, chat_id: int) -> Tuple[List[CoverageCell], dict]:
        cells = self.coverage.program_matrix(chat_id)
        return cells, self.coverage.summarize(cells)

    def coverage_snapshot(self, chat_id: int, taken_by: Optional[int]) -> dict:
        return self.coverage.snapshot(chat_id, taken_by)

    # ---- health ----
    def health(self) -> dict:
        return {
            "enabled": self.config.enabled,
            "soc_bridge_enabled": self.config.soc_bridge_enabled,
            "builtin_plans": len(self.registry.builtin_codes()),
            "attack_catalog": self.catalog.available,
        }
