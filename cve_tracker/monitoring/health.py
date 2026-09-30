"""
cve_tracker.monitoring.health — roll per-source state into health verdicts.

Maps a :class:`SourceState`'s rolling counters into a
:class:`~cve_tracker.enums.SourceHealthState` (rule §29): a run of consecutive
failures degrades then fails a source; a recent success restores it. The overall
subsystem health is the worst of its enabled sources, tempered by whether any
source is succeeding at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from ..enums import SourceHealthState
from ..models import SourceState
from ..utils import now_epoch, humanize_ago

DEGRADED_AFTER = 2      # consecutive failures
FAILING_AFTER = 5       # consecutive failures
STALE_AFTER_S = 3600    # no success in this long → degraded even w/o errors


def evaluate_source(state: SourceState, *, enabled: bool = True) -> str:
    if not enabled:
        return SourceHealthState.DISABLED.value
    if state.consecutive_failures >= FAILING_AFTER:
        return SourceHealthState.FAILING.value
    if state.consecutive_failures >= DEGRADED_AFTER:
        return SourceHealthState.DEGRADED.value
    if state.last_success_at is None and state.total_runs > 0:
        return SourceHealthState.DEGRADED.value
    if state.last_success_at and (now_epoch() - state.last_success_at) > STALE_AFTER_S * 6:
        return SourceHealthState.DEGRADED.value
    if state.last_success_at is None:
        return SourceHealthState.UNKNOWN.value
    return SourceHealthState.HEALTHY.value


@dataclass
class HealthReport:
    overall: str
    sources: Dict[str, dict]
    healthy_count: int
    total_count: int

    @property
    def ok(self) -> bool:
        return self.overall in (SourceHealthState.HEALTHY.value,
                                SourceHealthState.DEGRADED.value)


class HealthTracker:
    def __init__(self, repo, config):
        self.repo = repo
        self.config = config

    def report(self) -> HealthReport:
        enabled_names = {s.name for s in self.config.enabled_sources()}
        states = self.repo.all_source_states()
        by_name = {s.source: s for s in states}

        sources: Dict[str, dict] = {}
        healthy = 0
        worst_rank = 0
        rank = {
            SourceHealthState.HEALTHY.value: 0,
            SourceHealthState.UNKNOWN.value: 1,
            SourceHealthState.DEGRADED.value: 2,
            SourceHealthState.FAILING.value: 3,
            SourceHealthState.DISABLED.value: 0,
        }
        for name in sorted(enabled_names | set(by_name)):
            enabled = name in enabled_names
            st = by_name.get(name, SourceState(source=name))
            verdict = evaluate_source(st, enabled=enabled)
            if verdict == SourceHealthState.HEALTHY.value:
                healthy += 1
            if enabled:
                worst_rank = max(worst_rank, rank.get(verdict, 0))
            sources[name] = {
                "health": verdict,
                "last_success": humanize_ago(st.last_success_at) if st.last_success_at else "ยังไม่เคย",
                "consecutive_failures": st.consecutive_failures,
                "records_new": st.records_new,
                "last_error": st.last_error,
                "latency_ms": st.last_latency_ms,
            }

        overall = {
            0: SourceHealthState.HEALTHY.value,
            1: SourceHealthState.UNKNOWN.value,
            2: SourceHealthState.DEGRADED.value,
            3: SourceHealthState.FAILING.value,
        }.get(worst_rank, SourceHealthState.UNKNOWN.value)

        return HealthReport(overall=overall, sources=sources,
                            healthy_count=healthy, total_count=len(enabled_names))
