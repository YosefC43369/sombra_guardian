"""Coverage analytics: aggregation across exercises + summary math."""

from __future__ import annotations

from purple_range.coverage import CoverageAnalytics
from purple_range.models import CoverageCell

from .conftest import CHAT


def test_program_matrix_overlays_library(service, engagement):
    # before any exercise: library techniques appear as not-exercised
    cells0, summary0 = service.coverage_matrix(CHAT)
    assert summary0["total_techniques"] >= 5
    assert summary0["exercised"] == 0

    # after instantiating a plan: its techniques show as exercised
    service.instantiate_plan("discovery-baseline", CHAT, engagement, 42)
    cells, summary = service.coverage_matrix(CHAT)
    exercised_ids = {c.technique_id for c in cells if c.exercised}
    assert {"T1082", "T1049"} <= exercised_ids
    assert summary["exercised"] >= 5


def test_summarize_math():
    cells = [
        CoverageCell("T1", "discovery", "n1", True, "DETECTION", 2),
        CoverageCell("T2", "discovery", "n2", True, "PARTIAL", 1),
        CoverageCell("T3", "execution", "n3", False, "NONE", 0),
        CoverageCell("T4", "execution", "n4", False, "NONE", 0),
    ]
    s = CoverageAnalytics().summarize(cells)
    assert s["total_techniques"] == 4
    assert s["exercised"] == 2 and s["exercised_pct"] == 50.0
    assert s["detection"] == 1 and s["detection_pct"] == 25.0
    assert s["by_state"]["NONE"] == 2
    assert s["by_tactic"]["discovery"]["detection"] == 1


def test_snapshot_persists(service, engagement):
    service.instantiate_plan("discovery-baseline", CHAT, engagement, 42)
    out = service.coverage_snapshot(CHAT, 42)
    assert out["summary"]["total_techniques"] >= 5
    latest = service.store.latest_coverage_snapshot(CHAT)
    assert latest is not None and latest["summary"]["total_techniques"] >= 5
