"""End-to-end: plugin metadata + the full plan→exercise→coverage flow."""

from __future__ import annotations

from .conftest import CHAT


def test_plugin_metadata():
    from plugins.builtin.purple_range_suite import PurpleRangePlugin
    from plugins.base import PermissionLevel
    p = PurpleRangePlugin()
    assert p.name == "purple-range"
    assert PermissionLevel.parse(p.permission) == PermissionLevel.ADMIN


def test_full_flow(service, engagement):
    import purpleteam
    # 1) instantiate a plan -> real purpleteam exercise
    res = service.instantiate_plan("credential-access-sim", CHAT, engagement, 42)
    assert res.steps_added == 3
    # 2) the exercise is owned by purpleteam and bound to the engagement
    ex = purpleteam.get_exercise(res.exercise_id)
    assert ex["engagement_id"] == engagement
    # 3) synthetic telemetry generated for the plan
    tel = service.generate_plan_telemetry("credential-access-sim")
    assert tel and all(e.source == "purple_range_sim" for e in tel)
    # 4) coverage reflects the exercised techniques
    _cells, summary = service.coverage_matrix(CHAT)
    assert summary["exercised"] >= 3
    # 5) snapshot persists
    out = service.coverage_snapshot(CHAT, 42)
    assert out["summary"]["total_techniques"] >= 3


def test_runtime_cache(legacy_db, config):
    from purple_range.runtime import get_runtime, reset_runtimes
    reset_runtimes()
    a = get_runtime(legacy_db, config=config)
    b = get_runtime(legacy_db, config=config)
    assert a is b       # cached per db_path
