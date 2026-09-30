"""The purpleteam bridge + service facade — governance is enforced, never bypassed."""

from __future__ import annotations

import pytest

from purple_range.exceptions import InstantiationError, PlanNotFoundError

from .conftest import CHAT


def test_instantiate_creates_purpleteam_exercise(service, engagement):
    import purpleteam
    res = service.instantiate_plan("discovery-baseline", CHAT, engagement, 42)
    assert res.steps_added == 5 and res.steps_failed == 0
    ex = purpleteam.get_exercise(res.exercise_id)
    assert ex["chat_id"] == CHAT and ex["engagement_id"] == engagement
    emus = purpleteam.list_emulations(res.exercise_id)
    assert sorted(e["technique_id"] for e in emus) == ["T1016", "T1049", "T1057", "T1082", "T1083"]


def test_instantiation_link_recorded(service, engagement):
    res = service.instantiate_plan("execution-scripting", CHAT, engagement, 42)
    rows = service.list_instantiations(CHAT)
    assert rows and rows[0]["exercise_id"] == res.exercise_id
    assert rows[0]["plan_code"] == "execution-scripting"


def test_wrong_chat_engagement_denied(service, engagement):
    # engagement belongs to CHAT; instantiating into a different chat must fail closed
    with pytest.raises(InstantiationError) as exc:
        service.instantiate_plan("discovery-baseline", 424242, engagement, 42)
    assert exc.value.context.get("reason") == "ENGAGEMENT_WRONG_CHAT"


def test_missing_engagement_denied(service):
    with pytest.raises(InstantiationError):
        service.instantiate_plan("discovery-baseline", CHAT, 999999, 42)


def test_unknown_plan_raises(service, engagement):
    with pytest.raises(PlanNotFoundError):
        service.instantiate_plan("no-such-plan", CHAT, engagement, 42)


def test_service_telemetry_and_expectations(service):
    tel = service.generate_telemetry("T1082", per_type=2)
    assert tel and all(e.source == "purple_range_sim" for e in tel)
    assert service.expectations("T1082").expected_rules == ["BT-SIM-001"]


def test_soc_bridge_disabled_by_default(service):
    tel = service.generate_telemetry("T1082")
    assert service.replay_to_bus(CHAT, None, tel) == 0     # soc_bridge off → 0 emitted
