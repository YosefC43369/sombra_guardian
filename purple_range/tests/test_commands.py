"""The /range command dispatcher."""

from __future__ import annotations

from purple_range.commands import RangeCommandService

from .conftest import CHAT

OP = 42


def _svc(service):
    return RangeCommandService(service)


def test_help_and_status(service):
    c = _svc(service)
    assert "PURPLE RANGE" in c.dispatch(CHAT, OP, ["help"])
    assert "builtin plans" in c.dispatch(CHAT, OP, ["status"])


def test_plans_and_plan_detail(service):
    c = _svc(service)
    assert "discovery-baseline" in c.dispatch(CHAT, OP, ["plans"])
    detail = c.dispatch(CHAT, OP, ["plan", "discovery-baseline"])
    assert "T1082" in detail and "instantiate" in detail


def test_instantiate_via_command(service, engagement):
    out = _svc(service).dispatch(CHAT, OP, ["instantiate", "discovery-baseline", str(engagement)])
    assert "Instantiated" in out and "/pt start" in out


def test_instantiate_bad_engagement_id(service):
    out = _svc(service).dispatch(CHAT, OP, ["instantiate", "discovery-baseline", "notanumber"])
    assert "must be a number" in out


def test_telemetry_and_expectations_commands(service):
    c = _svc(service)
    t = c.dispatch(CHAT, OP, ["telemetry", "T1082"])
    assert "SYNTHETIC TELEMETRY" in t and "synthetic" in t.lower()
    e = c.dispatch(CHAT, OP, ["expectations", "T1003"])
    assert "BT-SIM-020" in e


def test_coverage_command(service, engagement):
    service.instantiate_plan("discovery-baseline", CHAT, engagement, OP)
    out = _svc(service).dispatch(CHAT, OP, ["coverage"])
    assert "ATT&CK COVERAGE" in out and "techniques:" in out


def test_dispatch_never_raises(service):
    c = _svc(service)
    assert isinstance(c.dispatch(CHAT, OP, ["plan"]), str)          # missing arg
    assert isinstance(c.dispatch(CHAT, None, []), str)
    assert isinstance(c.dispatch(CHAT, OP, ["nonsense"]), str)
