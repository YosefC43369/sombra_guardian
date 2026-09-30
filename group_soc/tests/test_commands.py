"""Command dispatcher: activation, overview, alert ops, watchlist, reports, help."""

from __future__ import annotations

from group_soc.commands import SocCommandService
from group_soc.models import Alert
from group_soc.util import hash_id

from .conftest import CHAT

ADMIN = 42


def _svc(runtime):
    return SocCommandService(runtime)


def test_activation_toggle(runtime):
    svc = _svc(runtime)
    # runtime fixture already activates; toggle off then on
    assert "deactivated" in svc.dispatch(CHAT, ADMIN, ["off"])
    assert runtime.storage.is_group_active(CHAT) is False
    assert "activated" in svc.dispatch(CHAT, ADMIN, ["on"])
    assert runtime.storage.is_group_active(CHAT) is True


def test_overview_and_status(runtime):
    svc = _svc(runtime)
    assert "SOMBRA SOC" in svc.dispatch(CHAT, ADMIN, ["overview"])
    st = svc.dispatch(CHAT, ADMIN, ["status"])
    assert "capabilities" in st and "ingest: on" in st


def test_help_on_unknown(runtime):
    assert "commands" in _svc(runtime).dispatch(CHAT, ADMIN, ["florb"]).lower()


def test_alert_lifecycle_via_commands(runtime):
    # seed an alert directly
    a = Alert(chat_id=CHAT, dedup_key="k", title="Join burst", status="new", priority_band="P2")
    runtime.storage.alerts.add(a)
    svc = _svc(runtime)
    listing = svc.dispatch(CHAT, ADMIN, ["alerts"])
    assert a.alert_id in listing
    assert "acknowledged" in svc.dispatch(CHAT, ADMIN, ["alert", "ack", a.alert_id])
    detail = svc.dispatch(CHAT, ADMIN, ["alert", a.alert_id])
    assert "acknowledged" in detail


def test_watchlist_commands(runtime):
    svc = _svc(runtime)
    assert "watching" in svc.dispatch(CHAT, ADMIN, ["watch", "domain", "evil.com"])
    listing = svc.dispatch(CHAT, ADMIN, ["watchlist"])
    assert "evil" in listing
    assert "removed" in svc.dispatch(CHAT, ADMIN, ["unwatch", "domain", "evil.com"])


def test_case_and_incident_commands(runtime):
    svc = _svc(runtime)
    out = svc.dispatch(CHAT, ADMIN, ["cases", "create", "Investigate", "spam"])
    assert "case created" in out
    out2 = svc.dispatch(CHAT, ADMIN, ["incident", "create", "raid", "Raid", "wave"])
    assert "created" in out2


def test_report_commands(runtime):
    svc = _svc(runtime)
    assert "SOMBRA SOC REPORT" in svc.dispatch(CHAT, ADMIN, ["report", "daily"])
    assert "SOMBRA SOC REPORT" in svc.dispatch(CHAT, ADMIN, ["report", "technical"])


def test_dispatch_never_raises(runtime):
    # malformed args must return text, never raise
    assert isinstance(_svc(runtime).dispatch(CHAT, ADMIN, ["alert", "ack"]), str)
    assert isinstance(_svc(runtime).dispatch(CHAT, None, []), str)
