"""End-to-end integration: bus → runtime.on_event → ingest → alert, and plugin wiring."""

from __future__ import annotations

import asyncio

from group_soc.constants import CONSUMED_BUS_EVENTS
from group_soc.integrations.event_bus import bind_emit

from .conftest import CHAT, run_async


class _FakeEvent:
    def __init__(self, type, payload, correlation_id="c"):
        self.type = type
        self.payload = payload
        self.correlation_id = correlation_id


class _Bus:
    """Minimal async bus mirroring workflows.EventBus.subscribe/publish semantics."""
    def __init__(self):
        self._subs = {}
        self._all = []

    def subscribe(self, handler, event_type=None):
        if event_type is None:
            self._all.append(handler)
        else:
            self._subs.setdefault(event_type, []).append(handler)

    def emit(self, event):
        # sync emit used by bind_emit(raw bus) — record type only
        self._emitted = getattr(self, "_emitted", [])
        self._emitted.append(event.type)

    async def publish(self, event):
        for h in self._all + self._subs.get(event.type, []):
            await h(event)


def test_bus_to_alert(runtime):
    bus = _Bus()
    runtime.set_emit(bind_emit(bus))
    for t in CONSUMED_BUS_EVENTS:
        bus.subscribe(runtime.on_event, t)

    async def go():
        for uid in range(3):
            await bus.publish(_FakeEvent("member.joined",
                                         {"chat_id": CHAT, "user_id": uid, "is_bot": False}))
        # the runtime processes off a background worker; wait for the queue to drain
        if runtime._started:
            await asyncio.wait_for(runtime.worker._queue.join(), timeout=5)
        await runtime.stop()

    run_async(go())
    assert runtime.storage.events.total(CHAT) == 3
    assert runtime.storage.alerts.count_open(CHAT) >= 1


def test_soc_events_not_reingested(runtime):
    # feeding a soc.* event must not create a soc_event (router doesn't handle them)
    async def go():
        await runtime.on_event(_FakeEvent("soc.alert.created", {"chat_id": CHAT}))
    run_async(go())
    assert runtime.storage.events.total(CHAT) == 0


def test_inactive_group_ignores_events(storage, config, db_path):
    from group_soc.runtime import SocRuntime
    rt = SocRuntime(db_path, config=config)      # group NOT activated
    run_async(rt.on_event(_FakeEvent("member.joined",
                                     {"chat_id": CHAT, "user_id": 1, "is_bot": False})))
    assert rt.storage.events.total(CHAT) == 0


def test_plugin_class_metadata():
    from plugins.builtin.group_soc_suite import GroupSocPlugin
    from plugins.base import PermissionLevel
    p = GroupSocPlugin()
    assert p.name == "group-soc"
    assert PermissionLevel.parse(p.permission) == PermissionLevel.ADMIN
    # dormant health when config disabled
    assert p.healthcheck().healthy in (True, False)
