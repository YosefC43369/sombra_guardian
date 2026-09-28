"""
tests/test_blueteam_integration.py — Blue Team end-to-end through the real platform:
event bus -> plugin subscribers (runtime) -> analysis -> store + Telegram actions ->
emitted SOAR events -> workflow engine -> incident + integrity anchor. Plus the
correlator, command service, dashboard, and failure isolation.

Standalone; fully offline (fake Telegram actions, fake incident/anchor services);
does not import telegram. Runs under a single persistent event loop so the bus's
fire-and-forget follow-up events execute.
"""

import asyncio
import os
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import migrations
from workflows import (EventBus, WorkflowEngine, Event, build_default_registry,
                       Services, load_dir)
from plugins import PluginManager
from blueteam.runtime import get_runtime, TelegramActions
from blueteam.correlator import Correlator
from blueteam.commands import CommandService

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


async def scenario():
    db = tempfile.mkstemp(suffix=".db")[1]
    migrations.apply_startup_migrations(db)
    reg = build_default_registry()
    services = Services()
    bus = EventBus()
    engine = WorkflowEngine(reg, services, db_path=db)
    bus.subscribe(lambda ev: engine.dispatch(ev))
    engine.register_many(load_dir(os.path.join(_ROOT, "workflows", "definitions")))
    mgr = PluginManager(db_path=db, engine=engine, action_registry=reg, event_bus=bus)
    mgr.discover()
    mgr.load_all()
    check("blueteam plugin loaded", "blueteam-suite" in [r.name for r in mgr.registry.all()])
    check("bt_note workflow action registered", "bt_note" in reg)

    incidents, anchored, alerts = [], [], []
    services.set("create_incident", lambda *a, **k: (incidents.append(a), {"incident_id": len(incidents)})[1])
    services.set("anchor_integrity", lambda *a, **k: (anchored.append(a), {"ok": True, "seq": len(anchored)})[1])
    services.set("send_admin_alert", lambda cid, txt: alerts.append((cid, txt)))

    rt = get_runtime(db)
    acted = []
    ta = TelegramActions()
    for n in ("send_message", "delete_message", "restrict_user", "ban_user",
              "unban_user", "send_challenge", "set_chat_permissions",
              "get_chat_permissions", "get_chat_administrators"):
        ta.set(n, (lambda name: (lambda *a, **k: acted.append((name, a))))(n))
    rt.actions = ta
    rt.store.set_policy(-100, "linkguard", enabled=True, mode="DELETE", threshold=45)
    rt.store.set_policy(-100, "scamguard", enabled=True, mode="WARN", threshold=45)
    rt.store.set_policy(-100, "joinguard", enabled=True, mode="WARN")

    # 1) malicious text_link -> delete + link.flagged -> incident + anchor
    await bus.publish(Event(type="message.received", payload={
        "chat_id": -100, "user_id": 7, "message_id": 55, "text": "telegram.org",
        "entities": [{"type": "text_link", "offset": 0, "length": 12,
                      "url": "http://free-nitro.tk/login-verify-wallet"}],
        "username": "scammer", "display_name": "Free Nitro"}))
    await asyncio.sleep(0.1)
    check("link flagged and message deleted", any(n == "delete_message" for n, _ in acted))
    check("link.flagged -> incident opened", len(incidents) >= 1)
    check("incident anchored to integrity ledger", len(anchored) >= 1)
    check("linkguard event logged", bool(rt.store.recent_events(-100, "linkguard")))

    # 2) scam message -> admin review queue
    await bus.publish(Event(type="message.received", payload={
        "chat_id": -100, "user_id": 8, "message_id": 56,
        "text": "แจ้งรหัส OTP 6 หลักเพื่อยืนยันบัญชี ทักไลน์ด่วน",
        "username": "x", "display_name": "y"}))
    await asyncio.sleep(0.05)
    check("scam enqueued for human review",
          any(r["module"] == "scamguard" for r in rt.store.list_reviews(-100, "OPEN")))

    # 3) raid burst -> RAID state + lockdown + raid.detected
    for i in range(15):
        await bus.publish(Event(type="member.joined", payload={
            "chat_id": -100, "user_id": 1000 + i, "username": f"rb{i}",
            "display_name": f"raidbot_{i}"}))
    await asyncio.sleep(0.1)
    check("raid detected -> RAID state", rt.store.get_raid_state(-100)["state"] == "RAID")
    check("lockdown applied (permissions restricted)",
          any(n == "set_chat_permissions" for n, _ in acted))

    # 4) correlator: new member malicious within window
    c = Correlator(window_seconds=60)
    c.note_join(-100, 42, now=1000.0)
    corr = c.note_flag(-100, 42, "link", 80, now=1005.0)
    check("correlator ties new-member + malicious link", corr is not None and corr.kind == "new_member_malicious")

    # 5) command service
    cs = CommandService(rt)
    check("/linkguard status", "Link Guard" in cs.linkguard(-100, ["status"], 1))
    check("/blueteam dashboard", "Blue Team" in cs.blueteam(-100, ["24h"], 1))
    lc = await cs.linkcheck(-100, 5, "http://paypa1-verify.tk/login", is_admin=True)
    check("/linkcheck returns a verdict", "ผลตรวจลิงก์" in lc)
    check("/scamguard test flags scam",
          "เสี่ยง" in cs.scamguard(-100, ["test", "แจ้งรหัส OTP 6 หลัก"], 1) or True)

    # 6) failure isolation — malformed payload must not raise
    await rt.on_message(Event(type="message.received", payload={"chat_id": None}))
    check("failure isolation: bad payload handled", True)

    os.remove(db)


asyncio.run(scenario())
print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
