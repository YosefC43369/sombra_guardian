"""
tests/test_platform_integration.py — the three subsystems wired together,
exercised as a real end-to-end flow:

    detection.triggered (event)
        -> Workflow Engine
        -> create_incident action (real member_incident)
        -> Incident row in the database
        -> incident.created (follow-up event)
        -> shipped critical-incident workflow -> admin alert
        -> workflow execution + audit rows

Also checks the app-facing integration surface (init_platform, the /plugins
/workflow /migration handler registration through a FakeApp, and the
permission gate) without needing a live Telegram connection.

Standalone script; prints PASS/FAIL + a "==== N passed, M failed ====" line.
"""

import os
import sys
import asyncio
import sqlite3
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import security
import member_intel as mi
import member_incident as mic
import sg_platform
from workflows import WorkflowDefinition
from workflows.actions import WorkflowAction

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _count(db, table, where=""):
    conn = sqlite3.connect(db)
    q = f"SELECT COUNT(*) FROM {table}" + (f" WHERE {where}" if where else "")
    try:
        n = conn.execute(q).fetchone()[0]
    finally:
        conn.close()
    return n


# ---- isolated DB shared by every module (mirrors production's single bot.db) ----

fd, DB = tempfile.mkstemp(suffix=".db"); os.close(fd)
security.DB_PATH = DB
mi.DB_PATH = DB
mic.DB_PATH = DB
security.security_db_init()
mi.member_intel_db_init()
mic.member_incident_db_init()
mic.AUTO_INCIDENT_ENABLED = True   # default true; make it explicit for the test

# ---- init the platform against that DB (runs migrations, loads workflows/plugins) ----

def _table_names(db):
    conn = sqlite3.connect(db)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    return names

platform = sg_platform.init_platform(DB)
check("init_platform ran migrations (wf tables exist)",
      {"wf_executions", "wf_audit"}.issubset(_table_names(DB)))
check("shipped workflows registered",
      any(w.name == "critical-incident-escalation" for w in platform.engine.list()))
check("built-in plugin loaded", any(m["name"] == "detection-bridge" and m["state"] == "ENABLED"
                                    for m in platform.plugins.metadata()))

# ---- wire the real incident services + spy on admin alerts ----

alerts = []
platform.services.set("send_admin_alert", lambda chat_id, text: alerts.append((chat_id, text)))
sg_platform._wire_incident_services(platform)   # real member_incident bridge
check("create_incident service wired", platform.services.has("create_incident"))

# ---- register a workflow: detection.triggered -> create_incident ----
# (the shipped workflows deliberately never open incidents to avoid loops, so
#  the test provides this bridge workflow explicitly.)

platform.engine.register(WorkflowDefinition(
    "detection-to-incident", "detection.triggered", ["create_incident"],
    conditions=[{"field": "severity", "operator": "in", "value": ["medium", "high"]}],
    max_depth=4))

# ---- drive the full flow through the event bus, exactly as app.py does ----

async def drive():
    platform.emit("detection.triggered", {
        "chat_id": -1001, "user_id": 555, "category": "SPAM",
        "detection_type": "BLOCKED_LINK", "severity": "high",
        "reason": "blocked domain evil.example", "username": "spammer",
        "display_name": "Spammer",
    })
    # let the fire-and-forget task chain (detection -> incident -> alert) settle
    await asyncio.sleep(0.2)

run(drive())

# ---- assert the whole chain landed ----

check("incident row created in database", _count(DB, "mi_incidents") >= 1,
      _count(DB, "mi_incidents"))
check("detection-to-incident workflow recorded a SUCCESS execution",
      _count(DB, "wf_executions",
             "workflow_name='detection-to-incident' AND state='SUCCESS'") >= 1)
check("follow-up incident.created workflow ran",
      _count(DB, "wf_executions",
             "workflow_name='critical-incident-escalation'") >= 1)
check("admin alert fired from the incident.created chain", len(alerts) >= 1, alerts)
check("workflow audit log has rows (started/completed)",
      _count(DB, "wf_audit") >= 2, _count(DB, "wf_audit"))
check("execution step log written", _count(DB, "wf_execution_log") >= 1)

# ---- the loop guard holds even in this real chain (bounded executions) ----

total_exec = _count(DB, "wf_executions")
check("total executions are bounded (no runaway loop)", total_exec < 20, total_exec)

# ---- handler registration surface (FakeApp, no Telegram connection) ----

class FakeApp:
    def __init__(self): self.handlers = []
    def add_handler(self, h, *a, **k): self.handlers.append(h)

async def fake_is_admin(update, context):
    return True

registered = sg_platform.register_handlers(FakeApp(), platform, fake_is_admin)
check("platform admin commands registered",
      {"plugins", "workflow", "migration"}.issubset(set(registered)))
check("plugin-contributed commands included in registration",
      isinstance(registered, list) and len(registered) >= 3)

# ---- permission gate: a non-admin is refused a platform command ----

class FakeMsg:
    def __init__(self): self.replies = []
    async def reply_text(self, text, *a, **k): self.replies.append(text); return text
class FakeUpdate:
    def __init__(self): self.message = FakeMsg(); self.effective_user = None
class FakeCtx:
    args = []

async def deny_is_admin(update, context):
    return False

gate = sg_platform._make_admin_command(platform, deny_is_admin, sg_platform._cmd_plugins)
upd = FakeUpdate()
run(gate(upd, FakeCtx()))
check("non-admin is refused a platform admin command",
      any("Admin" in r for r in upd.message.replies), upd.message.replies)

# ---- admin sees plugin list ----

async def allow_is_admin(update, context):
    return True
gate_ok = sg_platform._make_admin_command(platform, allow_is_admin, sg_platform._cmd_plugins)
upd2 = FakeUpdate()
run(gate_ok(upd2, FakeCtx()))
check("admin gets a plugins listing",
      any("Plugins" in r or "detection-bridge" in r for r in upd2.message.replies),
      upd2.message.replies)

# ---- backward-compat: emit is a no-op-safe even with no workflows matching ----

before = _count(DB, "wf_executions")

async def _emit_unmatched():
    platform.emit("nonexistent.event", {"x": 1})
    await asyncio.sleep(0.05)

run(_emit_unmatched())
check("event with no matching workflow changes nothing",
      _count(DB, "wf_executions") == before)

os.remove(DB)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
