"""
tests/test_workflows.py — workflow engine: conditions, matching, actions,
retry, timeout, idempotency/dedup, loop-guard, permissions-of-config, failure.

Standalone script; prints PASS/FAIL + a "==== N passed, M failed ====" line.
Uses an in-memory engine (db_path=None) except where persistence is asserted.
"""

import os
import sys
import asyncio
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import migrations
from workflows import (
    Event, WorkflowEngine, WorkflowDefinition, build_default_registry, Services,
    load_dir, evaluate_condition, evaluate_all, safe_regex_search,
)
from workflows.actions import WorkflowAction
from workflows.models import ActionResult, WorkflowState

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ---- 1. condition operators ----

P = {"severity": "high", "count": 7, "text": "hello world", "tags": ["a", "b"],
     "nested": {"risk": "HIGH"}}
cases = [
    ({"field": "severity", "operator": "equals", "value": "high"}, True),
    ({"field": "severity", "operator": "not_equals", "value": "low"}, True),
    ({"field": "text", "operator": "contains", "value": "world"}, True),
    ({"field": "text", "operator": "not_contains", "value": "zzz"}, True),
    ({"field": "count", "operator": "gt", "value": 5}, True),
    ({"field": "count", "operator": "gte", "value": 7}, True),
    ({"field": "count", "operator": "lt", "value": 10}, True),
    ({"field": "count", "operator": "lte", "value": 7}, True),
    ({"field": "severity", "operator": "in", "value": ["high", "critical"]}, True),
    ({"field": "severity", "operator": "not_in", "value": ["low"]}, True),
    ({"field": "severity", "operator": "exists"}, True),
    ({"field": "missing", "operator": "not_exists"}, True),
    ({"field": "text", "operator": "regex", "value": "^hello"}, True),
    ({"field": "count", "operator": "gt", "value": 100}, False),
    ({"field": "nested.risk", "operator": "equals", "value": "HIGH"}, True),
]
ok = all(evaluate_condition(c, P) is expected for c, expected in cases)
check("all condition operators evaluate correctly", ok)
check("evaluate_all AND semantics", evaluate_all(
    [{"field": "severity", "operator": "equals", "value": "high"},
     {"field": "count", "operator": "gt", "value": 5}], P) is True)
check("evaluate_all fails if one fails", evaluate_all(
    [{"field": "severity", "operator": "equals", "value": "high"},
     {"field": "count", "operator": "gt", "value": 50}], P) is False)
check("no conditions always matches", evaluate_all([], P) is True)

# ---- 2. ReDoS protection ----

check("regex rejects nested quantifiers (ReDoS)",
      safe_regex_search("(a+)+$", "aaaaaaaaaaaaaaaaaaaa!") is False)
check("regex rejects over-long pattern",
      safe_regex_search("a" * 500, "aaa") is False)
check("regex still works for safe pattern",
      safe_regex_search("^foo", "foobar") is True)
check("regex invalid pattern returns False (no raise)",
      safe_regex_search("([", "x") is False)

# ---- 3. trigger matching + condition gating ----

reg = build_default_registry()
engine = WorkflowEngine(reg)
engine.register(WorkflowDefinition(
    "audit-high", "detection.triggered", ["log_event"],
    conditions=[{"field": "severity", "operator": "equals", "value": "high"}]))

r = run(engine.dispatch(Event("detection.triggered", {"severity": "high"})))
check("matching workflow runs to SUCCESS", r and r[0].state == WorkflowState.SUCCESS.value)
r = run(engine.dispatch(Event("detection.triggered", {"severity": "low"})))
check("condition mismatch -> SKIPPED", r and r[0].state == WorkflowState.SKIPPED.value)
r = run(engine.dispatch(Event("unrelated.event", {})))
check("no matching trigger -> no records", r == [])

# ---- 4. action execution + custom action + emitted follow-up event ----

seen = {"child": 0}

class RecordAction(WorkflowAction):
    name = "record"
    async def execute(self, ctx):
        ev = ctx["event"]
        return ActionResult(ok=True, action=self.name, detail="ok",
                            emit=[ev.child("child.event", {})])

class ChildCounter(WorkflowAction):
    name = "count_child"
    async def execute(self, ctx):
        seen["child"] += 1
        return ActionResult.success(self.name)

reg.register(RecordAction()); reg.register(ChildCounter())
engine.register(WorkflowDefinition("emitter", "parent.event", ["record"]))
engine.register(WorkflowDefinition("child-handler", "child.event", ["count_child"]))
run(engine.dispatch(Event("parent.event", {})))
check("action-emitted event is dispatched to its workflow", seen["child"] == 1)

# ---- 5. retry ----

state = {"n": 0}
class Flaky(WorkflowAction):
    name = "flaky"
    async def execute(self, ctx):
        state["n"] += 1
        if state["n"] < 3:
            return ActionResult.failure(self.name, "not yet")
        return ActionResult.success(self.name)
reg.register(Flaky())
engine.register(WorkflowDefinition("retry-wf", "t.retry", ["flaky"],
                                   max_retries=5, retry_backoff_seconds=0))
r = run(engine.dispatch(Event("t.retry", {})))
check("retry recovers a flaky action", r[0].state == WorkflowState.SUCCESS.value)
check("retry attempted the right number of times", state["n"] == 3, state["n"])

state["n"] = 0
engine.register(WorkflowDefinition("noretry-wf", "t.noretry", ["flaky"], max_retries=0))
r = run(engine.dispatch(Event("t.noretry", {})))
check("no-retry action fails -> FAILED", r[0].state == WorkflowState.FAILED.value)

# ---- 6. timeout ----

class Slow(WorkflowAction):
    name = "slow"
    async def execute(self, ctx):
        await asyncio.sleep(1.0)
        return ActionResult.success(self.name)
reg.register(Slow())
engine.register(WorkflowDefinition("slow-wf", "t.slow", ["slow"], timeout_seconds=0.1))
r = run(engine.dispatch(Event("t.slow", {})))
check("action exceeding timeout -> TIMEOUT", r[0].state == WorkflowState.TIMEOUT.value)

# ---- 7. action raising exception is isolated -> FAILED, others unaffected ----

class Boom(WorkflowAction):
    name = "boom"
    async def execute(self, ctx):
        raise RuntimeError("explode")
reg.register(Boom())
engine.register(WorkflowDefinition("boom-wf", "t.boom", ["boom"], max_retries=0))
r = run(engine.dispatch(Event("t.boom", {})))
check("raising action -> FAILED (isolated, no crash)", r[0].state == WorkflowState.FAILED.value)

# ---- 8. idempotency / dedup within cooldown ----

engine.register(WorkflowDefinition(
    "dedup-wf", "t.dedup", ["log_event"], cooldown_seconds=60,
    dedup_fields=["chat_id", "user_id"]))
e1 = run(engine.dispatch(Event("t.dedup", {"chat_id": 1, "user_id": 2})))
e2 = run(engine.dispatch(Event("t.dedup", {"chat_id": 1, "user_id": 2})))
e3 = run(engine.dispatch(Event("t.dedup", {"chat_id": 9, "user_id": 9})))
check("first dedup run succeeds", e1[0].state == WorkflowState.SUCCESS.value)
check("duplicate within cooldown -> SKIPPED", e2[0].state == WorkflowState.SKIPPED.value)
check("different key is not deduplicated", e3[0].state == WorkflowState.SUCCESS.value)

# ---- 9. loop guard via depth ----

engine.register(WorkflowDefinition("deep-wf", "t.deep", ["log_event"], max_depth=2))
ev = Event("t.deep", {}); ev.depth = 5
r = run(engine.dispatch(ev))
check("event beyond max_depth -> SKIPPED (loop guard)",
      r[0].state == WorkflowState.SKIPPED.value and "max_depth" in (r[0].error or ""))

# ---- 10. real infinite-loop scenario is bounded ----
# create_incident emits incident.created; a workflow on incident.created that
# calls update_incident emits incident.updated; a workflow on incident.updated
# that calls update_incident would recurse — the depth guard must stop it.

loop_calls = {"update": 0}
services = Services(
    update_incident=lambda *a, **k: loop_calls.__setitem__("update", loop_calls["update"] + 1) or {"ok": True},
)
loop_engine = WorkflowEngine(build_default_registry(), services)
loop_engine.register(WorkflowDefinition("on-created", "incident.created",
                                        ["update_incident"], max_depth=3))
loop_engine.register(WorkflowDefinition("on-updated", "incident.updated",
                                        ["update_incident"], max_depth=3))
run(loop_engine.dispatch(Event("incident.created", {"incident_id": 1})))
check("recursive incident loop is bounded by depth guard",
      0 < loop_calls["update"] <= 4, loop_calls["update"])

# ---- 11. safe stub when service missing (no crash) ----

stub_engine = WorkflowEngine(build_default_registry(), Services())  # no services wired
stub_engine.register(WorkflowDefinition("alert-wf", "t.alert", ["send_admin_alert"]))
r = run(stub_engine.dispatch(Event("t.alert", {"chat_id": 1, "reason": "x"})))
check("missing service degrades to stub SUCCESS (no crash)",
      r[0].state == WorkflowState.SUCCESS.value)

# ---- 12. persistence: history + enable/disable survive via DB ----

fd, dbp = tempfile.mkstemp(suffix=".db"); os.close(fd)
migrations.apply_startup_migrations(dbp)
pengine = WorkflowEngine(build_default_registry(), db_path=dbp)
pengine.register(WorkflowDefinition("persist-wf", "t.persist", ["log_event"]))
run(pengine.dispatch(Event("t.persist", {})))
check("execution persisted to history", len(pengine.history()) == 1)
check("history filter by name works", len(pengine.history("persist-wf")) == 1)
pengine.set_enabled("persist-wf", False, actor=42)
# a fresh engine reading the same DB should see it disabled
pengine2 = WorkflowEngine(build_default_registry(), db_path=dbp)
pengine2.register(WorkflowDefinition("persist-wf", "t.persist", ["log_event"]))
check("disable persists across engine instances",
      pengine2.get("persist-wf").enabled is False)
r = run(pengine2.dispatch(Event("t.persist", {})))
check("disabled workflow does not run", r == [])
os.remove(dbp)

# ---- 13. shipped definition files load and validate ----

defs = load_dir(os.path.join(_ROOT, "workflows", "definitions"))
check("shipped workflow definitions load", len(defs) >= 2, [d.name for d in defs])
check("shipped definitions reference known actions",
      all(all(a in build_default_registry() for a in d.actions) for d in defs))

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
