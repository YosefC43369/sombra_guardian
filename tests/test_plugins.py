"""
tests/test_plugins.py — plugin architecture: discovery, loading, failure
isolation, metadata, healthcheck, permissions, enable/disable persistence,
command/action/event registration.

Standalone script; prints PASS/FAIL + a "==== N passed, M failed ====" line.
"""

import os
import sys
import asyncio
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import migrations
from workflows import build_default_registry, EventBus, WorkflowEngine, Event
from plugins import (
    PluginManager, BasePlugin, PluginContext, PluginState, PermissionLevel,
    HealthStatus,
)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _fresh_db():
    fd, path = tempfile.mkstemp(suffix=".db"); os.close(fd)
    migrations.apply_startup_migrations(path)
    return path


# ---- test plugins ----

class GoodPlugin(BasePlugin):
    name = "good"
    version = "1.2.3"
    description = "a healthy plugin with a command"
    permission = PermissionLevel.ADMIN

    def setup(self, ctx):
        async def handler(update, context):
            return "ran"
        ctx.register_command("demo", handler, permission="ADMIN", description="demo")

class BrokenPlugin(BasePlugin):
    name = "broken"
    version = "0.0.1"
    def setup(self, ctx):
        raise RuntimeError("kaboom during setup")

class SickPlugin(BasePlugin):
    name = "sick"
    def setup(self, ctx):
        pass
    def healthcheck(self):
        return HealthStatus.unhealthy("backend down")

class ActionPlugin(BasePlugin):
    name = "actions"
    def setup(self, ctx):
        class MyAction:
            name = "my_action"
            async def execute(self, c):
                from workflows.models import ActionResult
                return ActionResult.success("my_action")
        ctx.register_workflow_action(MyAction())
        ctx.subscribe_event(self._on_event, "test.event")
        self.received = 0
    async def _on_event(self, event):
        self.received += 1


# ---- 1. discovery of built-ins ----

db = _fresh_db()
reg = build_default_registry(); bus = EventBus()
engine = WorkflowEngine(reg, db_path=db)
mgr = PluginManager(db_path=db, engine=engine, action_registry=reg, event_bus=bus)
mgr.discover()   # auto-discovers plugins.builtin
builtin_names = [r.name for r in mgr.registry.all()]
check("built-in plugins discovered", "detection-bridge" in builtin_names, builtin_names)

# ---- 2. loading + failure isolation ----

mgr.discover(plugins=[GoodPlugin(), BrokenPlugin(), SickPlugin(), ActionPlugin()])
mgr.load_all()
states = {r.name: r.state for r in mgr.registry.all()}
check("good plugin ENABLED", states["good"] == PluginState.ENABLED)
check("broken plugin FAILED (isolated)", states["broken"] == PluginState.FAILED)
check("broken plugin did not stop the others",
      states["good"] == PluginState.ENABLED and states["actions"] == PluginState.ENABLED)
check("detection-bridge still ENABLED alongside a failure",
      states.get("detection-bridge") == PluginState.ENABLED)

# ---- 3. metadata ----

meta = {m["name"]: m for m in mgr.metadata()}
check("metadata exposes version", meta["good"]["version"] == "1.2.3")
check("metadata exposes description", "healthy" in meta["good"]["description"])
check("metadata lists commands", meta["good"]["commands"] == ["demo"])
check("metadata carries FAILED error", bool(meta["broken"]["error"]))

# ---- 4. healthcheck ----

health = mgr.healthcheck_all()
check("healthy plugin reports healthy", health["good"].healthy is True)
check("sick plugin reports unhealthy", health["sick"].healthy is False)
check("failed plugin reports unhealthy", health["broken"].healthy is False)
check("healthcheck detail surfaced", "backend down" in health["sick"].detail)

# ---- 5. command specs (only from ENABLED plugins) ----

specs = {s.name: s for s in mgr.iter_command_specs()}
check("enabled plugin contributes its command", "demo" in specs)
check("command carries its permission level",
      specs["demo"].permission == PermissionLevel.ADMIN)

# ---- 6. workflow action + event subscription registered ----

check("plugin-registered action reached the shared registry", "my_action" in reg)
run(bus.publish(Event("test.event", {})))
action_plugin = mgr.registry.get("actions").plugin
check("plugin event subscription received the event", action_plugin.received == 1)

# ---- 7. permission parsing ----

check("PermissionLevel ordering (ADMIN >= MODERATOR)",
      PermissionLevel.ADMIN >= PermissionLevel.MODERATOR)
check("PermissionLevel.parse from string", PermissionLevel.parse("owner") == PermissionLevel.OWNER)
check("PermissionLevel.parse unknown defaults to ADMIN",
      PermissionLevel.parse("nonsense") == PermissionLevel.ADMIN)

# ---- 8. disable / enable + persistence ----

mgr.disable("good", actor=7)
check("disabled plugin drops its commands",
      "demo" not in {s.name for s in mgr.iter_command_specs()})
check("disabled plugin state is DISABLED",
      mgr.registry.get("good").state == PluginState.DISABLED)

# a fresh manager on the same DB must honour the persisted 'disabled'
mgr2 = PluginManager(db_path=db, engine=WorkflowEngine(build_default_registry(), db_path=db),
                     action_registry=build_default_registry())
mgr2.discover(plugins=[GoodPlugin()])
mgr2.load_all()
check("persisted disable honoured by a fresh manager",
      mgr2.registry.get("good").state == PluginState.DISABLED)

mgr.enable("good", actor=7)
check("re-enabled plugin restores its commands",
      "demo" in {s.name for s in mgr.iter_command_specs()})

# ---- 9. summary ----

summary = mgr.summary()
check("summary counts failed plugins", "broken" in summary["failed"])
check("summary totals all plugins", summary["total"] == len(mgr.registry.all()))

# ---- 10. duplicate plugin name rejected, not crashing ----

before = len(mgr.registry.all())
mgr.discover(plugins=[GoodPlugin()])   # 'good' already present
check("duplicate plugin name skipped (no crash)", len(mgr.registry.all()) == before)

# ---- 11. shutdown ----

mgr.shutdown_all()
check("shutdown_all stops enabled plugins",
      all(r.state in (PluginState.STOPPED, PluginState.DISABLED, PluginState.FAILED)
          for r in mgr.registry.all()))

os.remove(db)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
