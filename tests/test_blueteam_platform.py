"""
tests/test_blueteam_platform.py — shared platform: metrics, write-behind batcher,
scheduler (fake clock, lease, missed-run catch-up), circuit breaker, tenancy
isolation, typed config, migration 0004 up/down.

Standalone; offline; deterministic.
"""

import asyncio
import os
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import migrations
from blueteam.platform.metrics import MetricsRegistry
from blueteam.platform.batcher import WriteBehindBatcher
from blueteam.platform.scheduler import Scheduler, InMemoryJobStore
from blueteam.platform.circuit_breaker import CircuitBreaker
from blueteam.platform.tenancy import TenantScope, Role, TenantIsolationError
from blueteam.platform.clock import FakeClock
from blueteam.platform.config import get_v08_config

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ---- metrics ----
m = MetricsRegistry()
m.incr("hits", 3)
m.incr("hits")
m.gauge("pending", 12)
for v in (0.2, 0.4, 1.5, 9.0):
    m.observe("lat", v)
snap = m.snapshot()
check("counter aggregates", snap["counters"]["hits"] == 4.0)
check("gauge stored", snap["gauges"]["pending"] == 12)
check("histogram percentiles", snap["histograms"]["lat"]["count"] == 4 and snap["histograms"]["lat"]["p95_ms"] >= 5)

# ---- batcher ----
flushed = []
b = WriteBehindBatcher(lambda items: flushed.extend(items), max_batch=3, max_pending=5)
for i in range(4):
    b.add(i)
check("batcher accumulates", b.pending == 4)
b.flush_sync()
check("batcher flush writes all", flushed == [0, 1, 2, 3])
# backpressure: drop oldest beyond max_pending
b2 = WriteBehindBatcher(lambda items: None, max_batch=100, max_pending=3)
for i in range(6):
    b2.add(i)
check("batcher backpressure drops oldest", b2.pending == 3 and b2.dropped == 3)

# ---- scheduler with fake clock, lease, missed-run ----
fc = FakeClock(1000.0)
store = InMemoryJobStore()
sched = Scheduler(store, clock=fc)
runs = []


async def job():
    runs.append(fc())

sched.register("sync", interval_s=60, fn=job, jitter_s=0)
run(sched.run_due_once())            # first run due (~now)
check("scheduler runs due job", len(runs) == 1)
run(sched.run_due_once())            # not due yet
check("scheduler respects interval", len(runs) == 1)
fc.advance(120)                       # two intervals passed while 'down'
run(sched.run_due_once())
check("missed-run catch-up runs once (not twice)", len(runs) == 2)
check("next_run rescheduled ahead", store.get_next_run("sync") > fc())
# lease prevents double-run
fc.advance(60)
store.set_next_run("sync", fc())
check("lease acquired then blocks second", store.try_lease("sync", fc(), 300) and not store.try_lease("sync", fc(), 300))

# ---- circuit breaker ----
cb = CircuitBreaker("feed", failure_threshold=2, cooldown_s=100, clock=fc)
check("breaker starts closed/allow", cb.allow())
cb.record_failure(); cb.record_failure()
check("breaker opens after threshold", not cb.allow() and cb.state == "open")
fc.advance(101)
check("breaker half-opens after cooldown", cb.allow() and cb.state == "half_open")
cb.record_success()
check("breaker closes on success", cb.allow() and cb.state == "closed")

# ---- tenancy isolation ----
scope = TenantScope.single(-100, role=Role.ADMIN)
check("scope guards in-scope chat", scope.guard(-100) == -100)
try:
    scope.guard(-999)
    check("scope blocks out-of-scope chat", False)
except TenantIsolationError:
    check("scope blocks out-of-scope chat", True)
check("role comparison", scope.can(Role.ADMIN) and not scope.can(Role.OWNER))

# ---- config ----
cfg = get_v08_config(refresh=True)
check("config loads with safe defaults", cfg.intel.enabled and not cfg.kill_switch
      and cfg.intel.max_decompress_ratio >= 2)
check("config module_enabled honours kill switch",
      cfg.module_enabled("intel") is True)

# ---- migration 0004 up/down ----
db = tempfile.mkstemp(suffix=".db")[1]
runner = migrations.MigrationRunner(db)
applied = runner.migrate_up()
check("migration 0004 applies", "0004" in applied)
import sqlite3
conn = sqlite3.connect(db)
tabs = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
need = {"bt_ioc", "bt_ioc_sighting", "bt_feed_state", "bt_rule", "bt_rule_version",
        "bt_rule_hit", "bt_posture_rollup", "bt_posture_snapshot", "bt_report",
        "bt_tenant", "bt_job"}
check("0004 creates all tables", need <= tabs, str(need - tabs))
conn.close()
check("0004 verify clean", runner.verify() == [])
runner.migrate_down("0003")
conn = sqlite3.connect(db)
tabs2 = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
check("0004 downgrade drops its tables", not (need & tabs2))
conn.close()
os.remove(db)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
