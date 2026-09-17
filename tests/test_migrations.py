"""
tests/test_migrations.py — migration framework.

Standalone script (same style as the other tests/ files): prints PASS/FAIL
lines and a "==== N passed, M failed ====" summary, exits non-zero on failure.
Exercises the real public API against isolated temp databases — never the
repo's bot.db.
"""

import os
import sys
import sqlite3
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import migrations
from migrations import MigrationRunner, Migration, MigrationError
from migrations.runner import discover_migrations

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


def _tmpdb():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


def _tables(path):
    conn = sqlite3.connect(path)
    rows = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    return rows


# ---- helper migrations for controlled tests ----

class _M1(Migration):
    version = "0001"
    description = "create table a"
    def upgrade(self, conn):
        conn.execute("CREATE TABLE a (id INTEGER PRIMARY KEY)")
    def downgrade(self, conn):
        conn.execute("DROP TABLE a")


class _M2(Migration):
    version = "0002"
    description = "create table b"
    def upgrade(self, conn):
        conn.execute("CREATE TABLE b (id INTEGER PRIMARY KEY)")
    def downgrade(self, conn):
        conn.execute("DROP TABLE b")


class _MBoom(Migration):
    version = "0002"
    description = "fails on purpose"
    def upgrade(self, conn):
        conn.execute("CREATE TABLE c (id INTEGER PRIMARY KEY)")
        conn.execute("THIS IS NOT SQL")   # forces a failure mid-migration


class _MAfterBoom(Migration):
    version = "0003"
    description = "create table b (ordered after the failing one)"
    def upgrade(self, conn):
        conn.execute("CREATE TABLE b (id INTEGER PRIMARY KEY)")


class _MDestructive(Migration):
    version = "0004"
    description = "drops a"
    destructive = True
    def upgrade(self, conn):
        conn.execute("DROP TABLE IF EXISTS a")


# ---- 1. discovery of the real package ----

real = discover_migrations("migrations")
check("discovers real migrations in order",
      [m.version for m in real] == sorted(m.version for m in real) and len(real) >= 2,
      [m.version for m in real])
check("real migrations include workflow engine (0001)",
      any(m.version == "0001" for m in real))

# ---- 2. fresh database: apply all ----

db = _tmpdb()
r = MigrationRunner(db, migrations=[_M1(), _M2()])
check("fresh db has no applied migrations", r.current() is None)
check("pending lists all", [m.version for m in r.pending()] == ["0001", "0002"])
applied = r.migrate_up()
check("migrate_up applies both", applied == ["0001", "0002"], applied)
check("tables created", {"a", "b"}.issubset(_tables(db)))
check("current is latest", r.current() == "0002", r.current())
check("schema_migrations records rows", r.status()["applied_count"] == 2)
os.remove(db)

# ---- 3. existing database: only pending re-applied (idempotent) ----

db = _tmpdb()
r = MigrationRunner(db, migrations=[_M1()])
r.migrate_up()
r2 = MigrationRunner(db, migrations=[_M1(), _M2()])   # a new migration appears
check("existing db sees only new migration pending",
      [m.version for m in r2.pending()] == ["0002"])
r2.migrate_up()
check("second run applies only the new one", r2.current() == "0002")
# re-run: nothing pending
check("re-running is idempotent", r2.migrate_up() == [])
os.remove(db)

# ---- 4. ordering is enforced numerically ----

db = _tmpdb()
r = MigrationRunner(db, migrations=[_M2(), _M1()])   # given out of order
check("runner sorts migrations", [m.version for m in r.migrations] == ["0001", "0002"])
os.remove(db)

# ---- 5. failure rolls back and stops ----

db = _tmpdb()
r = MigrationRunner(db, migrations=[_M1(), _MBoom(), _MAfterBoom()])
raised = False
try:
    r.migrate_up()
except MigrationError:
    raised = True
check("failing migration raises MigrationError", raised)
check("first migration committed before the failure", "a" in _tables(db))
check("failed migration rolled back (no table c)", "c" not in _tables(db))
check("failed migration not recorded", "0002" not in r.applied())
check("migration after the failure never ran (no table b)", "b" not in _tables(db))
os.remove(db)

# ---- 6. checksum mismatch detected by verify ----

db = _tmpdb()
r = MigrationRunner(db, migrations=[_M1()])
r.migrate_up()
# Tamper with the stored checksum to simulate an edited-after-apply migration.
conn = sqlite3.connect(db)
conn.execute("UPDATE schema_migrations SET checksum='tampered' WHERE version='0001'")
conn.commit(); conn.close()
problems = r.verify()
check("verify flags checksum mismatch", any("checksum" in p for p in problems), problems)
os.remove(db)

# ---- 7. applied-but-missing-on-disk detected ----

db = _tmpdb()
MigrationRunner(db, migrations=[_M1(), _M2()]).migrate_up()
r_missing = MigrationRunner(db, migrations=[_M1()])   # 0002 vanished from disk
check("verify flags applied migration missing on disk",
      any("not present" in p for p in r_missing.verify()))
os.remove(db)

# ---- 8. destructive safety ----

db = _tmpdb()
r = MigrationRunner(db, migrations=[_M1(), _MDestructive()])
r.migrate_up(target="0001")   # apply the safe one only
# startup-style call must NOT auto-apply the destructive one
applied = r.migrate_up(allow_destructive=False, stop_before_destructive=True)
check("destructive migration NOT auto-applied", applied == [] and "a" in _tables(db))
check("destructive still pending", [m.version for m in r.pending()] == ["0004"])
# explicit confirmation applies it
applied2 = r.migrate_up(allow_destructive=True)
check("destructive applied with confirmation", applied2 == ["0004"] and "a" not in _tables(db))
os.remove(db)

# ---- 9. destructive without stop flag raises ----

db = _tmpdb()
r = MigrationRunner(db, migrations=[_MDestructive()])
raised = False
try:
    r.migrate_up(allow_destructive=False, stop_before_destructive=False)
except MigrationError:
    raised = True
check("destructive without confirm+stop raises", raised)
os.remove(db)

# ---- 10. rollback ----

db = _tmpdb()
r = MigrationRunner(db, migrations=[_M1(), _M2()])
r.migrate_up()
rolled = r.migrate_down("0001")
check("rollback removes newer migration", rolled == ["0002"] and "b" not in _tables(db))
check("rollback keeps target migration", "a" in _tables(db) and r.current() == "0001")
os.remove(db)

# ---- 11. apply_startup_migrations on the REAL package ----

db = _tmpdb()
status = migrations.apply_startup_migrations(db)
check("startup applies real migrations", status["pending_count"] == 0)
check("startup created wf_ tables",
      {"wf_executions", "wf_audit", "wf_workflow_state"}.issubset(_tables(db)))
check("startup created plugin_state", "plugin_state" in _tables(db))
check("startup is idempotent", migrations.apply_startup_migrations(db)["pending_count"] == 0)
os.remove(db)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
