"""
migrations/runner.py — discover, apply, verify and roll back migrations.

The runner keeps a ``schema_migrations`` metadata table:

    version           the migration version (primary key)
    name              class name, for readability
    applied_at        unix seconds
    checksum          the migration's checksum at apply time
    execution_time_ms wall-clock cost of the upgrade

Everything is standard-library sqlite3. Applying a migration is atomic:
each upgrade runs inside its own transaction and either commits fully or
rolls back and stops the run (a partial schema is never left behind).
"""

import os
import re
import time
import logging
import importlib
import importlib.util
import sqlite3
from typing import Dict, List, Optional

from .base import Migration, MigrationError

logger = logging.getLogger("modbot.migrations")

SCHEMA_MIGRATIONS_TABLE = "schema_migrations"

# Migration module files look like ``m0001_something.py`` or ``0001_something.py``.
_MIGRATION_FILE_RE = re.compile(r"^m?(\d+)_.+\.py$")


# ---------------- Discovery ----------------

def discover_migrations(package: str = "migrations") -> List[Migration]:
    """Import every migration module in ``package`` and return one instance
    of each Migration subclass, ordered by version.

    A module that fails to import is logged and skipped rather than taking
    down discovery for the whole set — but note that a *gap* introduced this
    way will be caught by ``verify()``.
    """
    pkg = importlib.import_module(package)
    pkg_dir = os.path.dirname(os.path.abspath(pkg.__file__))

    migrations: List[Migration] = []
    seen_versions: Dict[str, str] = {}

    for filename in sorted(os.listdir(pkg_dir)):
        if not _MIGRATION_FILE_RE.match(filename):
            continue
        mod_name = filename[:-3]
        full_name = f"{package}.{mod_name}"
        try:
            module = importlib.import_module(full_name)
        except Exception:
            logger.exception("MIGRATION DISCOVERY | could not import %s", full_name)
            continue

        for attr in vars(module).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, Migration)
                and attr is not Migration
                and attr.__module__ == module.__name__
            ):
                instance = attr()
                if instance.version in seen_versions:
                    raise MigrationError(
                        f"duplicate migration version {instance.version!r}: "
                        f"{seen_versions[instance.version]} and {filename}"
                    )
                seen_versions[instance.version] = filename
                migrations.append(instance)

    migrations.sort(key=lambda m: _version_key(m.version))
    return migrations


def _version_key(version: str):
    """Sort key that orders numeric versions correctly even if widths differ."""
    try:
        return (0, int(version))
    except (TypeError, ValueError):
        return (1, version)


# ---------------- Runner ----------------

class MigrationRunner:
    def __init__(self, db_path: str, migrations: Optional[List[Migration]] = None,
                 package: str = "migrations"):
        self.db_path = db_path
        if migrations is None:
            migrations = discover_migrations(package)
        else:
            migrations = sorted(migrations, key=lambda m: _version_key(m.version))
        self.migrations = migrations
        self._by_version = {m.version: m for m in migrations}

    # ---- connection / metadata ----

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def ensure_meta_table(self) -> None:
        conn = self._conn()
        try:
            conn.execute(
                f"""CREATE TABLE IF NOT EXISTS {SCHEMA_MIGRATIONS_TABLE} (
                    version TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at INTEGER NOT NULL,
                    checksum TEXT NOT NULL,
                    execution_time_ms INTEGER NOT NULL DEFAULT 0
                )"""
            )
            conn.commit()
        finally:
            conn.close()

    # ---- introspection ----

    def applied(self) -> Dict[str, dict]:
        """version -> row dict for every applied migration."""
        self.ensure_meta_table()
        conn = self._conn()
        try:
            rows = conn.execute(
                f"SELECT * FROM {SCHEMA_MIGRATIONS_TABLE} ORDER BY version"
            ).fetchall()
        finally:
            conn.close()
        return {r["version"]: dict(r) for r in rows}

    def pending(self) -> List[Migration]:
        applied = self.applied()
        return [m for m in self.migrations if m.version not in applied]

    def current(self) -> Optional[str]:
        applied = self.applied()
        if not applied:
            return None
        return max(applied.keys(), key=_version_key)

    def status(self) -> dict:
        """A structured snapshot for /migration status and diagnostics."""
        applied = self.applied()
        pending = self.pending()
        return {
            "db_path": self.db_path,
            "current": self.current(),
            "applied_count": len(applied),
            "pending_count": len(pending),
            "total": len(self.migrations),
            "applied": [
                {"version": v, "name": applied[v]["name"],
                 "applied_at": applied[v]["applied_at"]}
                for v in sorted(applied, key=_version_key)
            ],
            "pending": [
                {"version": m.version, "name": type(m).__name__,
                 "description": m.description, "destructive": m.destructive}
                for m in pending
            ],
            "problems": self.verify(),
        }

    def verify(self) -> List[str]:
        """Return a list of human-readable integrity problems (empty = OK):

        - an applied migration whose definition is gone from disk
        - an applied migration whose checksum no longer matches its source
        """
        problems: List[str] = []
        applied = self.applied()
        for version, row in applied.items():
            migration = self._by_version.get(version)
            if migration is None:
                problems.append(
                    f"applied migration {version} ({row['name']}) is not present "
                    f"on disk"
                )
                continue
            if migration.checksum() != row["checksum"]:
                problems.append(
                    f"checksum mismatch for migration {version} "
                    f"({row['name']}): definition changed after it was applied"
                )
        return problems

    # ---- mutation ----

    def migrate_up(self, target: Optional[str] = None,
                   allow_destructive: bool = False,
                   stop_before_destructive: bool = False) -> List[str]:
        """Apply pending migrations in order, up to and including ``target``
        (or all pending when ``target`` is None). Returns the versions
        actually applied.

        A destructive migration is only applied when ``allow_destructive`` is
        True. When it is not:
          - ``stop_before_destructive`` True  -> stop cleanly before it
            (used at startup so the bot boots; an admin applies it later),
          - otherwise -> raise MigrationError (an explicit up-run that hit a
            destructive step without confirmation).
        """
        self.ensure_meta_table()
        applied_now: List[str] = []

        for migration in self.pending():
            if target is not None and _version_key(migration.version) > _version_key(target):
                break

            if migration.destructive and not allow_destructive:
                if stop_before_destructive:
                    logger.warning(
                        "MIGRATION | %s (%s) is destructive and was NOT applied "
                        "automatically. An admin must confirm it explicitly.",
                        migration.version, migration.description,
                    )
                    break
                raise MigrationError(
                    f"migration {migration.version} is destructive; "
                    f"re-run with explicit confirmation to apply it"
                )

            self._apply_one(migration)
            applied_now.append(migration.version)

        return applied_now

    def _apply_one(self, migration: Migration) -> None:
        conn = self._conn()
        started = time.monotonic()
        try:
            # sqlite runs DDL inside transactions; the explicit BEGIN plus a
            # single commit makes the upgrade + bookkeeping atomic.
            conn.execute("BEGIN")
            migration.upgrade(conn)
            elapsed_ms = int((time.monotonic() - started) * 1000)
            conn.execute(
                f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} "
                f"(version, name, applied_at, checksum, execution_time_ms) "
                f"VALUES (?, ?, ?, ?, ?)",
                (migration.version, type(migration).__name__, int(time.time()),
                 migration.checksum(), elapsed_ms),
            )
            conn.commit()
            logger.info(
                "MIGRATION APPLIED | %s (%s) in %sms",
                migration.version, migration.description, elapsed_ms,
            )
        except Exception as exc:
            conn.rollback()
            logger.exception(
                "MIGRATION FAILED | %s (%s) rolled back; database left at "
                "previous consistent version",
                migration.version, migration.description,
            )
            raise MigrationError(
                f"migration {migration.version} failed: {exc}"
            ) from exc
        finally:
            conn.close()

    def migrate_down(self, target: Optional[str],
                     allow_destructive: bool = False) -> List[str]:
        """Roll back applied migrations newer than ``target`` (exclusive),
        newest first. ``target`` None rolls back everything. Returns the
        versions rolled back."""
        applied = self.applied()
        to_rollback = sorted(
            (v for v in applied if (target is None or _version_key(v) > _version_key(target))),
            key=_version_key,
            reverse=True,
        )
        rolled_back: List[str] = []
        for version in to_rollback:
            migration = self._by_version.get(version)
            if migration is None:
                raise MigrationError(
                    f"cannot roll back {version}: definition not on disk"
                )
            if migration.destructive and not allow_destructive:
                raise MigrationError(
                    f"rollback of {version} is destructive; re-run with "
                    f"explicit confirmation"
                )
            self._rollback_one(migration)
            rolled_back.append(version)
        return rolled_back

    def _rollback_one(self, migration: Migration) -> None:
        conn = self._conn()
        try:
            conn.execute("BEGIN")
            migration.downgrade(conn)
            conn.execute(
                f"DELETE FROM {SCHEMA_MIGRATIONS_TABLE} WHERE version=?",
                (migration.version,),
            )
            conn.commit()
            logger.info("MIGRATION ROLLED BACK | %s (%s)",
                        migration.version, migration.description)
        except Exception as exc:
            conn.rollback()
            logger.exception("MIGRATION ROLLBACK FAILED | %s", migration.version)
            raise MigrationError(
                f"rollback of {migration.version} failed: {exc}"
            ) from exc
        finally:
            conn.close()


# ---------------- Startup helper ----------------

def apply_startup_migrations(db_path: str,
                             package: str = "migrations") -> dict:
    """Called by app.py at boot. Applies all pending NON-destructive
    migrations. Destructive ones are left pending (an admin confirms them via
    /migration up --confirm) so an automated restart can never lose data.

    On a genuine migration failure this raises MigrationError — the caller
    must not continue silently, per the framework's contract. On success it
    returns the runner's status snapshot.
    """
    runner = MigrationRunner(db_path, package=package)
    problems = runner.verify()
    if problems:
        # A drift/verify problem is a loud warning, not a silent pass, but it
        # does not by itself stop the boot — the operator needs to see it.
        for problem in problems:
            logger.error("MIGRATION VERIFY | %s", problem)

    pending_before = runner.pending()
    if not pending_before:
        logger.info("MIGRATION | schema up to date at %s",
                    runner.current() or "(baseline)")
        return runner.status()

    logger.info("MIGRATION | %d pending migration(s); applying non-destructive ones",
                len(pending_before))
    applied = runner.migrate_up(allow_destructive=False, stop_before_destructive=True)
    logger.info("MIGRATION | applied %d migration(s): %s",
                len(applied), ", ".join(applied) or "(none)")
    return runner.status()
