"""
migrations/ — centralized database migration framework for Sombra Guardian.

Why this package exists
-----------------------
Historically every module owns its own tables through an idempotent
``*_db_init()`` that runs ``CREATE TABLE IF NOT EXISTS`` at startup
(security.py, detection.py, member_incident.py, …). That pattern is fine
for tables that already exist on every deployment, and this framework does
NOT try to rip it out — those inits stay exactly where they are and keep
running. They are, in effect, the compatibility layer for pre-existing
schema.

What this framework adds is a single, versioned, auditable place to evolve
schema going forward — starting with the Workflow Automation Engine's
tables. New schema is expressed as a :class:`Migration` with an explicit
version, a checksum, and ``upgrade()`` / ``downgrade()`` steps, and is
tracked in a ``schema_migrations`` metadata table so an operator can see
exactly what has been applied.

Design constraints (Render / background-worker friendly)
-------------------------------------------------------
- Standard library only (sqlite3, hashlib, importlib, inspect).
- No network calls, no threads.
- Never destructive without an explicit confirmation flag.
- Applying a migration is transactional: a failure rolls that migration
  back and stops the run, so the database is never left half-migrated.

Public surface
--------------
``Migration``            base class for a single migration
``MigrationRunner``      discovers, applies, verifies and rolls back
``MigrationError``       raised when a migration fails to apply
``discover_migrations``  find Migration subclasses in this package
``apply_startup_migrations``  the helper app.py calls at boot
"""

from .base import Migration, MigrationError
from .runner import (
    MigrationRunner,
    discover_migrations,
    apply_startup_migrations,
    SCHEMA_MIGRATIONS_TABLE,
)

__all__ = [
    "Migration",
    "MigrationError",
    "MigrationRunner",
    "discover_migrations",
    "apply_startup_migrations",
    "SCHEMA_MIGRATIONS_TABLE",
]
