"""
migrations/base.py — the Migration contract.

A migration is a small, ordered unit of schema change. Each one carries a
zero-padded string ``version`` (so lexical and numeric ordering agree), a
human ``description``, and two steps:

    upgrade(conn)    apply the change
    downgrade(conn)  undo it (best effort; may raise NotImplementedError)

``destructive`` marks a migration that drops/truncates data. The runner
refuses to apply a destructive migration unless the caller passes an
explicit confirmation flag — startup never applies one automatically.

The ``checksum`` is derived from the migration class source, so if an
already-applied migration's definition changes on disk, ``verify()`` can
flag the drift instead of silently diverging.
"""

import hashlib
import inspect


class MigrationError(RuntimeError):
    """Raised when a migration fails to apply or when the migration set is
    inconsistent (e.g. a checksum mismatch during a strict verify)."""


class Migration:
    """Base class for one schema migration.

    Subclasses set ``version`` and ``description`` and implement
    ``upgrade``. ``downgrade`` is optional but recommended.
    """

    # Zero-padded so "0002" sorts after "0001" both lexically and numerically.
    version: str = "0000"
    description: str = ""
    # True for migrations that DROP/TRUNCATE or otherwise lose data.
    destructive: bool = False

    def upgrade(self, conn) -> None:  # pragma: no cover - abstract
        """Apply the migration. ``conn`` is an open sqlite3 connection
        inside a transaction managed by the runner."""
        raise NotImplementedError(
            f"migration {self.version} does not implement upgrade()"
        )

    def downgrade(self, conn) -> None:  # pragma: no cover - abstract
        """Reverse the migration. Optional: a migration with no safe
        downgrade should raise NotImplementedError, which the runner
        surfaces clearly rather than pretending the rollback happened."""
        raise NotImplementedError(
            f"migration {self.version} has no downgrade()"
        )

    # ---------------- Identity / integrity ----------------

    @property
    def name(self) -> str:
        return f"{self.version}_{type(self).__name__}"

    def checksum(self) -> str:
        """A stable hash of this migration's definition. Uses the class
        source when available (detects edits to an applied migration),
        falling back to version+description so the value is always defined."""
        try:
            source = inspect.getsource(type(self))
        except (OSError, TypeError):
            source = ""
        payload = "\n".join([self.version, self.description or "", source])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def __repr__(self) -> str:
        flag = " destructive" if self.destructive else ""
        return f"<Migration {self.version}: {self.description}{flag}>"
