"""
cve_tracker.storage — sqlite persistence for the CVE subsystem.

Everything lives on the shared ``bot.db``; the single schema definition is in
:mod:`database`, the typed API is :class:`CVERepository`, and short-horizon hot
values use :class:`TTLCache`. :mod:`retention` prunes history tables without
ever deleting a CVE core record.
"""

from .database import connect, ensure_schema, drop_schema, CVE_SCHEMA, CVE_TABLES
from .repository import CVERepository
from .cache import TTLCache
from .retention import RetentionManager
from . import migrations

__all__ = [
    "connect", "ensure_schema", "drop_schema", "CVE_SCHEMA", "CVE_TABLES",
    "CVERepository", "TTLCache", "RetentionManager", "migrations",
]
