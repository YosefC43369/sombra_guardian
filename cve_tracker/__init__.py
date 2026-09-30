"""
cve_tracker — CVE Intelligence & Tracking subsystem for Sombra Guardian.

A defensive vulnerability-monitoring subsystem, structured like the project's
existing self-contained packages (``group_soc``, ``purple_range``). It watches
public vulnerability sources (NVD, CVE.org, CISA KEV, GitHub Security
Advisories, and pluggable vendor advisories), normalizes and de-duplicates the
records, enriches them (CVSS/CWE/CPE/KEV/exploit-reference classification),
produces a validated Thai summary using the project's existing AI provider, and
publishes filtered alerts to Telegram subscribers.

Scope discipline: this subsystem only *reads and reports* public vulnerability
information. It never fetches, downloads, generates, or executes exploit code;
it classifies exploit *references* as data and nothing more.

Integration seam (no parallel infrastructure):
  * AI            → reuses ``gemini.ask_gemini`` / ``ai_router.route`` via
                    :class:`cve_tracker.ai.adapter.AIProviderAdapter`
  * Telegram      → reuses the single bot Application; the plugin
                    ``plugins/builtin/cve_tracker_suite.py`` registers commands
                    and the background loop is started in app.py's ``post_init``
                    exactly like ``news_background_loop``
  * Storage       → sqlite on the shared ``bot.db``; schema in
                    ``migrations/m0008_cve_tracker.py``
  * Config/env    → ``envutil`` (blank-tolerant), all keys ``CVE_*``

Public entry points:
  * :func:`get_config`      — the env-driven configuration snapshot
  * :class:`CVETracker`     — the orchestration facade (engine + scheduler)
  * :func:`register_cve_tracker` — one-call integration helper for app.py

Nothing in this package imports ``app.py``.
"""

from .version import __version__, SCHEMA_VERSION, CODENAME
from .config import get_config, CVETrackerConfig
from .models import (
    CVERecord,
    CVSSScore,
    Weakness,
    AffectedProduct,
    Reference,
    KEVInfo,
    SourceRecord,
    TimelineEntry,
    ChangeSet,
    FieldChange,
    AISummary,
    Subscription,
    Notification,
    SourceState,
)
from .enums import (
    Severity,
    CVSSVersion,
    SourceKind,
    ReferenceType,
    ExploitMaturity,
    EventType,
    Priority,
)

__all__ = [
    "__version__", "SCHEMA_VERSION", "CODENAME",
    "get_config", "CVETrackerConfig",
    "CVERecord", "CVSSScore", "Weakness", "AffectedProduct", "Reference",
    "KEVInfo", "SourceRecord", "TimelineEntry", "ChangeSet", "FieldChange",
    "AISummary", "Subscription", "Notification", "SourceState",
    "Severity", "CVSSVersion", "SourceKind", "ReferenceType",
    "ExploitMaturity", "EventType", "Priority",
    # Facade + integration helper are imported lazily to avoid importing
    # httpx/telegram at package-import time (tests import models only).
    "CVETracker", "register_cve_tracker",
]


def __getattr__(name):
    """Lazy access to the heavy facade so ``import cve_tracker`` stays cheap and
    dependency-light (PEP 562). ``CVETracker`` pulls in the engine/coordinator
    which pull in httpx; tests that only need models never pay that cost."""
    if name == "CVETracker":
        from .engine import CVETracker
        return CVETracker
    if name == "register_cve_tracker":
        from .integration import register_cve_tracker
        return register_cve_tracker
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
