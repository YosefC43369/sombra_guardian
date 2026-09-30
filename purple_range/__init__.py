"""
purple_range — a purple-team content, telemetry and analytics layer for Sombra Guardian.

Adds an ATT&CK emulation plan library, deterministic synthetic telemetry, a detection
expectation catalog, and program-wide coverage analytics ON TOP OF the existing
``purpleteam.py`` engine (which it reuses for exercises/emulations/detection) and the
existing redteam/scope_policy governance (which it respects, never bypasses).

Defensive / adversary-emulation only: no agents, no command execution, no shell, no
scope/RoE bypass. Dormant by default (``PURPLE_RANGE_ENABLED=false``).

Entry points: ``get_runtime(db_path, emit=...)`` and ``get_config()``.
Schema: ``migrations/m0007_purple_range.py``. Plugin: ``plugins/builtin/purple_range_suite.py``.
"""

from .version import __version__, PLAN_SCHEMA_VERSION
from .config import PurpleRangeConfig, get_config
from .service import PurpleRangeService
from .runtime import get_runtime, reset_runtimes, bind_emit

__all__ = [
    "__version__", "PLAN_SCHEMA_VERSION", "PurpleRangeConfig", "get_config",
    "PurpleRangeService", "get_runtime", "reset_runtimes", "bind_emit",
]
