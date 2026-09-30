"""
group_soc — Group Security Operations Center for Sombra Guardian.

A modular, defensive (Blue Team) SOC subsystem for Telegram communities. It ingests the
platform's existing bus events, normalizes them into privacy-safe SecurityEvents, and
runs the SOC loop (correlate → detect → prioritize → alert → case/incident → timeline
→ story → report).

Public entry points:
  * ``get_runtime(db_path, emit=...)`` — the per-DB orchestration seam
  * ``get_config()``                   — feature flags / tunables (dormant by default)
  * ``group_soc.models``               — the value objects
The plugin ``plugins/builtin/group_soc_suite.py`` wires this into the bot; schema lives
in ``migrations/m0006_group_soc.py``. Nothing here imports app.py.
"""

from .version import __version__, SCHEMA_VERSION
from .config import SocConfig, get_config
from .runtime import SocRuntime, get_runtime, reset_runtimes

__all__ = [
    "__version__", "SCHEMA_VERSION", "SocConfig", "get_config",
    "SocRuntime", "get_runtime", "reset_runtimes",
]
