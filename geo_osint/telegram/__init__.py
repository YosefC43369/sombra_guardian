"""
geo_osint.telegram — the Telegram surface (spec §44-45).

  * :class:`GeoCommandService` — pure, bot-independent command logic (14 commands);
  * :func:`build_handlers` / :func:`build_handler` — PTB registration helpers;
  * keyboards + callbacks for interactive follow-ups.

The service is fully testable offline; the PTB integration is imported defensively.
"""

from .commands import GeoCommandService, build_handlers
from . import keyboards, callbacks

__all__ = ["GeoCommandService", "build_handlers", "keyboards", "callbacks"]
