"""
threat_actor_intelligence.telegram — the CTI Telegram command interface.

Exposes /actor /campaign /malware /ioc /attack /capec /report /timeline
/actor_graph /campaign_graph /ioc_report, their inline keyboards and callback
handling, and a ``register_all`` hook to wire them onto an existing
python-telegram-bot Application. All commands are read-only public-CTI queries.
"""

from . import commands, keyboards, callbacks
from .commands import TAICommandService, register, COMMANDS, HAVE_PTB
from .callbacks import make_handler, dispatch


def register_all(application, *, service=None) -> int:
    """Register the CTI commands AND the inline-callback handler. Returns the
    number of command handlers registered. Collision-safe and fully guarded."""
    n = commands.register(application, service=service)
    handler = make_handler(service or commands._svc())
    if handler is not None:  # pragma: no cover
        application.add_handler(handler)
    return n


__all__ = ["commands", "keyboards", "callbacks", "TAICommandService", "register",
           "register_all", "COMMANDS", "make_handler", "dispatch", "HAVE_PTB"]
