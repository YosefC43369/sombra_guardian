"""
behavioral_intelligence.telegram — Telegram command interface.

Exposes the behavioural commands (/behavior, /activity, /heatmap, /timeline,
/languages, /topics, /hashtags, /domains, /interactions, /anomalies, /changes,
/baseline, /behavior_report), their inline keyboards and callback handling, and a
``register`` hook to wire them onto an existing python-telegram-bot Application.

Every command is fail-closed authorized: account/person behavioural analysis
requires an authorized scope_policy program (``program=<id>``); Telegram admin is
never sufficient on its own.
"""

from . import commands, keyboards, callbacks
from .commands import (BehaviorCommandService, register, COMMANDS, HAVE_PTB)
from .callbacks import make_handler, dispatch


def register_all(application, *, service=None) -> int:
    """Register the behavioural commands AND the inline-callback handler on an
    Application. Returns the number of command handlers registered."""
    n = commands.register(application, service=service)
    handler = make_handler(service or commands._svc())
    if handler is not None:
        application.add_handler(handler)
    return n


__all__ = [
    "commands", "keyboards", "callbacks", "BehaviorCommandService", "register",
    "register_all", "COMMANDS", "make_handler", "dispatch", "HAVE_PTB",
]
