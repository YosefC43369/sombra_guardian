"""
news_intelligence.telegram — the /news* Telegram command interface.

Exposes /news /news_today /news_week /news_search /news_actor /news_campaign
/news_cve /news_malware /news_org /news_country /news_graph /news_brief /news_report,
their inline navigation keyboards and callback handling, and a ``register_all`` hook to
wire them onto an existing python-telegram-bot Application. All commands are read-only
public-news queries. Collision-safe and fully guarded.
"""

from . import commands, keyboards, callbacks
from .commands import NewsCommandService, register, COMMANDS, HAVE_PTB
from .callbacks import make_handler, dispatch


def register_all(application, *, service=None) -> int:
    """Register the /news commands AND the inline-callback handler. Returns the number
    of command handlers registered. Collision-safe and fully guarded."""
    n = commands.register(application, service=service)
    handler = make_handler(service or commands._svc())
    if handler is not None:  # pragma: no cover
        application.add_handler(handler)
    return n


__all__ = ["commands", "keyboards", "callbacks", "NewsCommandService", "register",
           "register_all", "COMMANDS", "make_handler", "dispatch", "HAVE_PTB"]
