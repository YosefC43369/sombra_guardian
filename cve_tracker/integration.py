"""
cve_tracker.integration — one-call wiring for a python-telegram-bot Application.

The primary integration path in this repo is the plugin
(``plugins/builtin/cve_tracker_suite.py``) plus the ``post_init`` background-loop
hook in app.py. :func:`register_cve_tracker` is the *alternative* for a project
that does not use that plugin platform: it registers the whole ``/cve*`` command
surface, the pagination callback, and the background loop directly onto a live
``telegram.ext.Application`` in a single call, sharing the same
:class:`~cve_tracker.engine.CVETracker` singleton so commands and the loop stay
in sync.

It is import-safe without python-telegram-bot installed (the telegram imports
happen inside the function), and it never raises into the caller — a wiring
failure is logged and the bot keeps running (rule §46).
"""

from __future__ import annotations

import logging
from typing import Callable, List, Optional

from .engine import get_tracker, cve_background_loop
from .telegram.handlers import CVEHandlers
from .telegram.permissions import PermissionChecker

logger = logging.getLogger("modbot.cve.integration")

# (command name, handler attribute, is_admin?) — mirrors the plugin's surface.
_COMMANDS = [
    ("cve", "cve", False),
    ("cve_info", "cve_info", False),
    ("cve_history", "cve_history", False),
    ("cve_search", "cve_search", False),
    ("cve_ask", "cve_ask", False),
    ("cve_recent", "cve_recent", False),
    ("cve_latest", "cve_latest", False),
    ("cve_kev", "cve_kev", False),
    ("cve_affected", "cve_affected", False),
    ("cve_digest", "cve_digest", False),
    ("cve_stats", "cve_stats", False),
    ("cve_report", "cve_report", False),
    ("cve_sources", "cve_sources", False),
    ("cve_subscribe", "cve_subscribe", False),
    ("cve_unsubscribe", "cve_unsubscribe", False),
    ("cve_preferences", "cve_preferences", False),
    ("cve_status", "cve_status", True),
    ("cve_sync", "cve_sync", True),
    ("cve_test", "cve_test", True),
]


def register_cve_tracker(app, *, is_admin: Optional[Callable] = None,
                         start_loop: bool = True, emit=None) -> List[str]:
    """Register the CVE subsystem onto ``app`` (a telegram Application).

    Parameters
    ----------
    app : telegram.ext.Application
    is_admin : callable, optional
        The host's admin check; admin commands self-gate through it. When None,
        admin commands are denied (fail-closed).
    start_loop : bool
        If True (default), schedule the background polling loop via
        ``post_init`` — dormant unless ``CVE_TRACKER_ENABLED=true``.
    emit : callable, optional
        An event emitter for cve.* domain events.

    Returns the list of registered command names.
    """
    registered: List[str] = []
    try:
        from telegram.ext import CommandHandler, CallbackQueryHandler
    except Exception:
        logger.warning("CVE integration: python-telegram-bot not available; skipping")
        return registered

    tracker = get_tracker(emit=emit)
    try:
        tracker.init_storage()
    except Exception:
        logger.exception("CVE integration: schema init failed (continuing)")

    perms = PermissionChecker(is_admin=is_admin)
    handlers = CVEHandlers(tracker.command_service, permissions=perms)

    for name, attr, _admin in _COMMANDS:
        handler = getattr(handlers, attr, None)
        if handler is None:
            continue
        try:
            app.add_handler(CommandHandler(name, handler))
            registered.append(name)
        except Exception:
            logger.exception("CVE integration: could not register /%s", name)

    try:
        app.add_handler(CallbackQueryHandler(handlers.on_callback, pattern=r"^cvepg:"))
    except Exception:
        logger.exception("CVE integration: could not register pagination callback")

    if start_loop:
        _wire_background_loop(app)

    logger.info("CVE integration: registered %d commands (loop=%s)",
                len(registered), start_loop)
    return registered


def _wire_background_loop(app) -> None:
    """Chain the CVE loop onto the app's post_init without clobbering an
    existing one. Best-effort; a telegram version without post_init hooks just
    skips the loop (commands still work, and app.py's own hook can start it)."""
    try:
        existing = getattr(app, "post_init", None)

        async def _post_init(application):
            if callable(existing):
                try:
                    await existing(application)
                except Exception:
                    logger.exception("CVE integration: prior post_init failed")
            import asyncio
            bot = getattr(application, "bot", None)
            if bot is not None:
                app.bot_data.setdefault(
                    "cve_task", asyncio.create_task(cve_background_loop(bot), name="cve_task"))

        # python-telegram-bot exposes post_init via the builder normally; if the
        # Application allows setting it, do so, else leave it to app.py.
        if hasattr(app, "post_init"):
            try:
                app.post_init = _post_init
            except Exception:
                logger.debug("CVE integration: app.post_init not settable; "
                             "start the loop via app.py post_init instead")
    except Exception:
        logger.exception("CVE integration: could not wire background loop")
