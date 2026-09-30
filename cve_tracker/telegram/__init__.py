"""
cve_tracker.telegram — the Telegram command surface.

Command *logic* lives in :class:`CVECommandService` (pure, testable); the thin
python-telegram-bot adapter is :class:`CVEHandlers`. Admin gating reuses the
host's is_admin via :class:`PermissionChecker`. The plugin suite registers these
through the platform's command registry — nothing here imports app.py.
"""

from .commands import CVECommandService
from .handlers import CVEHandlers
from .permissions import PermissionChecker
from .preferences import SubscriptionService

__all__ = [
    "CVECommandService", "CVEHandlers", "PermissionChecker", "SubscriptionService",
]
