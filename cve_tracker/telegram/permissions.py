"""
cve_tracker.telegram.permissions — reuse the bot's existing authority.

There is no new auth system here (same stance as ``plugins/base.py``): admin
commands are gated by the host's existing ``is_admin`` check, passed in by the
plugin suite. This module only wraps that callable so the command service can
ask 'is this user allowed to run an admin command?' without importing app.py.
"""

from __future__ import annotations

from typing import Awaitable, Callable, Optional

# is_admin may be sync or async in the host; we support both.
IsAdmin = Callable[..., object]


class PermissionChecker:
    def __init__(self, is_admin: Optional[IsAdmin] = None):
        self._is_admin = is_admin

    async def is_admin(self, update, context) -> bool:
        """Best-effort admin check via the host's callable. Fails CLOSED — if we
        can't confirm admin, deny the admin action."""
        if self._is_admin is None:
            return False
        try:
            result = self._is_admin(update, context)
            if hasattr(result, "__await__"):
                result = await result
            return bool(result)
        except TypeError:
            # host is_admin may take (user_id, chat_id) etc.
            try:
                user = update.effective_user
                chat = update.effective_chat
                result = self._is_admin(
                    user.id if user else None, chat.id if chat else None)
                if hasattr(result, "__await__"):
                    result = await result
                return bool(result)
            except Exception:
                return False
        except Exception:
            return False
