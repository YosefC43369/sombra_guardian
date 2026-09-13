"""
test_mute_regression.py — regression test for the mute-bypass fix.

Before the fix, apply_mute() built ChatPermissions(can_send_message=False)
-- a kwarg that does not exist in python-telegram-bot v20+ and raises
TypeError before restrict_chat_member() is ever called. The surrounding
except only catches TelegramError, so the TypeError propagated and the
mute silently never applied: /mute and the automatic
"3 warnings -> mute" escalation were both no-ops.

These tests fail loudly if that regression returns: they assert that
apply_mute actually calls restrict_chat_member with a valid, fully
restrictive ChatPermissions, and returns True.
"""

import asyncio
import os
import tempfile
import unittest

from telegram import ChatPermissions

import security
import member_intel as mi
import member_incident as mic


class _FakeBot:
    def __init__(self, raise_exc=None):
        self.calls = []
        self._raise = raise_exc

    async def restrict_chat_member(self, chat_id, user_id, permissions=None,
                                   until_date=None):
        # Mirror the real API: an invalid ChatPermissions would already
        # have raised in the caller, so if we get here the object is valid.
        self.calls.append({"chat_id": chat_id, "user_id": user_id,
                           "permissions": permissions, "until_date": until_date})
        if self._raise is not None:
            raise self._raise

    async def send_message(self, *a, **k):
        pass


class _FakeChat:
    def __init__(self, chat_id=-100):
        self.id = chat_id


class _FakeUpdate:
    def __init__(self, chat):
        self.effective_chat = chat


class _FakeContext:
    def __init__(self, bot):
        self.bot = bot


class MuteRegressionTests(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db = path
        for m in (security, mi, mic):
            m.DB_PATH = path
        security.security_db_init()
        mi.member_intel_db_init()
        mic.member_incident_db_init()
        import app
        self.app = app
        for m in (app.mi, app.mic):
            m.DB_PATH = path

    def tearDown(self):
        try:
            os.remove(self._db)
        except OSError:
            pass

    def test_apply_mute_actually_restricts(self):
        bot = _FakeBot()
        update = _FakeUpdate(_FakeChat(-100))
        ok = asyncio.run(self.app.apply_mute(update, _FakeContext(bot), 555, 600,
                                             admin_user_id=777))
        self.assertTrue(ok, "apply_mute must return True on success")
        self.assertEqual(len(bot.calls), 1,
                         "restrict_chat_member must actually be called (was a no-op before)")
        perms = bot.calls[0]["permissions"]
        self.assertIsInstance(perms, ChatPermissions)
        # a real mute: text sending is revoked...
        self.assertFalse(perms.can_send_messages)
        # ...and so is the media/other-message escape hatch
        self.assertFalse(perms.can_send_photos)
        self.assertFalse(perms.can_send_other_messages)

    def test_apply_mute_permissions_object_is_constructible(self):
        """The exact construction apply_mute uses must not raise -- the
        original TypeError is what made the whole feature a no-op."""
        try:
            ChatPermissions.no_permissions()
        except TypeError as e:  # pragma: no cover
            self.fail(f"mute permissions object must be valid: {e}")

    def test_mute_records_successful_admin_action(self):
        bot = _FakeBot()
        update = _FakeUpdate(_FakeChat(-100))
        asyncio.run(self.app.apply_mute(update, _FakeContext(bot), 555, 600,
                                        admin_user_id=777))
        actions = mic.list_admin_actions(-100, target_user_id=555)
        self.assertTrue(actions)
        self.assertEqual(actions[0]["action"], "MUTED")
        self.assertEqual(actions[0]["executed"], 1)
        self.assertEqual(actions[0]["admin_user_id"], 777)

    def test_failed_restriction_is_recorded_as_not_executed(self):
        from telegram.error import TelegramError
        bot = _FakeBot(raise_exc=TelegramError("not enough rights"))
        update = _FakeUpdate(_FakeChat(-100))
        ok = asyncio.run(self.app.apply_mute(update, _FakeContext(bot), 555, 600,
                                             admin_user_id=777))
        self.assertFalse(ok)
        actions = mic.list_admin_actions(-100, target_user_id=555)
        self.assertTrue(actions)
        self.assertEqual(actions[0]["executed"], 0,
                         "a mute that Telegram refused must not be logged as executed")


if __name__ == "__main__":
    unittest.main()
