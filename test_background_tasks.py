"""
test_background_tasks.py — tests for the background-task lifecycle
helpers added to app.py in Phase 3.

Importing app.py pulls in python-telegram-bot, which is not required to
test these helpers: _start_background_task, _on_background_task_done and
post_shutdown only touch asyncio and a dict-like `bot_data`. To keep this
suite runnable wherever the rest of the suite runs, the three helpers are
loaded out of app.py's source with ast/exec rather than by importing the
module. If app.py stops defining them, or their bodies stop being
self-contained, these tests fail loudly rather than silently passing
against a stale copy.
"""

import ast
import asyncio
import logging
import unittest
from unittest import mock

_HELPERS = ("BACKGROUND_SHUTDOWN_TIMEOUT_SECONDS", "_on_background_task_done",
            "_start_background_task", "post_init", "post_shutdown")


def _load_lifecycle_helpers():
    """exec only the lifecycle definitions from app.py, with a stub logger."""
    with open("app.py", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())

    wanted = []
    for node in tree.body:
        name = getattr(node, "name", None)
        if name in _HELPERS:
            wanted.append(node)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id in _HELPERS:
                    wanted.append(node)

    found = set()
    for node in wanted:
        found.add(getattr(node, "name", None)
                  or node.targets[0].id)
    missing = set(_HELPERS) - found
    if missing:
        raise AssertionError(f"app.py no longer defines: {sorted(missing)}")

    ns = {"asyncio": asyncio, "logger": logging.getLogger("modbot.test")}
    exec(compile(ast.Module(body=wanted, type_ignores=[]), "app.py", "exec"), ns)
    return ns


class FakeApp:
    """Stands in for telegram.ext.Application: the helpers only use
    .bot_data and .bot."""
    def __init__(self):
        self.bot_data = {}
        self.bot = object()


class BackgroundTaskTestCase(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.ns = _load_lifecycle_helpers()

    def setUp(self):
        self.app = FakeApp()
        self.start = self.ns["_start_background_task"]
        self.shutdown = self.ns["post_shutdown"]

    @staticmethod
    async def _forever():
        await asyncio.sleep(3600)

    # ---- startup ----

    async def test_task_is_created_and_stored_under_its_key(self):
        task = self.start(self.app, "news_task", self._forever)
        self.addCleanup(task.cancel)
        self.assertIs(self.app.bot_data["news_task"], task)
        self.assertFalse(task.done())

    async def test_duplicate_start_returns_the_running_task(self):
        """A second post_init must not leave an orphaned loop polling and
        posting alongside its replacement."""
        first = self.start(self.app, "news_task", self._forever)
        self.addCleanup(first.cancel)
        second = self.start(self.app, "news_task", self._forever)
        self.assertIs(second, first)
        self.assertIs(self.app.bot_data["news_task"], first)

    async def test_duplicate_start_creates_no_second_task(self):
        before = len(asyncio.all_tasks())
        first = self.start(self.app, "news_task", self._forever)
        self.addCleanup(first.cancel)
        after_one = len(asyncio.all_tasks())
        self.start(self.app, "news_task", self._forever)
        self.assertEqual(len(asyncio.all_tasks()), after_one)
        self.assertEqual(after_one, before + 1)

    async def test_finished_task_is_replaced_not_reused(self):
        async def immediate():
            return None
        done = self.start(self.app, "news_task", immediate)
        await asyncio.sleep(0)
        await done
        replacement = self.start(self.app, "news_task", self._forever)
        self.addCleanup(replacement.cancel)
        self.assertIsNot(replacement, done)

    # ---- runtime failure visibility ----

    async def test_task_death_is_logged_with_the_task_name(self):
        """asyncio would otherwise surface this only at garbage-collection
        time, long after the feature stopped working."""
        async def boom():
            raise RuntimeError("loop crashed")

        with self.assertLogs("modbot.test", level="ERROR") as cm:
            task = self.start(self.app, "news_task", boom)
            with self.assertRaises(RuntimeError):
                await task
            await asyncio.sleep(0)      # let the done-callback run
        joined = "\n".join(cm.output)
        self.assertIn("BACKGROUND TASK DIED", joined)
        self.assertIn("news_task", joined)

    async def test_cancellation_is_not_reported_as_a_death(self):
        logger = logging.getLogger("modbot.test")
        task = self.start(self.app, "news_task", self._forever)
        with mock.patch.object(logger, "error") as err:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            await asyncio.sleep(0)
        err.assert_not_called()

    # ---- shutdown ----

    async def test_shutdown_cancels_every_registered_task(self):
        news = self.start(self.app, "news_task", self._forever)
        sweep = self.start(self.app, "github_sweep_task", self._forever)
        await self.shutdown(self.app)
        self.assertTrue(news.cancelled())
        self.assertTrue(sweep.cancelled())

    async def test_shutdown_is_safe_when_no_tasks_were_started(self):
        await self.shutdown(self.app)          # must not raise
        self.assertEqual(self.app.bot_data, {})

    async def test_shutdown_uses_a_bounded_wait_and_logs_on_timeout(self):
        """A loop that swallows CancelledError, or blocks in a
        non-cancellable call, must not stop the process from exiting.
        The timeout is forced here so the branch is exercised
        deterministically rather than by racing a real stubborn task."""
        task = self.start(self.app, "news_task", self._forever)
        self.addCleanup(task.cancel)

        real_wait_for = asyncio.wait_for

        async def fake_wait_for(awaitable, timeout):
            self.assertEqual(timeout,
                             self.ns["BACKGROUND_SHUTDOWN_TIMEOUT_SECONDS"])
            raise asyncio.TimeoutError

        with mock.patch.object(asyncio, "wait_for", fake_wait_for):
            with self.assertLogs("modbot.test", level="ERROR") as cm:
                await real_wait_for(self.shutdown(self.app), timeout=5)

        joined = "\n".join(cm.output)
        self.assertIn("DID NOT STOP", joined)
        self.assertIn("news_task", joined)
        self.assertTrue(task.cancelling() or task.cancelled(),
                        "cancel() must still be called before the wait")

    async def test_shutdown_timeout_constant_is_bounded_and_positive(self):
        value = self.ns["BACKGROUND_SHUTDOWN_TIMEOUT_SECONDS"]
        self.assertGreater(value, 0)
        self.assertLessEqual(value, 60)


if __name__ == "__main__":
    unittest.main()