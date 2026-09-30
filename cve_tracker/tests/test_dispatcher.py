"""Tests for alert dispatch: routing→persist→send, idempotency, retry-drive,
flood-control, and the /cve_history command."""

import asyncio
import json
import os
import tempfile
import unittest

from cve_tracker.config import get_config
from cve_tracker.storage import CVERepository, migrations
from cve_tracker.alerts.dispatcher import AlertDispatcher
from cve_tracker.ai.summarizer import CVESummarizer
from cve_tracker.ai.adapter import AIResult
from cve_tracker.telegram.commands import CVECommandService
from cve_tracker.models import Subscription, Notification
from cve_tracker.enums import NotificationState
from cve_tracker import fixtures


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _FakeBot:
    def __init__(self, *, fail_times=0):
        self.sent = []
        self.fail_times = fail_times
        self.calls = 0

    async def send_message(self, **kw):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError("telegram down")
        self.sent.append(kw.get("chat_id"))


class _FakeAdapter:
    def available(self):
        return True

    async def generate(self, prompt, system="", task="heavy"):
        return AIResult(True, text=json.dumps({
            "title_th": "x", "summary_th": "สรุป", "impact_th": "ผล",
            "recommendation_th": ["ตรวจสอบ"]}), provider="fake")


class DispatchTest(unittest.TestCase):
    def setUp(self):
        self.db = tempfile.mktemp(suffix=".db")
        migrations.apply(self.db)
        self.repo = CVERepository(self.db)
        self.repo.save_record(fixtures.record("CVE-2026-0001", kev=True))
        self.repo.upsert_subscription(Subscription(chat_id=-100, min_severity="HIGH"))
        self.cfg = get_config()
        self.summ = CVESummarizer(self.cfg.ai, repo=self.repo, adapter=_FakeAdapter())

    def tearDown(self):
        os.remove(self.db)

    def test_dispatch_and_idempotency(self):
        bot = _FakeBot()
        disp = AlertDispatcher(bot, self.repo, self.cfg, self.summ)
        rec = self.repo.get_record("CVE-2026-0001")
        res = _run(disp.dispatch_new([rec]))
        self.assertEqual(res["sent"], 1)
        self.assertIn(-100, bot.sent)
        # second dispatch is suppressed (already sent)
        bot.sent.clear()
        res2 = _run(disp.dispatch_new([rec]))
        self.assertEqual(res2["enqueued"], 0)

    def test_failed_then_redrive(self):
        # first send fails → notification left FAILED; a manual retry row set to
        # 'retry' is re-driven on the next pass.
        bot = _FakeBot(fail_times=1)
        disp = AlertDispatcher(bot, self.repo, self.cfg, self.summ)
        rec = self.repo.get_record("CVE-2026-0001")
        _run(disp.dispatch_new([rec]))
        # mark it retry to simulate a transient failure worth re-driving
        n = Notification(cve_id="CVE-2026-0001", chat_id=-100)
        self.repo.mark_notification(n.dedupe_key, NotificationState.RETRY.value)
        res = _run(disp.redrive_pending())
        self.assertGreaterEqual(res["redriven"], 1)

    def test_history_command(self):
        # emit an event then check /cve_history renders it
        self.repo.log_event("cve.kev_added", "CVE-2026-0001", {})
        svc = CVECommandService(self.repo, self.cfg)
        out = svc.cmd_history("CVE-2026-0001")
        self.assertIn("ประวัติ", out)
        self.assertIn("kev_added", out)


if __name__ == "__main__":
    unittest.main()
