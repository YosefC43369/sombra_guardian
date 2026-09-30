"""Tests for the Telegram command surface, preferences, NL search, pagination —
all text-in/text-out, no bot."""

import asyncio
import os
import tempfile
import unittest

from cve_tracker.config import get_config
from cve_tracker.storage import CVERepository, migrations
from cve_tracker.telegram.commands import CVECommandService
from cve_tracker.telegram.preferences import SubscriptionService
from cve_tracker.telegram import pagination
from cve_tracker.search.nl import deterministic_nl
from cve_tracker import fixtures


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class CommandServiceTest(unittest.TestCase):
    def setUp(self):
        self.db = tempfile.mktemp(suffix=".db")
        migrations.apply(self.db)
        self.repo = CVERepository(self.db)
        self.repo.save_record(fixtures.record("CVE-2026-0001", vendor="TOTOLINK", product="A3002MU", kev=True))
        self.repo.save_record(fixtures.record("CVE-2026-0002", vendor="Apache", product="HTTP Server",
                                              score=7.5,
                                              vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"))
        self.svc = CVECommandService(self.repo, get_config())

    def tearDown(self):
        os.remove(self.db)

    def test_info_and_missing(self):
        self.assertIn("CVE-2026-0001", self.svc.cmd_info("CVE-2026-0001"))
        self.assertIn("ไม่พบ", self.svc.cmd_info("CVE-2026-9999"))

    def test_recent_kev_stats(self):
        self.assertIn("CVE-2026-0001", self.svc.cmd_recent())
        self.assertIn("CVE-2026-0001", self.svc.cmd_kev())
        self.assertIn("สถิติ", self.svc.cmd_stats())

    def test_search_and_token(self):
        text, token = self.svc.cmd_search("apache")
        self.assertIsNotNone(token)
        self.assertEqual(self.svc.query_for_token(token), "apache")

    def test_digest_and_report(self):
        self.assertIn("สรุป CVE", self.svc.cmd_digest())
        self.assertIn("รายงาน CVE", self.svc.cmd_report())

    def test_history_and_affected(self):
        self.repo.log_event("cve.discovered", "CVE-2026-0001", {})
        self.assertIn("ประวัติ", self.svc.cmd_history("CVE-2026-0001"))
        # affected requires product+version
        self.assertIn("ใช้", self.svc.cmd_affected(["onlyproduct"]))
        out = self.svc.cmd_affected(["A3002MU", "1.1.0", "totolink"])
        self.assertIsInstance(out, str)

    def test_subscribe_flow(self):
        out = self.svc.cmd_subscribe(-100, 0, ["critical"])
        self.assertIn("ตั้งค่า", out)
        self.assertIn("CRITICAL", self.svc.cmd_preferences(-100, 0))
        self.assertIn("ปิด", self.svc.cmd_unsubscribe(-100, 0))

    def test_ask_nl(self):
        # no AI configured → deterministic path
        out = _run(self.svc.cmd_ask("ช่องโหว่ critical ของ apache"))
        self.assertIn("ตัวกรอง", out)

    def test_help(self):
        h = self.svc.cmd_help()
        for cmd in ("/cve_search", "/cve_ask", "/cve_subscribe", "/cve_digest"):
            self.assertIn(cmd, h)


class SubscriptionServiceTest(unittest.TestCase):
    def setUp(self):
        self.db = tempfile.mktemp(suffix=".db")
        migrations.apply(self.db)
        self.repo = CVERepository(self.db)
        self.subs = SubscriptionService(self.repo)

    def tearDown(self):
        os.remove(self.db)

    def test_apply_filters(self):
        sub, notes = self.subs.subscribe(-100, 0, ["cvss", "8", "vendor", "microsoft"])
        self.assertEqual(sub.min_cvss, 8.0)
        self.assertIn("microsoft", sub.vendors)

    def test_kev_only(self):
        sub, _ = self.subs.subscribe(-100, 0, ["kev"])
        self.assertTrue(sub.kev_only)

    def test_describe(self):
        sub, _ = self.subs.subscribe(-100, 0, ["critical"])
        self.assertIn("CRITICAL", self.subs.describe(sub))


class NLParseTest(unittest.TestCase):
    def test_deterministic_extraction(self):
        q = deterministic_nl("ช่องโหว่ critical ของ apache ที่เพิ่งประกาศ")
        self.assertEqual(q.severity, "CRITICAL")
        self.assertEqual(q.vendor, "apache")
        self.assertTrue(q.recent)

    def test_kev_and_cvss(self):
        q = deterministic_nl("show me exploited CVEs with cvss 9")
        self.assertTrue(q.kev_only)
        self.assertEqual(q.min_cvss, 9.0)

    def test_cwe_extract(self):
        q = deterministic_nl("bugs with CWE-79 in wordpress")
        self.assertEqual(q.cwe, "CWE-79")
        self.assertEqual(q.vendor, "wordpress")


class PaginationTest(unittest.TestCase):
    def test_callback_roundtrip(self):
        data = f"{pagination.CALLBACK_PREFIX}:3:tok123"
        parsed = pagination.parse_callback(data)
        self.assertEqual(parsed, (3, "tok123"))
        self.assertIsNone(pagination.parse_callback("garbage"))


if __name__ == "__main__":
    unittest.main()
