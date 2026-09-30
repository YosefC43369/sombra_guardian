"""Tests for alerts — formatter, filters, routing, throttler, message splitting."""

import asyncio
import unittest

from cve_tracker.alerts.formatter import format_new_cve, format_updated_cve, format_compact, _local_split
from cve_tracker.alerts import filters, routing, templates
from cve_tracker.alerts.throttler import AlertThrottler
from cve_tracker.models import Subscription, ChangeSet, FieldChange
from cve_tracker.enums import ChangeKind
from cve_tracker import fixtures


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class FormatterTest(unittest.TestCase):
    def test_new_cve_contains_key_sections(self):
        chunks = format_new_cve(fixtures.record(kev=True))
        body = "\n".join(chunks)
        self.assertIn("พบ CVE ใหม่", body)
        self.assertIn("CVE-2026-93740", body)
        self.assertIn("CVSS", body)
        self.assertIn("CISA KEV: YES", body)
        self.assertIn("ลำดับความสำคัญภายใน", body)

    def test_html_escaped(self):
        r = fixtures.record()
        r.title = "Bad <script> & stuff"
        body = "\n".join(format_new_cve(r))
        self.assertIn("&lt;script&gt;", body)
        self.assertNotIn("<script>", body)

    def test_updated_cve(self):
        cs = ChangeSet(cve_id="CVE-2026-0001", changes=[
            FieldChange(kind=ChangeKind.SEVERITY.value, before="HIGH", after="CRITICAL",
                        note="HIGH → CRITICAL")])
        chunks = format_updated_cve(fixtures.record("CVE-2026-0001"), cs)
        body = "\n".join(chunks)
        self.assertIn("มีการอัปเดต", body)
        self.assertIn("HIGH → CRITICAL", body)

    def test_split_respects_limit(self):
        big = "\n\n".join(f"paragraph {i} " + "x" * 200 for i in range(60))
        parts = _local_split(big, 1000)
        self.assertTrue(all(len(p) <= 1000 for p in parts))
        self.assertGreater(len(parts), 1)

    def test_compact(self):
        s = format_compact(fixtures.record(kev=True))
        self.assertIn("CVE-2026-93740", s)
        self.assertIn("KEV", s)


class FormatterEdgeTest(unittest.TestCase):
    def test_no_cvss_renders_unknown(self):
        rec = fixtures.record_no_cvss()
        body = "\n".join(format_new_cve(rec))
        self.assertIn("CVE-", body)
        self.assertIn("ไม่พบข้อมูล", body)  # unknown severity/score shown honestly

    def test_epss_line_present_when_scored(self):
        rec = fixtures.record()
        from cve_tracker.enrichment.epss import apply_epss, EPSSScore
        apply_epss(rec, EPSSScore(cve_id=rec.cve_id, probability=0.9, percentile=0.99))
        body = "\n".join(format_new_cve(rec))
        self.assertIn("🔮", body)

    def test_multi_ref_truncates(self):
        rec = fixtures.record_multi_ref()
        body = "\n".join(format_new_cve(rec))
        self.assertIn("References", body)
        # more than the shown limit → "และอีก N รายการ"
        self.assertIn("และอีก", body)

    def test_fallback_footer(self):
        rec = fixtures.record()
        body = "\n".join(format_new_cve(rec, ai=None))
        self.assertIn("AI ไม่พร้อมใช้งาน", body)


class FilterTest(unittest.TestCase):
    def test_min_cvss(self):
        sub = Subscription(chat_id=1, min_cvss=8.0, min_severity="NONE")
        self.assertTrue(filters.matches(sub, fixtures.record())[0])
        self.assertFalse(filters.matches(sub, fixtures.record_medium())[0])

    def test_kev_only(self):
        sub = Subscription(chat_id=1, kev_only=True)
        self.assertTrue(filters.matches(sub, fixtures.record(kev=True))[0])
        self.assertFalse(filters.matches(sub, fixtures.record(kev=False))[0])

    def test_vendor_filter(self):
        sub = Subscription(chat_id=1, vendors=["totolink"], min_severity="NONE")
        self.assertTrue(filters.matches(sub, fixtures.record())[0])
        sub2 = Subscription(chat_id=1, vendors=["microsoft"], min_severity="NONE")
        self.assertFalse(filters.matches(sub2, fixtures.record())[0])

    def test_kev_bypasses_cvss_floor(self):
        # a record with no CVSS but KEV should still pass a cvss-floored sub
        r = fixtures.record_no_cvss()
        r.kev.in_kev = True
        sub = Subscription(chat_id=1, min_cvss=9.0, min_severity="NONE")
        self.assertTrue(filters.matches(sub, r)[0])

    def test_global_floor(self):
        self.assertTrue(filters.passes_global_floor(
            fixtures.record(), min_cvss=0.0, min_severity="HIGH"))
        self.assertFalse(filters.passes_global_floor(
            fixtures.record_low(), min_cvss=0.0, min_severity="HIGH"))


class RoutingTest(unittest.TestCase):
    def test_routes_to_matching_only(self):
        subs = [
            Subscription(chat_id=1, min_severity="CRITICAL"),
            Subscription(chat_id=2, min_severity="CRITICAL"),
            Subscription(chat_id=3, kev_only=True),  # no KEV → excluded
        ]
        notifs = routing.route(fixtures.record(kev=False), subs,
                               global_min_severity="MEDIUM")
        chats = {n.chat_id for n in notifs}
        self.assertEqual(chats, {1, 2})

    def test_admin_channel_added(self):
        notifs = routing.route(fixtures.record(), [], admin_chat_id=-999,
                               global_min_severity="MEDIUM")
        self.assertTrue(any(n.chat_id == -999 for n in notifs))


class ThrottlerTest(unittest.TestCase):
    def test_priority_order_and_drain(self):
        async def run():
            t = AlertThrottler(send_rate_per_sec=1000.0)
            await t.enqueue("low", priority=1)
            await t.enqueue("high", priority=100)
            sent = []
            async def send(p):
                sent.append(p)
                return True
            await t.drain(send, max_items=10)
            return sent
        sent = _run(run())
        self.assertEqual(sent[0], "high")  # higher priority first

    def test_flood_control_requeues(self):
        async def run():
            t = AlertThrottler(send_rate_per_sec=1000.0, max_attempts=3)
            await t.enqueue("msg", priority=1)
            calls = {"n": 0}
            async def send(p):
                calls["n"] += 1
                if calls["n"] == 1:
                    return ("retry", 0.01)
                return True
            stats = await t.drain(send, max_items=10)
            return stats, calls["n"]
        stats, n = _run(run())
        self.assertGreaterEqual(n, 2)  # retried
        self.assertEqual(stats["sent"], 1)


if __name__ == "__main__":
    unittest.main()
