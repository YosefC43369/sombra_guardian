"""Tests for the storage layer — repository CRUD, indexes, retention, cache, migrations."""

import os
import tempfile
import unittest

from cve_tracker.storage import CVERepository, migrations
from cve_tracker.storage.cache import TTLCache
from cve_tracker.storage.retention import RetentionManager
from cve_tracker.config import get_config
from cve_tracker.models import Subscription, Notification, SourceState, AISummary
from cve_tracker import fixtures


class MigrationTest(unittest.TestCase):
    def test_apply_verify_teardown(self):
        db = tempfile.mktemp(suffix=".db")
        migrations.apply(db)
        self.assertTrue(migrations.verify(db))
        self.assertEqual(migrations.current_version(db), 1)
        migrations.teardown(db)
        self.assertFalse(migrations.verify(db))
        os.remove(db)

    def test_does_not_touch_existing_tables(self):
        import sqlite3
        db = tempfile.mktemp(suffix=".db")
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE other(x)")
        conn.execute("INSERT INTO other VALUES (7)")
        conn.commit()
        conn.close()
        migrations.apply(db)
        conn = sqlite3.connect(db)
        self.assertEqual(conn.execute("SELECT x FROM other").fetchone()[0], 7)
        conn.close()
        os.remove(db)


class RepositoryTest(unittest.TestCase):
    def setUp(self):
        self.db = tempfile.mktemp(suffix=".db")
        migrations.apply(self.db)
        self.repo = CVERepository(self.db)

    def tearDown(self):
        os.remove(self.db)

    def test_save_change_detection(self):
        r = fixtures.record("CVE-2026-0001")
        self.assertEqual(self.repo.save_record(r), (True, True))
        self.assertEqual(self.repo.save_record(r), (False, False))
        r.description = "changed description here"
        self.assertEqual(self.repo.save_record(r), (False, True))

    def test_indexed_queries(self):
        self.repo.save_record(fixtures.record("CVE-2026-0001", kev=True))
        self.repo.save_record(fixtures.record("CVE-2026-0002", vendor="Apache",
                                              product="HTTP Server"))
        self.assertEqual(len(self.repo.by_severity("CRITICAL")), 2)
        self.assertEqual(len(self.repo.kev_records()), 1)
        self.assertEqual(len(self.repo.by_vendor("apache")), 1)
        self.assertEqual(len(self.repo.by_cwe("CWE-121")), 2)
        self.assertEqual(len(self.repo.by_min_cvss(9.0)), 2)
        self.assertEqual(self.repo.count(), 2)

    def test_stats(self):
        self.repo.save_record(fixtures.record("CVE-2026-0001", kev=True))
        s = self.repo.stats()
        self.assertEqual(s["total"], 1)
        self.assertEqual(s["kev"], 1)
        self.assertIn("CRITICAL", s["by_severity"])

    def test_subscription_crud(self):
        self.repo.upsert_subscription(Subscription(chat_id=-100, min_cvss=8.0))
        self.assertIsNotNone(self.repo.get_subscription(-100))
        self.assertEqual(len(self.repo.list_subscriptions()), 1)
        self.repo.delete_subscription(-100)
        self.assertIsNone(self.repo.get_subscription(-100))

    def test_notification_idempotency(self):
        n = Notification(cve_id="CVE-2026-0001", chat_id=5)
        self.assertIsNotNone(self.repo.record_notification(n))
        self.assertIsNone(self.repo.record_notification(n))  # dup
        self.assertTrue(self.repo.notification_exists(n.dedupe_key))
        self.repo.mark_notification(n.dedupe_key, "sent")
        self.assertEqual(self.repo.notification_stats().get("sent"), 1)

    def test_source_state(self):
        st = SourceState(source="nvd", records_new=5, health="healthy",
                         last_modified_seen=123)
        self.repo.save_source_state(st)
        got = self.repo.get_source_state("nvd")
        self.assertEqual(got.records_new, 5)
        self.assertEqual(got.last_modified_seen, 123)

    def test_ai_summary_cache(self):
        s = AISummary(cve_id="CVE-2026-0001", input_hash="h", summary_th="x")
        self.repo.save_ai_summary(s)
        self.assertIsNotNone(self.repo.get_ai_summary("CVE-2026-0001", "h"))
        self.assertIsNotNone(self.repo.get_latest_ai_summary("CVE-2026-0001"))

    def test_events_and_audit(self):
        self.repo.log_event("cve.discovered", "CVE-2026-0001", {"x": 1})
        self.repo.audit("cve_created", cve_id="CVE-2026-0001")
        self.assertEqual(len(self.repo.recent_events()), 1)

    def test_bulk_save(self):
        recs = [fixtures.record(f"CVE-2026-{1000+i}") for i in range(1, 6)]
        results = self.repo.save_records(recs)
        self.assertEqual(len(results), 5)
        self.assertEqual(self.repo.count(), 5)


class CacheTest(unittest.TestCase):
    def test_ttl_expiry(self):
        c = TTLCache(ttl=0.05)
        c.set("k", "v")
        self.assertEqual(c.get("k"), "v")
        import time
        time.sleep(0.06)
        self.assertIsNone(c.get("k"))

    def test_get_or_set(self):
        c = TTLCache(ttl=10)
        calls = {"n": 0}
        def factory():
            calls["n"] += 1
            return 42
        self.assertEqual(c.get_or_set("k", factory), 42)
        self.assertEqual(c.get_or_set("k", factory), 42)
        self.assertEqual(calls["n"], 1)


class RetentionTest(unittest.TestCase):
    def test_prunes_history_keeps_cves(self):
        db = tempfile.mktemp(suffix=".db")
        migrations.apply(db)
        repo = CVERepository(db)
        repo.save_record(fixtures.record("CVE-2026-0001"))
        # insert an old event directly
        import sqlite3
        conn = sqlite3.connect(db)
        conn.execute("INSERT INTO cve_events(cve_id,event_type,payload,created_at) VALUES (?,?,?,?)",
                     ("CVE-2026-0001", "old", "{}", 1))
        conn.commit()
        conn.close()
        cfg = get_config()
        rm = RetentionManager(repo, cfg.retention)
        deleted = rm.run()
        self.assertGreaterEqual(deleted.get("cve_events", 0), 1)
        self.assertEqual(repo.count(), 1)  # CVE kept
        os.remove(db)


if __name__ == "__main__":
    unittest.main()
