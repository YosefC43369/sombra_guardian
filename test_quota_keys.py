"""
test_quota_keys.py — tests for the AI quota-key system.

Pure SQLite, no network. Runs against a throwaway DB file so bot.db is never
touched (python -m unittest test_quota_keys).
"""

import os
import time
import tempfile
import unittest

import quota_keys


class QuotaKeysTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig = quota_keys.DB_PATH
        quota_keys.DB_PATH = os.path.join(self._tmp, "keys.db")
        quota_keys.quota_keys_db_init()

    def tearDown(self):
        quota_keys.DB_PATH = self._orig

    def test_generate_returns_raw_keys_and_stores_hashes(self):
        created = quota_keys.generate_keys(3, created_by=1)
        self.assertEqual(len(created), 3)
        for item in created:
            self.assertRegex(item["key"], r"^[0-9a-f]{64}$")
            self.assertTrue(item["label"].startswith("Key #"))
        # unused keys show as 'unused'
        rows = quota_keys.list_keys()
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(r["status"] == "unused" for r in rows))

    def test_redeem_binds_user_and_starts_ttl(self):
        key = quota_keys.generate_keys(1, created_by=1)[0]["key"]
        now = int(time.time())
        ok, reason, info = quota_keys.redeem_key(key, user_id=42, username="alice",
                                                 now=now)
        self.assertTrue(ok)
        self.assertEqual(reason, "ok")
        self.assertEqual(info["expires_at"], now + quota_keys._ttl_seconds())
        # same user can use again while valid
        ok2, _, _ = quota_keys.redeem_key(key, user_id=42, now=now + 100)
        self.assertTrue(ok2)

    def test_redeem_rejects_other_user(self):
        key = quota_keys.generate_keys(1, created_by=1)[0]["key"]
        quota_keys.redeem_key(key, user_id=42)
        ok, reason, _ = quota_keys.redeem_key(key, user_id=99)
        self.assertFalse(ok)
        self.assertEqual(reason, "bound_other")

    def test_expiry_and_purge(self):
        key = quota_keys.generate_keys(1, created_by=1)[0]["key"]
        t0 = int(time.time())
        quota_keys.redeem_key(key, user_id=42, now=t0)
        later = t0 + quota_keys._ttl_seconds() + 1
        ok, reason, _ = quota_keys.redeem_key(key, user_id=42, now=later)
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")
        # expired key is removed by purge; unused keys are not
        quota_keys.generate_keys(1, created_by=1)   # a fresh unused key
        removed = quota_keys.purge_expired(now=later)
        self.assertEqual(removed, 1)
        self.assertIsNone(quota_keys.active_key_for_user(42, now=later))

    def test_unknown_and_revoked(self):
        ok, reason, _ = quota_keys.redeem_key("deadbeef" * 8, user_id=1)
        self.assertFalse(ok)
        self.assertEqual(reason, "not_found")
        item = quota_keys.generate_keys(1, created_by=1)[0]
        self.assertTrue(quota_keys.revoke_key(item["label"]))
        ok2, reason2, _ = quota_keys.redeem_key(item["key"], user_id=1)
        self.assertFalse(ok2)
        self.assertEqual(reason2, "revoked")

    def test_active_key_lookup(self):
        key = quota_keys.generate_keys(1, created_by=1)[0]["key"]
        self.assertIsNone(quota_keys.active_key_for_user(7))
        quota_keys.redeem_key(key, user_id=7, username="bob")
        active = quota_keys.active_key_for_user(7)
        self.assertIsNotNone(active)
        self.assertIsNotNone(active["remaining_seconds"])


if __name__ == "__main__":
    unittest.main()
