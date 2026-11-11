# -*- coding: utf-8 -*-
"""เทสต์ pure logic ของ broadcast (store + core) — ไม่แตะ telegram"""

import os
import tempfile
import unittest
from datetime import timedelta

from broadcast import store, core


class StoreConfigTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "broadcast.json")

    def test_defaults(self):
        cfg = store.get_config(self.path)
        self.assertFalse(cfg["enabled"])          # ดีฟอลต์ปิด
        self.assertTrue(cfg["collect"])
        self.assertEqual(cfg["link"], "")

    def test_update_config_persists(self):
        store.update_config(lambda c: c.__setitem__("link", "https://x.com"), self.path)
        store.update_config(lambda c: c.__setitem__("enabled", True), self.path)
        cfg = store.get_config(self.path)
        self.assertEqual(cfg["link"], "https://x.com")
        self.assertTrue(cfg["enabled"])

    def test_mark_ran(self):
        store.mark_broadcast_ran(path=self.path)
        cfg = store.get_config(self.path)
        self.assertEqual(cfg["runs"], 1)
        self.assertIsNotNone(cfg["last_run_iso"])


class StoreTargetTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "broadcast.json")

    def test_add_and_list(self):
        store.add_target(-100, "กลุ่มเอ", "supergroup", path=self.path)
        store.add_target(222, "คนบี", "private", path=self.path)
        db = store.load(self.path)
        self.assertEqual(len(store.list_targets(db)), 2)

    def test_add_idempotent_updates_title(self):
        store.add_target(-100, "", "", path=self.path)
        store.add_target(-100, "ชื่อใหม่", "group", path=self.path)
        db = store.load(self.path)
        self.assertEqual(len(store.list_targets(db)), 1)
        self.assertEqual(store.get_target(db, -100)["title"], "ชื่อใหม่")

    def test_remember_respects_collect_flag(self):
        self.assertTrue(store.remember(-100, "g", "group", path=self.path))
        store.update_config(lambda c: c.__setitem__("collect", False), self.path)
        self.assertFalse(store.remember(-999, "h", "group", path=self.path))
        db = store.load(self.path)
        self.assertEqual(len(store.list_targets(db)), 1)

    def test_mute_excludes_from_active(self):
        store.add_target(-100, "g", "group", path=self.path)
        store.add_target(-200, "h", "group", path=self.path)
        store.set_muted(-100, True, path=self.path)
        db = store.load(self.path)
        self.assertEqual(len(store.list_targets(db, include_muted=False)), 1)
        self.assertEqual(len(store.list_targets(db, include_muted=True)), 2)

    def test_record_result_drops_on_permanent(self):
        store.add_target(-100, "g", "group", path=self.path)
        store.record_result(-100, ok=False, drop=True, path=self.path)
        self.assertIsNone(store.get_target(store.load(self.path), -100))

    def test_record_result_drops_after_max_fails(self):
        store.add_target(-100, "g", "group", path=self.path)
        for _ in range(store.MAX_FAILS_BEFORE_DROP):
            store.record_result(-100, ok=False, path=self.path)
        self.assertIsNone(store.get_target(store.load(self.path), -100))

    def test_record_result_ok_resets_fails(self):
        store.add_target(-100, "g", "group", path=self.path)
        store.record_result(-100, ok=False, path=self.path)
        store.record_result(-100, ok=True, path=self.path)
        t = store.get_target(store.load(self.path), -100)
        self.assertEqual(t["fails"], 0)
        self.assertIsNotNone(t["last_ok_iso"])

    def test_clear(self):
        store.add_target(-100, path=self.path)
        store.add_target(-200, path=self.path)
        self.assertEqual(store.clear_targets(self.path), 2)
        self.assertEqual(len(store.list_targets(store.load(self.path))), 0)


class CoreOwnerTests(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("BROADCAST_OWNER_IDS", None)

    def test_owner_parse(self):
        os.environ["BROADCAST_OWNER_IDS"] = "111, 222 333"
        self.assertEqual(core.owner_ids(), {111, 222, 333})
        self.assertTrue(core.is_owner(222))
        self.assertFalse(core.is_owner(999))

    def test_no_owner(self):
        os.environ.pop("BROADCAST_OWNER_IDS", None)
        self.assertFalse(core.owner_configured())
        self.assertFalse(core.is_owner(111))


class CoreDueTests(unittest.TestCase):
    def _cfg(self, **over):
        c = {"enabled": True, "link": "https://x.com", "interval_sec": 3600,
             "last_run_iso": None}
        c.update(over)
        return c

    def test_due_first_time(self):
        self.assertTrue(core.is_due(self._cfg()))

    def test_not_due_when_off_or_no_link(self):
        self.assertFalse(core.is_due(self._cfg(enabled=False)))
        self.assertFalse(core.is_due(self._cfg(link="")))

    def test_interval_gate(self):
        now = store.utcnow()
        c1 = self._cfg(last_run_iso=store.iso(now - timedelta(seconds=1800)))
        self.assertFalse(core.is_due(c1, now))
        c2 = self._cfg(last_run_iso=store.iso(now - timedelta(seconds=3601)))
        self.assertTrue(core.is_due(c2, now))


class CoreRenderTests(unittest.TestCase):
    def test_bare_link(self):
        self.assertEqual(core.render({"link": "https://x.com"}), "https://x.com")

    def test_message_prefix(self):
        out = core.render({"link": "https://x.com", "message": "ดูเลย"})
        self.assertEqual(out, "ดูเลย\nhttps://x.com")

    def test_message_with_url_placeholder(self):
        out = core.render({"link": "https://x.com", "message": "ไป {url} สิ"})
        self.assertEqual(out, "ไป https://x.com สิ")

    def test_template_label(self):
        out = core.render({"link": "https://sub.example.com", "template": "{label}: {url}"})
        self.assertIn("example.com", out)
        self.assertIn("https://sub.example.com", out)


class CoreParseTargetTests(unittest.TestCase):
    def test_numeric_id(self):
        self.assertEqual(core.parse_target("-1001234567890"),
                         {"ref": -1001234567890, "kind": "id"})

    def test_username(self):
        self.assertEqual(core.parse_target("@mychannel"),
                         {"ref": "@mychannel", "kind": "username"})

    def test_tme_link(self):
        self.assertEqual(core.parse_target("https://t.me/mychannel"),
                         {"ref": "@mychannel", "kind": "username"})

    def test_bad(self):
        with self.assertRaises(ValueError):
            core.parse_target("")
        with self.assertRaises(ValueError):
            core.parse_target("!!!")


if __name__ == "__main__":
    unittest.main(verbosity=2)
