# -*- coding: utf-8 -*-
"""เทสต์ส่วน pure logic ของ autolink (store + engine) — ไม่แตะ Telegram"""

import os
import tempfile
import unittest
from datetime import timedelta

from autolink import store, engine


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "autolink.json")

    def _links(self, *urls):
        return [engine.normalize_link(u) for u in urls]

    def test_create_and_load(self):
        c = store.create_campaign(
            -100, self._links("example.com", "github.com"), 1800,
            title="t", path=self.path)
        self.assertEqual(c["id"], 1)
        self.assertEqual(len(c["links"]), 2)
        self.assertTrue(c["links"][0]["url"].startswith("https://"))
        db = store.load(self.path)
        self.assertEqual(len(store.list_campaigns(db, -100)), 1)

    def test_ids_increment_and_delete(self):
        a = store.create_campaign(-100, self._links("a.com"), 60, path=self.path)
        b = store.create_campaign(-100, self._links("b.com"), 60, path=self.path)
        self.assertEqual((a["id"], b["id"]), (1, 2))
        self.assertTrue(store.delete_campaign(-100, 1, path=self.path))
        # id ไม่ reuse
        c = store.create_campaign(-100, self._links("c.com"), 60, path=self.path)
        self.assertEqual(c["id"], 3)
        self.assertFalse(store.delete_campaign(-100, 999, path=self.path))

    def test_min_interval_guard(self):
        with self.assertRaises(ValueError):
            store.create_campaign(-100, self._links("a.com"), 1, path=self.path)

    def test_mark_ran_persists(self):
        store.create_campaign(-100, self._links("a.com", "b.com"), 60, path=self.path)
        store.mark_ran(-100, 1, 1, path=self.path)
        c = store.get_campaign(store.load(self.path), -100, 1)
        self.assertEqual(c["runs"], 1)
        self.assertEqual(c["cursor"], 1)
        self.assertIsNotNone(c["last_run_iso"])

    def test_atomic_write_roundtrip_unicode(self):
        store.create_campaign(-100, self._links("a.com"), 60,
                              title="โปรโมทไทย", path=self.path)
        c = store.get_campaign(store.load(self.path), -100, 1)
        self.assertEqual(c["title"], "โปรโมทไทย")


class EngineDurationTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(engine.parse_duration("45s"), 45)
        self.assertEqual(engine.parse_duration("30m"), 1800)
        self.assertEqual(engine.parse_duration("2h"), 7200)
        self.assertEqual(engine.parse_duration("1d"), 86400)
        self.assertEqual(engine.parse_duration("90"), 90 * 60)  # เปล่า = นาที

    def test_parse_bad(self):
        for bad in ("", "abc", "10x", "-5m"):
            with self.assertRaises(ValueError):
                engine.parse_duration(bad)

    def test_format(self):
        self.assertEqual(engine.format_duration(0), "0s")
        self.assertEqual(engine.format_duration(90), "1m 30s")
        self.assertEqual(engine.format_duration(5400), "1h 30m")
        self.assertEqual(engine.format_duration(86400), "1d")


class EngineScheduleTests(unittest.TestCase):
    def _camp(self, **over):
        c = {
            "id": 1, "links": [{"url": "https://a.com", "label": ""},
                               {"url": "https://b.com", "label": ""}],
            "interval_sec": 60, "mode": "sequential", "cursor": 0,
            "enabled": True, "last_run_iso": None,
        }
        c.update(over)
        return c

    def test_due_first_time(self):
        self.assertTrue(engine.is_due(self._camp()))

    def test_not_due_when_disabled_or_empty(self):
        self.assertFalse(engine.is_due(self._camp(enabled=False)))
        self.assertFalse(engine.is_due(self._camp(links=[])))

    def test_due_respects_interval(self):
        now = store.utcnow()
        c = self._camp(last_run_iso=store.iso(now - timedelta(seconds=30)))
        self.assertFalse(engine.is_due(c, now))
        c2 = self._camp(last_run_iso=store.iso(now - timedelta(seconds=61)))
        self.assertTrue(engine.is_due(c2, now))

    def test_seconds_until_due(self):
        now = store.utcnow()
        c = self._camp(last_run_iso=store.iso(now - timedelta(seconds=20)))
        self.assertEqual(engine.seconds_until_due(c, now), 40)


class EngineChooseTests(unittest.TestCase):
    def _camp(self, mode, cursor=0):
        return {
            "links": [{"url": "https://a.com"}, {"url": "https://b.com"},
                      {"url": "https://c.com"}],
            "mode": mode, "cursor": cursor,
        }

    def test_sequential_rotation(self):
        c = self._camp("sequential", cursor=0)
        link, nxt = engine.choose(c)
        self.assertEqual(link["url"], "https://a.com")
        self.assertEqual(nxt, 1)
        c["cursor"] = nxt
        link, nxt = engine.choose(c)
        self.assertEqual(link["url"], "https://b.com")
        self.assertEqual(nxt, 2)
        c["cursor"] = 2
        link, nxt = engine.choose(c)
        self.assertEqual(link["url"], "https://c.com")
        self.assertEqual(nxt, 0)  # วนกลับ

    def test_single_mode_fixed(self):
        c = self._camp("single", cursor=2)
        link, nxt = engine.choose(c)
        self.assertEqual(link["url"], "https://a.com")
        self.assertEqual(nxt, 0)

    def test_random_in_range(self):
        import random
        c = self._camp("random")
        rng = random.Random(42)
        for _ in range(20):
            link, nxt = engine.choose(c, rng=rng)
            self.assertIn(nxt, (0, 1, 2))
            self.assertEqual(link["url"], c["links"][nxt]["url"])


class EngineRenderTests(unittest.TestCase):
    def test_default_render_uses_etld1_label(self):
        c = {"links": [{"url": "https://sub.example.com/x", "label": ""}],
             "template": "", "title": "T"}
        out = engine.render(c, c["links"][0], 0)
        # label ว่าง -> fallback เป็น eTLD+1 จาก urlkit
        self.assertIn("https://sub.example.com/x", out)
        self.assertIn("example.com", out)

    def test_template_vars(self):
        c = {"links": [{"url": "https://a.com", "label": "ไซต์เอ"},
                       {"url": "https://b.com", "label": ""}],
             "template": "{title} {n}/{total}: {label} -> {url}", "title": "แคมเปญ"}
        out = engine.render(c, c["links"][0], 0)
        self.assertEqual(out, "แคมเปญ 1/2: ไซต์เอ -> https://a.com")

    def test_broken_template_falls_back(self):
        c = {"links": [{"url": "https://a.com", "label": "L"}],
             "template": "{nope}", "title": "T"}
        out = engine.render(c, c["links"][0], 0)
        self.assertIn("https://a.com", out)  # ไม่ throw ส่งดีฟอลต์แทน


class NormalizeTests(unittest.TestCase):
    def test_adds_scheme(self):
        self.assertEqual(
            engine.normalize_link("example.com")["url"], "https://example.com")

    def test_keeps_scheme(self):
        self.assertEqual(
            engine.normalize_link("http://x.com")["url"], "http://x.com")

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            engine.normalize_link("")
        with self.assertRaises(ValueError):
            engine.normalize_link("not a url")


if __name__ == "__main__":
    unittest.main(verbosity=2)
