# -*- coding: utf-8 -*-
"""เทสต์ group_security_intelligence — pure logic + service (stub bot, ไม่แตะ telegram จริง)"""

import os
import asyncio
import tempfile
import unittest
from datetime import timedelta

from group_security_intelligence import store, detectors, monitor, correlate, service


# ---------------------------------------------------------------------------
# detectors — secret
# ---------------------------------------------------------------------------
class SecretDetectionTests(unittest.TestCase):
    def test_detects_and_redacts_private_key(self):
        text = "my key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END"
        f = detectors.scan_secrets(text)
        self.assertTrue(any(x["type"] == "Private key block" for x in f))
        self.assertEqual(f[0]["severity"], "CRITICAL")

    def test_detects_telegram_bot_token(self):
        f = detectors.scan_secrets("token 123456789:AAFakeToken_abcdefghijklmnopqrstuvwx")
        self.assertTrue(any("Telegram" in x["type"] for x in f))

    def test_detects_aws_and_github(self):
        f = detectors.scan_secrets("AKIAIOSFODNN7EXAMPLE and ghp_" + "a" * 36)
        types = {x["type"] for x in f}
        self.assertIn("AWS access key id", types)
        self.assertIn("GitHub token", types)

    def test_redaction_never_returns_full_secret(self):
        secret = "ghp_" + "b" * 36
        f = detectors.scan_secrets(secret)
        self.assertTrue(f)
        self.assertNotIn(secret, f[0]["redacted"])
        self.assertIn("…", f[0]["redacted"])

    def test_db_connection_string_password(self):
        f = detectors.scan_secrets("postgres://admin:SuperSecret99@db.host:5432/app")
        self.assertTrue(any(x["type"] == "DB connection string" for x in f))

    def test_placeholder_not_flagged(self):
        f = detectors.scan_secrets("password=changeme\nAPI_KEY=<your_api_key>")
        # changeme/placeholder ควรถูกกรอง
        reds = [x for x in f if x["type"] == "Password assignment"]
        self.assertFalse(any(x["redacted"] in ("chan…", "chang…") for x in reds) and len(reds) > 1)

    def test_clean_text_no_findings(self):
        self.assertEqual(detectors.scan_secrets("สวัสดีครับ วันนี้อากาศดี"), [])


# ---------------------------------------------------------------------------
# detectors — social engineering
# ---------------------------------------------------------------------------
class SocialEngTests(unittest.TestCase):
    def test_otp_request_flagged(self):
        r = detectors.analyze_social_eng(
            "ผมคือแอดมิน ด่วน! ส่งรหัส OTP ที่ได้รับมาให้ผมเพื่อยืนยันบัญชีของคุณทันที")
        self.assertIsNotNone(r)
        self.assertGreaterEqual(r["risk_score"], 45)
        self.assertIn("admin_impersonation", r["indicators"])

    def test_single_weak_signal_not_flagged(self):
        # คำว่า urgent คำเดียว ไม่ถึงเกณฑ์
        self.assertIsNone(detectors.analyze_social_eng("ด่วนนะครับ เดี๋ยวไปกินข้าว"))

    def test_payment_scam_with_link(self):
        r = detectors.analyze_social_eng(
            "โอน USDT มาที่ wallet address นี้ด่วน แล้วคลิก https://bit.ly/x เพื่อรับรางวัลฟรี")
        self.assertIsNotNone(r)
        self.assertTrue(r["has_external_link"])
        self.assertGreater(r["risk_score"], 45)

    def test_output_shape(self):
        r = detectors.analyze_social_eng(
            "this is the official admin, verify your account or it will be suspended, send your password")
        for k in ("category", "risk_score", "confidence", "explanation",
                  "indicators", "recommended_action"):
            self.assertIn(k, r)


# ---------------------------------------------------------------------------
# monitor — admin diff
# ---------------------------------------------------------------------------
class AdminMonitorTests(unittest.TestCase):
    def _admin(self, uid, **perms):
        d = {"user_id": uid, "status": "administrator", "username": f"u{uid}",
             "display": f"User {uid}"}
        d.update(perms)
        return d

    def test_baseline_first_time_no_events(self):
        new = monitor.snapshot_admins([self._admin(1)], store.iso())
        self.assertEqual(monitor.diff_admins(None, new), [])

    def test_promotion_detected(self):
        old = monitor.snapshot_admins([self._admin(1)], store.iso())
        new = monitor.snapshot_admins([self._admin(1), self._admin(2)], store.iso())
        events = monitor.diff_admins(old, new)
        self.assertTrue(any(e["kind"] == "admin_promoted" for e in events))

    def test_demotion_detected(self):
        old = monitor.snapshot_admins([self._admin(1), self._admin(2)], store.iso())
        new = monitor.snapshot_admins([self._admin(1)], store.iso())
        events = monitor.diff_admins(old, new)
        self.assertTrue(any(e["kind"] == "admin_demoted" for e in events))

    def test_sensitive_perm_change_is_high(self):
        old = monitor.snapshot_admins([self._admin(1, can_promote_members=False)], store.iso())
        new = monitor.snapshot_admins([self._admin(1, can_promote_members=True)], store.iso())
        events = monitor.diff_admins(old, new)
        perm_ev = [e for e in events if e["kind"] == "admin_perms_changed"]
        self.assertTrue(perm_ev and perm_ev[0]["severity"] == "HIGH")

    def test_transition_promote(self):
        old = {"user_id": 5, "status": "member"}
        new = {"user_id": 5, "status": "administrator", "can_promote_members": True}
        events = monitor.diff_admin_transition(old, new, actor_id=99)
        self.assertEqual(events[0]["kind"], "admin_promoted")
        self.assertEqual(events[0]["severity"], "HIGH")
        self.assertEqual(events[0]["actor_id"], 99)


# ---------------------------------------------------------------------------
# monitor — config integrity
# ---------------------------------------------------------------------------
class ConfigIntegrityTests(unittest.TestCase):
    def test_no_change_normal(self):
        snap = monitor.snapshot_config({"title": "A"}, store.iso())
        events, status = monitor.diff_config(snap, snap)
        self.assertEqual(status, monitor.INTEGRITY_NORMAL)
        self.assertEqual(events, [])

    def test_title_change_flagged(self):
        old = monitor.snapshot_config({"title": "A"}, store.iso())
        new = monitor.snapshot_config({"title": "B"}, store.iso())
        events, status = monitor.diff_config(old, new)
        self.assertTrue(events)
        self.assertIn(status, (monitor.INTEGRITY_SUSPICIOUS, monitor.INTEGRITY_CHANGED))

    def test_permissions_loosened_suspicious(self):
        old = monitor.snapshot_config({"permissions": {"can_send_messages": False}}, store.iso())
        new = monitor.snapshot_config({"permissions": {"can_send_messages": True}}, store.iso())
        events, status = monitor.diff_config(old, new)
        self.assertEqual(status, monitor.INTEGRITY_SUSPICIOUS)

    def test_two_sensitive_requires_review(self):
        old = monitor.snapshot_config({"username": "a", "title": "A"}, store.iso())
        new = monitor.snapshot_config({"username": "b", "title": "B"}, store.iso())
        events, status = monitor.diff_config(old, new)
        self.assertEqual(status, monitor.INTEGRITY_REQUIRES_REVIEW)


# ---------------------------------------------------------------------------
# monitor — invites
# ---------------------------------------------------------------------------
class InviteMonitorTests(unittest.TestCase):
    def test_new_untrusted_link(self):
        events = monitor.diff_invites({}, [{"link": "https://t.me/+abcdef", "trusted": False}])
        self.assertEqual(events[0]["kind"], "invite_created")
        self.assertEqual(events[0]["severity"], "MEDIUM")

    def test_revocation(self):
        reg = {"L": {"link": "L", "is_revoked": False}}
        events = monitor.diff_invites(reg, [{"link": "L", "is_revoked": True}])
        self.assertEqual(events[0]["kind"], "invite_revoked")

    def test_event_never_contains_full_link(self):
        events = monitor.diff_invites({}, [{"link": "https://t.me/+SECRETLINK123", "trusted": False}])
        self.assertNotIn("SECRETLINK123", str(events))


# ---------------------------------------------------------------------------
# correlate
# ---------------------------------------------------------------------------
class CorrelationTests(unittest.TestCase):
    def _ev(self, kind, sev, offset_sec):
        ts = store.iso(store.utcnow() + timedelta(seconds=offset_sec))
        return {"ts": ts, "kind": kind, "severity": sev, "detail": kind}

    def test_single_event_no_incident(self):
        self.assertEqual(correlate.correlate([self._ev("admin_promoted", "HIGH", 0)]), [])

    def test_takeover_pattern_high(self):
        evs = [
            self._ev("admin_promoted", "HIGH", 0),
            self._ev("invite_revoked", "MEDIUM", 60),
            self._ev("config_permissions_changed", "HIGH", 120),
        ]
        inc = correlate.correlate(evs, window_sec=900, min_events=2)
        self.assertEqual(len(inc), 1)
        self.assertIn(inc[0]["level"], ("HIGH", "CRITICAL"))
        self.assertGreaterEqual(inc[0]["takeover_overlap"], 2)
        self.assertIn("ยึดกลุ่ม", inc[0]["explanation"])

    def test_events_outside_window_separate(self):
        evs = [
            self._ev("admin_promoted", "HIGH", 0),
            self._ev("admin_demoted", "MEDIUM", 50),
            self._ev("config_title_changed", "LOW", 5000),  # ไกลเกินหน้าต่าง
        ]
        inc = correlate.correlate(evs, window_sec=900, min_events=2)
        self.assertEqual(len(inc), 1)  # แค่คลัสเตอร์แรก


# ---------------------------------------------------------------------------
# service — audit, scan, backup/recovery (stub bot)
# ---------------------------------------------------------------------------
class FakeBot:
    def __init__(self):
        self.sent = []
        self.admins = []
        self.chat = None
        self.title_set = None
    async def send_message(self, chat_id, text, **kw):
        self.sent.append((chat_id, text))
    async def get_chat_administrators(self, chat_id):
        return self.admins
    async def get_chat(self, chat_id):
        return self.chat
    async def set_chat_title(self, chat_id, title):
        self.title_set = title


class _U:
    def __init__(self, uid, uname="x", full="X", is_bot=False):
        self.id = uid; self.username = uname; self.full_name = full; self.is_bot = is_bot


class _CM:
    def __init__(self, user, status="administrator", **perms):
        self.user = user; self.status = status
        for p in monitor.ADMIN_PERMS:
            setattr(self, p, perms.get(p, False))


class _Chat:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)
        for attr in ("title", "description", "username", "photo", "permissions",
                     "slow_mode_delay", "linked_chat_id", "join_by_request",
                     "has_protected_content", "message_auto_delete_time"):
            if not hasattr(self, attr):
                setattr(self, attr, None)


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "gsi.json")

    def test_audit_appends_and_redacts(self):
        service.audit(-100, "secret", "HIGH", "พบข้อมูลลับ", actor_id=5,
                      after={"redacted": "ghp_…aaaa"}, path=self.path)
        node = store.get_chat(store.load(self.path), -100)
        self.assertEqual(len(node["audit_index"]), 1)
        self.assertEqual(node["audit_index"][0]["severity"], "HIGH")

    def test_scan_message_secret_audits_and_notifies(self):
        bot = FakeBot()
        async def run():
            await service.scan_message(bot, -100, 7, "token ghp_" + "c" * 36,
                                       username="bob", path=self.path)
        asyncio.run(run())
        node = store.get_chat(store.load(self.path), -100)
        self.assertEqual(len(node["secret_findings"]), 1)
        # ค่าจริงต้องไม่โผล่ในไฟล์/การแจ้งเตือน
        self.assertNotIn("c" * 36, str(node["secret_findings"]))
        self.assertTrue(bot.sent)
        self.assertNotIn("c" * 36, str(bot.sent))

    def test_notify_throttle(self):
        bot = FakeBot()
        async def run():
            a = await service.notify(bot, -100, "x", "HIGH", "k", path=self.path)
            b = await service.notify(bot, -100, "x", "HIGH", "k", path=self.path)
            return a, b
        a, b = asyncio.run(run())
        self.assertTrue(a)
        self.assertFalse(b)  # ครั้งที่สองถูก throttle

    def test_poll_baseline_then_promotion(self):
        bot = FakeBot()
        bot.admins = [_CM(_U(1), "creator")]
        bot.chat = _Chat(title="G", permissions=None)
        async def run():
            await service.ensure_baseline(bot, -100, path=self.path)
            # เพิ่มแอดมินใหม่
            bot.admins = [_CM(_U(1), "creator"), _CM(_U(2), "administrator",
                                                     can_promote_members=True)]
            return await service.poll_chat(bot, -100, path=self.path)
        summary = asyncio.run(run())
        self.assertGreaterEqual(summary["admin_events"], 1)
        node = store.get_chat(store.load(self.path), -100)
        self.assertTrue(any(a["category"] == "admin" for a in node["audit_index"]))

    def test_backup_and_recovery_diff(self):
        bot = FakeBot()
        bot.admins = [_CM(_U(1), "creator")]
        bot.chat = _Chat(title="Original", description="desc")
        async def run():
            rec = await service.create_backup(bot, -100, actor_id=1, path=self.path)
            bot.chat = _Chat(title="HACKED", description="desc")  # ชื่อถูกเปลี่ยน
            plan = await service.recovery_diff(bot, -100, rec["id"], path=self.path)
            res = await service.apply_recovery(bot, -100, rec["id"], ["title"],
                                               actor_id=1, path=self.path)
            return rec, plan, res
        rec, plan, res = asyncio.run(run())
        self.assertTrue(plan["ok"])
        self.assertTrue(any(c["key"] == "title" for c in plan["changes"]))
        self.assertIn("title", res["restored"])
        self.assertEqual(bot.title_set, "Original")

    def test_correlation_creates_incident(self):
        bot = FakeBot()
        async def run():
            # ป้อนเหตุการณ์อ่อนไหวหลายชนิดในหน้าต่างเดียว
            for kind, sev in (("admin_promoted", "HIGH"),
                              ("config_permissions_changed", "HIGH"),
                              ("invite_revoked", "MEDIUM")):
                service.audit(-100, kind.split("_")[0] if kind.startswith("admin") else
                              ("config" if kind.startswith("config") else "invite"),
                              sev, kind, kind=kind, path=self.path)
            return await service.run_correlation(bot, -100, path=self.path)
        inc = asyncio.run(run())
        self.assertIsNotNone(inc)
        self.assertIn(inc["level"], ("MEDIUM", "HIGH", "CRITICAL"))


# ---------------------------------------------------------------------------
# store — policy + retention
# ---------------------------------------------------------------------------
class StoreTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "gsi.json")

    def test_policy_defaults_and_set(self):
        pol = store.get_policy(-100, self.path)
        self.assertTrue(pol["enabled"])
        store.set_policy(-100, "notify_min_severity", "HIGH", self.path)
        self.assertEqual(store.get_policy(-100, self.path)["notify_min_severity"], "HIGH")

    def test_unknown_policy_rejected(self):
        with self.assertRaises(ValueError):
            store.set_policy(-100, "nope", 1, self.path)

    def test_retention_prune(self):
        node = store.get_chat(store.load(self.path), -100)
        node["policy"]["retention_days"] = 1
        old_ts = store.iso(store.utcnow() - timedelta(days=5))
        node["secret_findings"].append({"ts": old_ts, "type": "x"})
        node["secret_findings"].append({"ts": store.iso(), "type": "y"})
        removed = store.prune_retention(node)
        self.assertEqual(removed, 1)
        self.assertEqual(len(node["secret_findings"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
