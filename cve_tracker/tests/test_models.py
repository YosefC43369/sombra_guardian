"""Tests for the normalized models — roundtrip, properties, id normalization."""

import unittest

from cve_tracker.models import CVERecord, CVSSScore, Reference, KEVInfo, Subscription, Notification
from cve_tracker import fixtures
from cve_tracker.utils import normalize_cve_id, normalize_cwe_id, extract_cve_ids


class IdNormalizationTest(unittest.TestCase):
    def test_cve_id_forms(self):
        self.assertEqual(normalize_cve_id("cve 2026-93740"), "CVE-2026-93740")
        self.assertEqual(normalize_cve_id("  CVE-2026-93740 "), "CVE-2026-93740")
        self.assertIsNone(normalize_cve_id("2026-93740"))
        self.assertIsNone(normalize_cve_id("CVE-99-1"))

    def test_cwe_id_forms(self):
        self.assertEqual(normalize_cwe_id("79"), "CWE-79")
        self.assertEqual(normalize_cwe_id("CWE-0079"), "CWE-79")
        self.assertEqual(normalize_cwe_id("cwe79"), "CWE-79")

    def test_extract_ids_dedup(self):
        ids = extract_cve_ids("see CVE-2026-0001 and CVE-2026-0001 and CVE-2025-0099")
        self.assertEqual(ids, ["CVE-2026-0001", "CVE-2025-0099"])


class RecordTest(unittest.TestCase):
    def test_roundtrip(self):
        r = fixtures.record(kev=True)
        d = r.to_dict()
        r2 = CVERecord.from_dict(d)
        self.assertEqual(r2.cve_id, r.cve_id)
        self.assertEqual(r2.cvss_score, r.cvss_score)
        self.assertEqual(r2.in_kev, True)
        self.assertEqual(r2.cwe_ids, r.cwe_ids)
        self.assertEqual(len(r2.references), len(r.references))

    def test_post_init_normalizes_id(self):
        r = CVERecord(cve_id="cve-2026-0005")
        self.assertEqual(r.cve_id, "CVE-2026-0005")

    def test_properties(self):
        r = fixtures.record(kev=True)
        self.assertIn("TOTOLINK", r.vendors)
        self.assertIn("CWE-121", r.cwe_ids)
        self.assertTrue(r.is_critical)
        self.assertTrue(r.in_kev)
        self.assertTrue(r.primary_url)

    def test_primary_url_fallback(self):
        r = CVERecord(cve_id="CVE-2026-0009")
        self.assertIn("CVE-2026-0009", r.primary_url)


class SubNotifTest(unittest.TestCase):
    def test_subscription_roundtrip(self):
        s = Subscription(chat_id=-100, vendors=["microsoft"], min_cvss=8.0)
        s2 = Subscription.from_dict(s.to_dict())
        self.assertEqual(s2.chat_id, -100)
        self.assertEqual(s2.vendors, ["microsoft"])

    def test_notification_dedupe_key(self):
        n1 = Notification(cve_id="CVE-2026-0001", chat_id=5, is_update=False)
        n2 = Notification(cve_id="CVE-2026-0001", chat_id=5, is_update=True)
        self.assertNotEqual(n1.dedupe_key, n2.dedupe_key)
        n3 = Notification(cve_id="CVE-2026-0001", chat_id=5, is_update=False)
        self.assertEqual(n1.dedupe_key, n3.dedupe_key)


if __name__ == "__main__":
    unittest.main()
