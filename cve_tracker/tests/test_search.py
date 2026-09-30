"""Tests for search — query parsing, ranking, and the service over a temp DB."""

import os
import tempfile
import unittest

from cve_tracker.search.query import parse
from cve_tracker.search.ranking import rank, score
from cve_tracker.search.service import SearchService
from cve_tracker.storage import CVERepository, migrations
from cve_tracker import fixtures


class QueryParseTest(unittest.TestCase):
    def test_bare_cve(self):
        q = parse("CVE-2026-93740")
        self.assertEqual(q.kind, "cve_id")
        self.assertEqual(q.cve_id, "CVE-2026-93740")

    def test_field_tokens(self):
        q = parse("severity:critical")
        self.assertEqual(q.severity, "CRITICAL")
        q = parse("cvss:9")
        self.assertEqual(q.min_cvss, 9.0)
        q = parse("vendor:microsoft")
        self.assertEqual(q.vendor, "microsoft")
        q = parse("cwe:CWE-79")
        self.assertEqual(q.cwe, "CWE-79")

    def test_keywords(self):
        self.assertTrue(parse("kev").kev_only)
        self.assertTrue(parse("recent").recent)
        self.assertEqual(parse("critical").severity, "CRITICAL")

    def test_free_text(self):
        q = parse("totolink buffer overflow")
        self.assertEqual(q.kind, "text")
        self.assertIn("totolink", q.text)

    def test_empty_is_recent(self):
        self.assertTrue(parse("").recent)


class RankingTest(unittest.TestCase):
    def test_exact_cve_ranks_first(self):
        target = fixtures.record("CVE-2026-0001")
        other = fixtures.record("CVE-2026-0002")
        q = parse("CVE-2026-0001")
        ranked = rank([other, target], q)
        self.assertEqual(ranked[0].cve_id, "CVE-2026-0001")

    def test_product_match_scores(self):
        r = fixtures.record("CVE-2026-0001", vendor="Apache", product="HTTP Server")
        q = parse("apache")
        self.assertGreater(score(r, q), 0)


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.db = tempfile.mktemp(suffix=".db")
        migrations.apply(self.db)
        self.repo = CVERepository(self.db)
        self.repo.save_record(fixtures.record("CVE-2026-0001", vendor="TOTOLINK", product="A3002MU"))
        self.repo.save_record(fixtures.record("CVE-2026-0002", vendor="Apache", product="HTTP Server",
                                              score=7.5,
                                              vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"))
        self.repo.save_record(fixtures.record("CVE-2026-0003", kev=True))
        self.svc = SearchService(self.repo)

    def tearDown(self):
        os.remove(self.db)

    def test_search_vendor(self):
        res = self.svc.search("apache")
        self.assertTrue(any(r.cve_id == "CVE-2026-0002" for r in res.records))

    def test_search_severity(self):
        res = self.svc.search("severity:critical")
        self.assertTrue(all(r.severity == "CRITICAL" for r in res.records))

    def test_search_kev(self):
        res = self.svc.search("kev")
        self.assertTrue(all(r.in_kev for r in res.records))

    def test_get_one(self):
        self.assertIsNotNone(self.svc.get_one("CVE-2026-0001"))
        self.assertIsNone(self.svc.get_one("CVE-2026-0999"))

    def test_pagination(self):
        for i in range(12):
            self.repo.save_record(fixtures.record(f"CVE-2026-0009{i:02d}"))
        res = self.svc.search("recent", page=1, page_size=5)
        self.assertEqual(len(res.page_items()), 5)
        self.assertTrue(res.has_next)
        res2 = self.svc.search("recent", page=2, page_size=5)
        self.assertTrue(res2.has_prev)


if __name__ == "__main__":
    unittest.main()
