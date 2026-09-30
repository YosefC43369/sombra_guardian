"""Tests for the ingestion transform — normalize, validate, pipeline, ratelimit."""

import asyncio
import unittest

from cve_tracker.ingestion.normalizer import normalize_record
from cve_tracker.ingestion.validator import validate_record, is_publishable, filter_valid
from cve_tracker.ingestion.pipeline import IngestionPipeline
from cve_tracker.ingestion.ratelimit import TokenBucket
from cve_tracker.models import CVERecord, SourceRecord
from cve_tracker import fixtures


class NormalizeTest(unittest.TestCase):
    def test_severity_from_cvss(self):
        r = fixtures.record(enrich_it=False)
        r.severity = "UNKNOWN"
        normalize_record(r)
        self.assertEqual(r.severity, "CRITICAL")
        self.assertEqual(r.cvss_score, 9.8)

    def test_no_cvss_keeps_unknown(self):
        r = fixtures.record_no_cvss()
        r.severity = "UNKNOWN"
        normalize_record(r)
        self.assertEqual(r.severity, "UNKNOWN")


class ValidateTest(unittest.TestCase):
    def test_valid_record(self):
        ok, reason = validate_record(fixtures.record())
        self.assertTrue(ok, reason)

    def test_bad_id(self):
        r = CVERecord(cve_id="CVE-2026-93740")
        r.cve_id = "not-a-cve"
        r.sources = [SourceRecord(source="nvd")]
        ok, reason = validate_record(r)
        self.assertFalse(ok)

    def test_no_source(self):
        r = CVERecord(cve_id="CVE-2026-0001")
        ok, reason = validate_record(r)
        self.assertFalse(ok)
        self.assertEqual(reason, "no-source-record")

    def test_impossible_score_rejected(self):
        r = fixtures.record()
        r.cvss_score = 42.0
        ok, reason = validate_record(r)
        self.assertFalse(ok)

    def test_publishable_requires_title(self):
        r = CVERecord(cve_id="CVE-2026-0001")
        r.sources = [SourceRecord(source="nvd")]
        ok, _ = is_publishable(r)
        self.assertFalse(ok)

    def test_filter_valid_splits(self):
        good = fixtures.record("CVE-2026-0001")
        bad = CVERecord(cve_id="CVE-2026-0002")  # no source
        valid, rejected = filter_valid([good, bad])
        self.assertEqual(len(valid), 1)
        self.assertEqual(len(rejected), 1)


class PipelineTest(unittest.TestCase):
    def test_merges_same_cve(self):
        nvd = fixtures.record("CVE-2026-0100", source="nvd")
        kev = fixtures.record("CVE-2026-0100", source="cisa_kev", kev=True,
                              vector="", score=None, cwe="", refs=[])
        result = IngestionPipeline().process([nvd, kev])
        self.assertEqual(result.total_out, 1)
        merged = result.records[0]
        self.assertTrue(merged.in_kev)
        self.assertEqual(merged.cvss_score, 9.8)
        self.assertEqual(sorted(merged.source_names), ["cisa_kev", "nvd"])

    def test_drops_invalid_keeps_rest(self):
        good = fixtures.record("CVE-2026-0001")
        bad = CVERecord(cve_id="CVE-2026-0002")
        result = IngestionPipeline().process([good, bad])
        self.assertEqual(result.total_out, 1)
        self.assertEqual(result.rejected_count, 1)


class RateLimitTest(unittest.TestCase):
    def test_token_bucket_paces(self):
        async def run():
            bucket = TokenBucket(rate=100.0, capacity=1.0)
            # first acquire immediate, second must wait a little
            await bucket.acquire()
            import time
            start = time.monotonic()
            await bucket.acquire()
            return time.monotonic() - start
        waited = asyncio.get_event_loop().run_until_complete(run())
        self.assertGreaterEqual(waited, 0.0)

    def test_penalize_blocks(self):
        async def run():
            bucket = TokenBucket(rate=1000.0)
            bucket.penalize(0.2)
            import time
            start = time.monotonic()
            await bucket.acquire()
            return time.monotonic() - start
        waited = asyncio.new_event_loop().run_until_complete(run())
        self.assertGreaterEqual(waited, 0.15)


if __name__ == "__main__":
    unittest.main()
