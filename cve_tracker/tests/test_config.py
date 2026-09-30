"""Tests for config resolution and the fetcher's retry/backoff/size guards."""

import asyncio
import os
import unittest

from cve_tracker.config import get_config, severities_at_or_above
from cve_tracker.ingestion.fetcher import HttpFetcher, _parse_retry_after
from cve_tracker.errors import HTTPStatusError, RateLimitedError


class ConfigTest(unittest.TestCase):
    def test_defaults(self):
        c = get_config()
        self.assertFalse(c.enabled)  # dormant by default
        self.assertIn("nvd", c.sources)
        self.assertIn("epss", c.sources)
        self.assertGreaterEqual(c.poll_interval, 30)

    def test_env_override(self):
        os.environ["CVE_POLL_INTERVAL"] = "120"
        os.environ["CVE_ALERT_MIN_SEVERITY"] = "HIGH"
        try:
            c = get_config()
            self.assertEqual(c.poll_interval, 120)
            self.assertEqual(c.alerts.min_severity, "HIGH")
        finally:
            del os.environ["CVE_POLL_INTERVAL"]
            del os.environ["CVE_ALERT_MIN_SEVERITY"]

    def test_poll_interval_floor(self):
        os.environ["CVE_POLL_INTERVAL"] = "5"
        try:
            self.assertEqual(get_config().poll_interval, 30)  # clamped up
        finally:
            del os.environ["CVE_POLL_INTERVAL"]

    def test_response_bytes_capped(self):
        from cve_tracker.constants import ABSOLUTE_MAX_RESPONSE_BYTES
        os.environ["CVE_MAX_RESPONSE_BYTES"] = str(ABSOLUTE_MAX_RESPONSE_BYTES * 2)
        try:
            self.assertLessEqual(get_config().max_response_bytes, ABSOLUTE_MAX_RESPONSE_BYTES)
        finally:
            del os.environ["CVE_MAX_RESPONSE_BYTES"]

    def test_severities_at_or_above(self):
        self.assertEqual(severities_at_or_above("HIGH"), ["HIGH", "CRITICAL"])
        self.assertEqual(severities_at_or_above("MEDIUM"), ["MEDIUM", "HIGH", "CRITICAL"])


class HTTPStatusErrorTest(unittest.TestCase):
    def test_retryable_by_status(self):
        self.assertTrue(HTTPStatusError(503).retryable)
        self.assertFalse(HTTPStatusError(404).retryable)
        self.assertTrue(RateLimitedError(source="x", retry_after=5).retryable)

    def test_retry_after_parse(self):
        self.assertEqual(_parse_retry_after("30"), 30.0)
        self.assertIsNone(_parse_retry_after(None))


class IntegrationHelperTest(unittest.TestCase):
    def test_register_cve_tracker(self):
        import cve_tracker
        # public entry point is importable (was a lazy __getattr__ target)
        self.assertTrue(callable(cve_tracker.register_cve_tracker))

        class _FakeApp:
            def __init__(self):
                self.handlers = []
                self.bot_data = {}
                self.bot = object()
            def add_handler(self, h):
                self.handlers.append(h)

        app = _FakeApp()
        names = cve_tracker.register_cve_tracker(
            app, is_admin=lambda *a, **k: True, start_loop=False)
        # every /cve* command registered (telegram present in this env or not,
        # the function is import-safe; when telegram is absent it returns []).
        self.assertIsInstance(names, list)


class FetcherBackoffTest(unittest.TestCase):
    def test_backoff_bounded(self):
        f = HttpFetcher(user_agent="t", retry_base_delay=2.0, retry_max_delay=10.0)
        for attempt in range(1, 8):
            delay = f._backoff(attempt)
            self.assertGreaterEqual(delay, 0.0)
            self.assertLessEqual(delay, 10.0)  # never exceeds the ceiling


if __name__ == "__main__":
    unittest.main()
