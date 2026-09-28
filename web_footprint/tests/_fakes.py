"""Shared fake collectors and helpers for the offline test suite.

The pipeline takes injectable collectors; these fakes return canned
``CollectorResult`` records so the whole engine is exercised end-to-end without a
network, httpx, or scope_policy state. They mirror the real collectors' record
shapes so ingestion is tested against the same contract the network collectors
emit.
"""

from __future__ import annotations

import asyncio
from typing import Any, List

from ..collectors.base import Collector, CollectorResult, CollectorStatus


def run_async(coro):
    return asyncio.run(coro)


class FakeCollector(Collector):
    """A collector that returns a fixed record list for any target."""

    def __init__(self, name: str, stage: str, records: List[dict], *,
                 status: CollectorStatus = None, requests: int = 1) -> None:
        self.name = name
        self.stage = stage
        self._records = records
        self._status = status
        self._requests = requests

    async def fetch(self, client, target: str, limits: Any = None) -> CollectorResult:
        recs = [dict(r) for r in self._records]
        if self._status is not None:
            res = CollectorResult(self.name, target, self._status, records=recs)
        else:
            res = self._ok(target, recs)
        res.requests_made = self._requests
        return res


def cert_collector(target: str = "example.com") -> FakeCollector:
    return FakeCollector("crtsh", "certificates", [
        {"type": "subdomain", "value": f"api.{target}", "source": "crtsh",
         "signal_state": "historical"},
        {"type": "subdomain", "value": f"admin.{target}", "source": "crtsh"},
        {"type": "subdomain", "value": f"www.{target}", "source": "crtsh"},
        {"type": "certificate", "value": "serial-1", "issuer": "Let's Encrypt",
         "not_before": "2024-01-01", "not_after": "2024-04-01",
         "sans": [f"api.{target}", f"www.{target}"], "source": "crtsh"},
    ])


def dns_collector(target: str = "example.com") -> FakeCollector:
    return FakeCollector("passive_dns", "passive_dns", [
        {"type": "dns_record", "rr_type": "A", "host": f"api.{target}",
         "value": "93.184.216.34", "source": "passive_dns"},
        {"type": "ip", "value": "93.184.216.34", "host": f"api.{target}",
         "source": "passive_dns"},
        {"type": "related_host", "value": "ns1.hostingco.net", "host": target,
         "rr_type": "NS", "source": "passive_dns"},
    ])


def page_collector(target: str = "example.com") -> FakeCollector:
    body = (
        '<html><head><title>Example Inc</title>'
        '<meta name="generator" content="WordPress 6.2"></head><body>'
        '<script src="https://cdn.example.com/jquery-3.6.0.min.js"></script>'
        f' email us at security@{target} or visit https://api.{target}/api/v1/users '
        ' our storage is assets.s3.amazonaws.com and staging-internal.corp is internal '
        ' aws_key = AKIAIOSFODNN7EXAMPLE '
        ' see our program at https://hackerone.com/exampleinc'
        '</body></html>'
    )
    return FakeCollector("wellknown", "wellknown", [
        {"type": "page", "value": f"https://{target}/", "source": "wellknown",
         "status": 200, "title": "Example Inc", "host": target,
         "headers": {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3",
                     "Strict-Transport-Security": "max-age=63072000",
                     "Content-Security-Policy": "default-src 'self'"},
         "body": body},
        {"type": "wellknown_file", "name": "security.txt",
         "value": f"https://{target}/.well-known/security.txt", "source": "wellknown",
         "text": f"Contact: mailto:security@{target}\nExpires: 2025-12-31T23:59:59Z\n"
                 f"Policy: https://{target}/security-policy"},
    ], requests=2)


def archive_collector(target: str = "example.com") -> FakeCollector:
    return FakeCollector("wayback", "archive", [
        {"type": "subdomain", "value": f"old.{target}", "source": "wayback",
         "signal_state": "archived", "first_timestamp": "20180101000000"},
        {"type": "historical_url", "value": f"https://{target}/old-page",
         "source": "wayback", "timestamp": "20180101000000", "mimetype": "text/html"},
        {"type": "document", "value": f"https://{target}/report.pdf",
         "source": "wayback", "ext": "pdf", "timestamp": "20190101000000",
         "signal_state": "archived"},
    ])


def repo_collector(target: str = "example.com") -> FakeCollector:
    return FakeCollector("github_repos", "repositories", [
        {"type": "repository", "value": "exampleinc/webapp", "source": "github",
         "url": "https://github.com/exampleinc/webapp", "description": "example.com app",
         "stars": 42, "language": "Python", "relevant": True,
         "homepage": f"https://{target}"},
    ])
