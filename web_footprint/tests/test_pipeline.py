import unittest

from web_footprint import ReconContext, ScopeSpec, ReconMode, ReconConfig
from web_footprint.assets import AssetType, ScopeStatus
from web_footprint.pipeline import ReconPipeline
from web_footprint.collectors.base import Collector, CollectorStatus
from ._fakes import (run_async, FakeCollector, cert_collector, dns_collector,
                     page_collector, archive_collector, repo_collector)


def _ctx(**kw):
    kw.setdefault("scope", ScopeSpec(include=["*.example.com", "example.com"]))
    kw.setdefault("dev_unsafe_allow_all", True)
    kw.setdefault("actor", "tester")
    return ReconContext(**kw)


def _all_collectors():
    return [cert_collector(), dns_collector(), page_collector(),
            archive_collector(), repo_collector()]


class TestPipeline(unittest.TestCase):
    def test_full_offline_run(self):
        pipe = ReconPipeline(_all_collectors())
        res = run_async(pipe.run("example.com", _ctx(),
                                 config=ReconConfig(mode=ReconMode.STANDARD)))
        self.assertTrue(res.gate.allowed)
        types = res.inventory.counts_by_type()
        self.assertIn("subdomain", types)
        self.assertIn("certificate", types)
        self.assertIn("website", types)
        self.assertIn("repository", types)
        # tech fingerprint attached to the fetched page
        techs = {t["name"] for a in res.inventory for t in a.technologies}
        self.assertTrue({"nginx", "PHP", "WordPress", "jQuery"} & techs)
        # graph built
        self.assertGreater(res.graph.node_count, 0)
        self.assertGreater(res.graph.edge_count, 0)
        # relevance present, note is non-vuln
        self.assertIn("NOT vulnerability", res.relevance["note"])

    def test_gate_denied_blocks_collection(self):
        pipe = ReconPipeline(_all_collectors())
        # No program, no dev override -> fail closed, no collectors run.
        res = run_async(pipe.run("example.com", ReconContext(program_id=None)))
        self.assertFalse(res.gate.allowed)
        self.assertEqual(len(res.inventory), 0)
        self.assertEqual(len(res.collector_results), 0)

    def test_scope_tagging(self):
        # www.other.com appears via a fake, must be tagged not-in-scope.
        extra = FakeCollector("crtsh", "certificates", [
            {"type": "subdomain", "value": "api.example.com", "source": "crtsh"},
            {"type": "subdomain", "value": "api.other.com", "source": "crtsh"},
        ])
        pipe = ReconPipeline([extra])
        res = run_async(pipe.run("example.com", _ctx(
            scope=ScopeSpec(include=["*.example.com"])),
            config=ReconConfig(mode=ReconMode.QUICK)))
        a_in = res.inventory.get(AssetType.SUBDOMAIN, "api.example.com")
        a_out = res.inventory.get(AssetType.SUBDOMAIN, "api.other.com")
        self.assertEqual(a_in.scope, ScopeStatus.IN_SCOPE)
        self.assertEqual(a_out.scope, ScopeStatus.UNKNOWN)  # not excluded, not included

    def test_subdomain_cap_enforced(self):
        many = [{"type": "subdomain", "value": f"h{i}.example.com", "source": "crtsh"}
                for i in range(50)]
        pipe = ReconPipeline([FakeCollector("crtsh", "certificates", many)])
        cfg = ReconConfig(mode=ReconMode.QUICK)
        object.__setattr__(cfg.limits, "max_subdomains", 5)
        res = run_async(pipe.run("example.com", _ctx(), config=cfg))
        self.assertLessEqual(len(res.inventory.of_type(AssetType.SUBDOMAIN)), 5)

    def test_request_budget_tracked(self):
        pipe = ReconPipeline([cert_collector(), page_collector()])
        res = run_async(pipe.run("example.com", _ctx(),
                                 config=ReconConfig(mode=ReconMode.QUICK)))
        # cert(1) + page(2) = 3 requests recorded
        self.assertEqual(res.requests_made, 3)

    def test_quick_mode_skips_dns_and_archive(self):
        # In QUICK mode, passive_dns and archive stages are disabled, so those
        # collectors never run even when provided.
        pipe = ReconPipeline([dns_collector(), archive_collector()])
        res = run_async(pipe.run("example.com", _ctx(),
                                 config=ReconConfig(mode=ReconMode.QUICK)))
        self.assertEqual(len(res.collector_results), 0)

    def test_secret_signal_never_leaks_raw(self):
        pipe = ReconPipeline([page_collector()])
        res = run_async(pipe.run("example.com", _ctx(),
                                 config=ReconConfig(mode=ReconMode.STANDARD)))
        secrets = [s for s in res.extra_signals if s.get("type") == "secret_signal"]
        self.assertTrue(secrets)
        for s in secrets:
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", str(s))


if __name__ == "__main__":
    unittest.main()
