import unittest

from web_footprint import WebFootprintEngine, ReconContext, ScopeSpec, ReconMode
from web_footprint.blue import BlueTeamMonitor, AlertKind
from web_footprint import history
from ._fakes import (run_async, FakeCollector, cert_collector, page_collector,
                     repo_collector)


def _ctx():
    return ReconContext(scope=ScopeSpec(include=["*.example.com", "example.com"]),
                        dev_unsafe_allow_all=True, actor="tester")


def _engine(collectors):
    return WebFootprintEngine(collectors)


class TestBlueTeam(unittest.TestCase):
    def test_defensive_inventory(self):
        engine = _engine([cert_collector(), page_collector(), repo_collector()])
        res = run_async(engine.recon("example.com", _ctx(), mode=ReconMode.STANDARD))
        inv = BlueTeamMonitor.defensive_inventory(res)
        self.assertIn("known_subdomains", inv)
        self.assertTrue(inv["known_subdomains"])
        self.assertIn("exampleinc/webapp", inv["known_repositories"])

    def test_compare_raises_new_asset_alert(self):
        engine = _engine([cert_collector()])
        # baseline: only api.example.com
        base_collector = FakeCollector("crtsh", "certificates", [
            {"type": "subdomain", "value": "api.example.com", "source": "crtsh"}])
        prev_res = run_async(_engine([base_collector]).recon(
            "example.com", _ctx(), mode=ReconMode.QUICK))
        prev_snapshot = history.snapshot(prev_res.inventory)
        # current run discovers admin.example.com + www.example.com too
        cur_res = run_async(engine.recon("example.com", _ctx(), mode=ReconMode.QUICK))
        alerts = BlueTeamMonitor.compare(cur_res, prev_snapshot)
        kinds = {a.kind for a in alerts}
        self.assertIn(AlertKind.NEW_PUBLIC_ASSET, kinds)
        new_subjects = {a.subject for a in alerts if a.kind is AlertKind.NEW_PUBLIC_ASSET}
        self.assertIn("admin.example.com", new_subjects)

    def test_compare_no_baseline_is_empty(self):
        engine = _engine([cert_collector()])
        res = run_async(engine.recon("example.com", _ctx(), mode=ReconMode.QUICK))
        self.assertEqual(BlueTeamMonitor.compare(res, None), [])

    def test_brand_monitor_lookalike(self):
        alerts = BlueTeamMonitor.brand_monitor(
            "example.com",
            ["examp1e.com", "example.com", "totallyunrelated.org", "example-support.com"])
        subjects = {a.subject for a in alerts}
        self.assertIn("examp1e.com", subjects)        # 1 char off
        self.assertIn("example-support.com", subjects)  # embeds brand
        self.assertNotIn("example.com", subjects)      # the real domain excluded
        self.assertNotIn("totallyunrelated.org", subjects)
        for a in alerts:
            self.assertIs(a.kind, AlertKind.POTENTIAL_IMPERSONATION)

    def test_ioc_handoff_not_prejudged(self):
        engine = _engine([cert_collector(), page_collector()])
        res = run_async(engine.recon("example.com", _ctx(), mode=ReconMode.STANDARD))
        handoff = BlueTeamMonitor.ioc_handoff(res)
        self.assertIn("domains", handoff)
        self.assertIn("not pre-classified as malicious", handoff["note"])

    def test_posture_signals_no_rating(self):
        engine = _engine([page_collector()])
        res = run_async(engine.recon("example.com", _ctx(), mode=ReconMode.STANDARD))
        posture = BlueTeamMonitor.posture_signals(res)
        self.assertIn("not converted to a security rating", posture["note"])


if __name__ == "__main__":
    unittest.main()
