import unittest
import json

from web_footprint import WebFootprintEngine, ReconContext, ScopeSpec, ReconMode
from web_footprint.reports import red_team, json_report
from ._fakes import run_async, cert_collector, page_collector, repo_collector


def _ctx():
    return ReconContext(scope=ScopeSpec(include=["*.example.com", "example.com"]),
                        dev_unsafe_allow_all=True, actor="tester")


class TestReports(unittest.TestCase):
    def setUp(self):
        engine = WebFootprintEngine([cert_collector(), page_collector(), repo_collector()])
        self.res = run_async(engine.recon("example.com", _ctx(), mode=ReconMode.STANDARD))

    def test_red_team_22_sections(self):
        md = red_team.render(self.res)
        sections = [l for l in md.splitlines() if l.startswith("## ")]
        self.assertEqual(len(sections), 22)
        self.assertIn("## 1. Target", md)
        self.assertIn("## 22. Limitations", md)
        self.assertIn("Passive only", md)  # limitations state passivity
        self.assertIn("naming signal", md.lower())  # naming≠exposure caveat

    def test_denied_gate_report_short(self):
        engine = WebFootprintEngine([cert_collector()])
        denied = run_async(engine.recon("example.com", ReconContext(program_id=None)))
        md = red_team.render(denied)
        self.assertIn("not authorized", md.lower())
        # Should not render the full inventory sections when denied.
        self.assertNotIn("## 5. Subdomain Inventory", md)

    def test_json_report_roundtrip(self):
        blob = json_report.render(self.res)
        data = json.loads(blob)
        self.assertIn("stats", data)
        self.assertIn("inventory", data)
        self.assertIn("graph", data)
        self.assertEqual(data["stats"]["base_domain"], "example.com")


if __name__ == "__main__":
    unittest.main()
