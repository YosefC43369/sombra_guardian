import unittest

from web_footprint.assets import (Asset, AssetType, AttackSurfaceInventory,
                                   Evidence, SignalState)
from web_footprint import history


def _inv(names, tech=None):
    inv = AttackSurfaceInventory("example.com")
    for nm in names:
        a = inv.upsert(AssetType.SUBDOMAIN, nm, evidence=Evidence(source="crtsh"))
        if tech and nm in tech:
            a.add_technology({"name": tech[nm]})
    return inv


class TestHistory(unittest.TestCase):
    def test_snapshot_and_diff(self):
        prev = history.snapshot(_inv(["api.example.com", "old.example.com"]))
        cur = history.snapshot(_inv(["api.example.com", "new.example.com"]))
        changes = history.diff_snapshots(cur, prev)
        summary = history.summarize_changes(changes)
        self.assertEqual(summary.get("added"), 1)
        self.assertEqual(summary.get("removed"), 1)
        self.assertEqual(summary.get("unchanged"), 1)
        removed = [c for c in changes if c.kind is history.ChangeKind.REMOVED][0]
        self.assertIn("not confirmed deleted", removed.detail)

    def test_changed_on_tech(self):
        prev = history.snapshot(_inv(["api.example.com"], tech={}))
        cur = history.snapshot(_inv(["api.example.com"], tech={"api.example.com": "nginx"}))
        changes = history.diff_snapshots(cur, prev)
        changed = [c for c in changes if c.kind is history.ChangeKind.CHANGED]
        self.assertEqual(len(changed), 1)
        self.assertIn("tech added", changed[0].detail)

    def test_reappeared(self):
        prev = history.snapshot(_inv(["api.example.com"]))
        cur = history.snapshot(_inv(["api.example.com", "back.example.com"]))
        earlier = {"subdomain::back.example.com"}
        changes = history.diff_snapshots(cur, prev, earlier_keys=earlier)
        kinds = {c.value: c.kind for c in changes}
        self.assertEqual(kinds["back.example.com"], history.ChangeKind.REAPPEARED)

    def test_technology_timeline(self):
        inv = _inv(["api.example.com", "www.example.com"],
                   tech={"api.example.com": "nginx", "www.example.com": "nginx"})
        tl = history.technology_timeline(inv)
        nginx = [t for t in tl if t["technology"] == "nginx"][0]
        self.assertEqual(nginx["asset_count"], 2)


if __name__ == "__main__":
    unittest.main()
