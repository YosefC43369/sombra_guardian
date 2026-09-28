import unittest

from web_footprint.assets import (Asset, AssetType, AttackSurfaceInventory,
                                   Evidence, SignalState, ScopeStatus, DomainClass)


class TestAssets(unittest.TestCase):
    def test_key_and_confidence(self):
        a = Asset(AssetType.SUBDOMAIN, "API.example.com")
        self.assertEqual(a.key, "subdomain::api.example.com")
        self.assertEqual(a.confidence, 0.0)
        a.add_evidence(Evidence(source="crtsh", detail="ct"))
        c1 = a.confidence
        self.assertGreater(c1, 0.0)
        a.add_evidence(Evidence(source="passive_dns", detail="dns"))
        self.assertGreaterEqual(a.confidence, c1)  # corroboration never lowers
        self.assertIn(a.confidence_band, ("tentative", "low", "medium", "high"))

    def test_merge_preserves_provenance(self):
        a = Asset(AssetType.SUBDOMAIN, "api.example.com",
                  signal_state=SignalState.UNVERIFIED)
        a.add_evidence(Evidence(source="crtsh"))
        b = Asset(AssetType.SUBDOMAIN, "api.example.com",
                  signal_state=SignalState.LIVE_SIGNAL, subdomain_role="api")
        b.add_evidence(Evidence(source="wayback"))
        a.merge(b)
        self.assertEqual(set(a.sources), {"crtsh", "wayback"})
        self.assertEqual(a.signal_state, SignalState.LIVE_SIGNAL)  # promoted
        self.assertEqual(a.subdomain_role, "api")

    def test_add_technology_dedup(self):
        a = Asset(AssetType.WEBSITE, "https://example.com/")
        a.add_technology({"name": "nginx"})
        a.add_technology({"name": "nginx", "version": "1.18.0"})
        self.assertEqual(len(a.technologies), 1)
        self.assertEqual(a.technologies[0]["version"], "1.18.0")

    def test_inventory_dedup_and_counts(self):
        inv = AttackSurfaceInventory("example.com")
        inv.upsert(AssetType.SUBDOMAIN, "api.example.com",
                   evidence=Evidence(source="crtsh"))
        inv.upsert(AssetType.SUBDOMAIN, "API.example.com",
                   evidence=Evidence(source="wayback"))  # same key, merges
        inv.upsert(AssetType.DOMAIN, "example.com", evidence=Evidence(source="crtsh"),
                   domain_class=DomainClass.PRIMARY)
        self.assertEqual(len(inv), 2)
        got = inv.get(AssetType.SUBDOMAIN, "api.example.com")
        self.assertEqual(set(got.sources), {"crtsh", "wayback"})
        self.assertEqual(inv.counts_by_type()["subdomain"], 1)
        self.assertEqual(len(inv.of_type(AssetType.DOMAIN)), 1)

    def test_upsert_empty_value(self):
        inv = AttackSurfaceInventory()
        self.assertIsNone(inv.upsert(AssetType.SUBDOMAIN, ""))

    def test_to_dict_roundtrip_shape(self):
        a = Asset(AssetType.CERTIFICATE, "serial-1",
                  attributes={"sans": ["a.example.com"]})
        a.add_evidence(Evidence(source="crtsh"))
        d = a.to_dict()
        self.assertEqual(d["asset_type"], "certificate")
        self.assertIn("confidence", d)
        self.assertIn("evidence", d)
        self.assertEqual(d["attributes"]["sans"], ["a.example.com"])


if __name__ == "__main__":
    unittest.main()
