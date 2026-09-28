import unittest

from web_footprint.assets import (Asset, AssetType, AttackSurfaceInventory,
                                   Evidence, SignalState)
from web_footprint.analysis import exposure


def _inv():
    inv = AttackSurfaceInventory("example.com")
    a = inv.upsert(AssetType.SUBDOMAIN, "api.example.com", evidence=Evidence(source="crtsh"))
    a.add_technology({"name": "nginx", "version": "1.18.0"})
    inv.upsert(AssetType.PUBLIC_FILE, "https://example.com/x.pdf",
               evidence=Evidence(source="wayback"), signal_state=SignalState.ARCHIVED)
    inv.upsert(AssetType.REPOSITORY, "org/repo", evidence=Evidence(source="github"))
    inv.upsert(AssetType.CERTIFICATE, "serial-1", evidence=Evidence(source="crtsh"))
    inv.upsert(AssetType.EMAIL, "a@example.com", evidence=Evidence(source="html"))
    return inv


class TestExposure(unittest.TestCase):
    def test_classify_categories(self):
        signals = exposure.classify_exposure(_inv(), [
            {"type": "secret_signal", "kind": "aws", "redacted": "AKIA****", "source": "html"},
            {"type": "internal_naming_signal", "value": "db.internal", "source": "html"},
        ])
        cats = {s.category.value for s in signals}
        self.assertIn("domain_exposure", cats)
        self.assertIn("technology_exposure", cats)
        self.assertIn("repository_exposure", cats)
        self.assertIn("historical_exposure", cats)   # the archived pdf
        self.assertIn("public_identifier_exposure", cats)  # email + secret
        self.assertIn("metadata_exposure", cats)      # internal naming

    def test_observed_public_surface_metrics(self):
        surf = exposure.observed_public_surface(_inv())
        self.assertEqual(surf["subdomains"], 1)
        self.assertEqual(surf["repositories"], 1)
        self.assertEqual(surf["certificates"], 1)
        self.assertEqual(surf["technologies"], 1)
        self.assertEqual(surf["emails"], 1)
        self.assertGreaterEqual(surf["historical_assets"], 1)
        # No grade / score field — metrics only.
        self.assertNotIn("maturity", surf)
        self.assertNotIn("grade", surf)

    def test_summarize(self):
        signals = exposure.classify_exposure(_inv(), [])
        summary = exposure.summarize_exposure(signals)
        self.assertTrue(sum(summary.values()) >= len(list(_inv())))


if __name__ == "__main__":
    unittest.main()
