import unittest

from geo_osint import GeoOSINTEngine, GeoConfig, GeoMode
from geo_osint.integration import (import_web_footprint_targets,
                                   to_entity_fusion_evidence,
                                   to_behavioral_timeline, shared_geography_signal)


class TestWebFootprintImport(unittest.TestCase):
    def test_extract_targets_from_dicts(self):
        inv = [{"asset_type": "domain", "value": "example.com"},
               {"asset_type": "ip", "value": "8.8.8.8"},
               {"asset_type": "email", "value": "a@b.com"},         # skipped
               {"asset_type": "domain", "value": "example.com"}]    # dedup
        targets = import_web_footprint_targets(inv)
        self.assertEqual(targets, ["example.com", "8.8.8.8"])

    def test_duck_typed_objects(self):
        class A:
            def __init__(self, t, v):
                self.asset_type, self.value = t, v
        targets = import_web_footprint_targets([A("subdomain", "api.example.com"),
                                               A("certificate", "x")])
        self.assertEqual(targets, ["api.example.com"])


class TestEntityFusionExport(unittest.TestCase):
    def setUp(self):
        self.e = GeoOSINTEngine(GeoConfig.build(GeoMode.LOCAL))

    def test_evidence_records_merge_safe_false(self):
        r = self.e.investigate_sync("Bangkok")
        recs = to_entity_fusion_evidence(r)
        self.assertTrue(recs)
        self.assertTrue(all(rec["merge_safe"] is False for rec in recs))

    def test_shared_geography_never_merges(self):
        a = self.e.investigate_sync("Bangkok")
        b = self.e.investigate_sync("Bangkok")
        sig = shared_geography_signal(a, b)
        self.assertFalse(sig["merge_safe"])


class TestBehavioralExport(unittest.TestCase):
    def test_timeline_has_no_inference_note(self):
        e = GeoOSINTEngine(GeoConfig.build(GeoMode.LOCAL))
        tl = to_behavioral_timeline(e.investigate_sync("Bangkok"))
        self.assertIn("no behavioural inference", tl["note"].lower())


if __name__ == "__main__":
    unittest.main()
