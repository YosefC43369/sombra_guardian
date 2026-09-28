import asyncio
import json
import unittest

from geo_osint import (GeoOSINTEngine, GeoPipeline, GeoOrchestrator,
                      GeoConfig, GeoMode, TargetKind)


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestEngineClassify(unittest.TestCase):
    def setUp(self):
        self.e = GeoOSINTEngine(GeoConfig.build(GeoMode.LOCAL))

    def test_classification(self):
        cases = {"8.8.8.8": TargetKind.IP, "AS15169": TargetKind.ASN,
                 "13.75, 100.5": TargetKind.COORDINATE, "example.com": TargetKind.DOMAIN,
                 "ATL": TargetKind.AIRPORT, "TH": TargetKind.COUNTRY,
                 "Thailand": TargetKind.COUNTRY, "Bangkok": TargetKind.PLACE}
        for token, kind in cases.items():
            self.assertEqual(self.e.classify(token), kind, token)


class TestEngineInvestigate(unittest.TestCase):
    def setUp(self):
        self.e = GeoOSINTEngine(GeoConfig.build(GeoMode.LOCAL))

    def test_coordinate(self):
        r = self.e.investigate_sync("13.7563, 100.5018")
        self.assertGreaterEqual(len(r.observations), 1)
        self.assertEqual(r.observations.observations[0].country_code, "TH")

    def test_country_and_score(self):
        r = self.e.investigate_sync("Thailand")
        self.assertEqual(r.kind, TargetKind.COUNTRY)
        self.assertIsNotNone(r.footprint_score)
        # footprint is explicitly NOT a risk score
        self.assertIn("not a risk", r.footprint_score["disclaimer"].lower())

    def test_domain_offline_cctld(self):
        r = self.e.investigate_sync("bank.co.th")
        self.assertTrue(any(o.country_code == "TH" for o in r.observations))

    def test_serializable(self):
        r = self.e.investigate_sync("Bangkok")
        self.assertGreater(len(json.dumps(r.to_dict())), 100)

    def test_no_errors_on_clean_run(self):
        r = self.e.investigate_sync("Singapore")
        self.assertEqual(r.errors, [])


class TestPipeline(unittest.TestCase):
    def test_enrichment(self):
        p = GeoPipeline(GeoConfig.build(GeoMode.LOCAL))
        pres = p.run_sync("Bangkok")
        types = {o.location_type.value for o in pres.result.observations}
        self.assertIn("city", types)
        # enriched with nearby public infra
        self.assertTrue({"cloud_region", "seaport"} & types)


class TestOrchestrator(unittest.TestCase):
    def test_multi_entity_and_shared_geo(self):
        o = GeoOrchestrator(GeoConfig.build(GeoMode.LOCAL))
        res = o.run_sync(["Bangkok", "Singapore", "Tokyo"])
        self.assertEqual(len(res.results), 3)
        self.assertEqual(len(res.shared_geography), 3)
        # never merge on geography alone
        self.assertTrue(all(s.merge_safe is False for s in res.shared_geography))

    def test_feature_collection(self):
        o = GeoOrchestrator(GeoConfig.build(GeoMode.LOCAL))
        res = o.run_sync(["Bangkok", "Tokyo"])
        fc = res.to_feature_collection()
        self.assertEqual(fc["type"], "FeatureCollection")


if __name__ == "__main__":
    unittest.main()
