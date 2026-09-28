import asyncio
import time
import unittest

from geo_osint.correlation import (TimelineEngine, GeoEntityCorrelator,
                                   IPGeolocationEngine, ASNGeolocationEngine,
                                   DomainGeolocationEngine, InfrastructureGraph)
from geo_osint.models import Coordinate, GeoObservation, LocationType, Evidence


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _obs():
    now = time.time()
    return [GeoObservation("acme", LocationType.CITY, city="Bangkok", country_code="TH",
                           source="wikidata", observation_timestamp=now - 1000,
                           evidence=[Evidence("wikidata", "hq", 0.6)]),
            GeoObservation("acme", LocationType.CITY, city="Singapore", country_code="SG",
                           source="news", observation_timestamp=now,
                           evidence=[Evidence("news", "moved", 0.5)])]


class TestTimeline(unittest.TestCase):
    def test_build_and_changes(self):
        te = TimelineEngine()
        obs = _obs()
        self.assertEqual(len(te.build(obs)), 2)
        ch = te.location_changes(obs)
        self.assertEqual(ch[0].to_place, "Singapore")


class TestEntityCorrelation(unittest.TestCase):
    def test_primary_country_and_merge_safeguard(self):
        gc = GeoEntityCorrelator()
        obs = _obs()
        prof = gc.correlate("acme", obs)
        self.assertIn(prof.primary_country.value, ("TH", "SG"))
        other = [GeoObservation("x", LocationType.CITY, city="Bangkok", country_code="TH",
                                source="z")]
        sg = gc.shared_geography("acme", obs, "x", other)
        self.assertFalse(sg.merge_safe)
        self.assertIn("Bangkok", sg.shared_cities)

    def test_noisy_or_combination(self):
        gc = GeoEntityCorrelator()
        obs = [GeoObservation("e", LocationType.CITY, city="Bangkok", country_code="TH",
                              source="a", evidence=[Evidence("a", "c", 0.6)]),
               GeoObservation("e", LocationType.CITY, city="Bangkok", country_code="TH",
                              source="b", evidence=[Evidence("b", "c", 0.5)])]
        prof = gc.correlate("e", obs)
        # noisy-OR of independent 0.6 and 0.5 -> 0.8
        self.assertAlmostEqual(prof.primary_city.confidence, 0.8, places=2)


class TestGeolocationParsers(unittest.TestCase):
    def test_ip_gating_and_parse(self):
        e = IPGeolocationEngine()
        self.assertTrue(e.is_locatable("8.8.8.8"))
        self.assertFalse(e.is_locatable("192.168.1.1"))
        o = e.parse_ipwhois({"success": True, "latitude": 1.29, "longitude": 103.85,
                             "city": "Singapore", "country_code": "SG",
                             "connection": {"asn": 15169, "org": "Google"},
                             "timezone": {"id": "Asia/Singapore"}}, "8.8.8.8")
        self.assertEqual(o.country_code, "SG")
        self.assertIn("estimate", o.evidence[0].limitations.lower())

    def test_ip_rejects_private_async(self):
        e = IPGeolocationEngine()
        res = run(e.locate("192.168.1.1"))
        self.assertFalse(res.ok)

    def test_domain_cctld(self):
        d = DomainGeolocationEngine()
        self.assertEqual(d.signals_offline("bank.co.th").countries, ["TH"])
        self.assertIsNone(d.cctld_signal("example.com"))
        self.assertTrue(d.cctld_signal("startup.co").metadata["generic_cctld"])

    def test_asn_normalize(self):
        a = ASNGeolocationEngine()
        self.assertEqual(a.normalize("AS15169"), 15169)


class TestInfraGraph(unittest.TestCase):
    def test_build_from_observations(self):
        g = InfrastructureGraph()
        for o in _obs():
            g.add_observation(o)
        d = g.to_dict()
        self.assertGreaterEqual(d["node_count"], 3)


if __name__ == "__main__":
    unittest.main()
