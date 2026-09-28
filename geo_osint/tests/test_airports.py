import unittest

from geo_osint.airports import (AirportEngine, RunwayEngine, AirportTimezoneEngine,
                               CountryAirportsEngine, AirlineGraphEngine)
from geo_osint.models import Coordinate, Airport


class TestAirportEngine(unittest.TestCase):
    def setUp(self):
        self.e = AirportEngine()

    def test_available(self):
        self.assertTrue(self.e.available)

    def test_by_iata(self):
        ap = self.e.by_iata("ATL")
        self.assertIsNotNone(ap)
        self.assertEqual(ap.iata, "ATL")
        self.assertTrue(ap.has_fix)

    def test_nearest(self):
        near = self.e.nearest(Coordinate(33.75, -84.39), limit=1, max_km=2000)
        self.assertTrue(near)
        self.assertEqual(near[0][0].iata, "ATL")

    def test_distance(self):
        d = self.e.distance_km("ATL", "PEK")
        self.assertTrue(d is None or d > 10000)

    def test_country_aggregation(self):
        agg = CountryAirportsEngine(self.e).for_country("US")
        self.assertGreater(agg.total, 0)

    def test_resolve_place_hook(self):
        loc = self.e.resolve_place("ATL")
        self.assertIsNotNone(loc)
        self.assertEqual(loc.feature_code, "AIRP")


class TestRunwayEngine(unittest.TestCase):
    def test_summary_empty_when_absent(self):
        ap = Airport(iata="XXX", coordinate=Coordinate(0.1, 0.1))
        s = RunwayEngine().summarize(ap)
        self.assertEqual(s.count, 0)

    def test_summary_from_metadata(self):
        ap = Airport(iata="YYY", coordinate=Coordinate(1, 1),
                     metadata={"runways": [{"ident": "09", "length_ft": 12000,
                                            "surface": "asphalt", "lighted": "yes"}]})
        s = RunwayEngine().summarize(ap)
        self.assertEqual(s.count, 1)
        self.assertEqual(s.longest_ft, 12000)
        self.assertTrue(s.paved)


class TestAirportTimezone(unittest.TestCase):
    def test_from_coordinate(self):
        ap = Airport(iata="ZZZ", country="US", coordinate=Coordinate(33.64, -84.43))
        tr = AirportTimezoneEngine().resolve(ap)
        self.assertIsNotNone(tr)


class TestAirportGraph(unittest.TestCase):
    def test_same_city_edges(self):
        aps = [Airport(iata="BKK", city="Bangkok", country="TH",
                       coordinate=Coordinate(13.68, 100.75)),
               Airport(iata="DMK", city="Bangkok", country="TH",
                       coordinate=Coordinate(13.91, 100.60))]
        g = AirlineGraphEngine().build(aps, same_city=True)
        self.assertEqual(len(g.nodes), 2)
        self.assertTrue(any(t == "same_city" for _, _, t in g.edges))


if __name__ == "__main__":
    unittest.main()
