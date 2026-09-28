import asyncio
import unittest

from geo_osint.geocoding import (CoordinateNormalizer, Geocoder, ReverseGeocoder,
                                 TimezoneResolver, PlaceResolver)
from geo_osint.models import Coordinate


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestNormalizer(unittest.TestCase):
    def setUp(self):
        self.n = CoordinateNormalizer()

    def test_detects_formats(self):
        self.assertEqual(self.n.detect_format("POINT (100 13)"), "wkt")
        self.assertEqual(self.n.detect_format('13°45\'N 100°30\'E'), "dms")
        self.assertEqual(self.n.detect_format("13.75, 100.5"), "decimal")

    def test_normalize_ok_and_fail(self):
        self.assertTrue(self.n.normalize("13.75, 100.5").ok)
        self.assertFalse(self.n.normalize("not a coord").ok)

    def test_represent(self):
        rep = self.n.represent(Coordinate(13.75, 100.5))
        self.assertIn("dms", rep)
        self.assertIn("mgrs", rep)
        self.assertIn("plus_code", rep)


class TestGeocoder(unittest.TestCase):
    def setUp(self):
        self.g = Geocoder()

    def test_city(self):
        self.assertEqual(self.g.geocode_offline("Bangkok")[0].city, "Bangkok")

    def test_country_token(self):
        self.assertEqual(self.g.geocode_offline("Thailand")[0].feature_code, "PCLI")
        self.assertEqual(self.g.geocode_offline("TH")[0].country_code, "TH")

    def test_alias(self):
        self.assertEqual(self.g.geocode_offline("Krung Thep")[0].city, "Bangkok")

    def test_coordinate_query(self):
        self.assertAlmostEqual(
            self.g.geocode_offline("13.75, 100.5")[0].coordinate.latitude, 13.75)

    def test_bangkok_not_bosnia(self):
        # regression: 'Bangkok'[:2] == 'BA' must NOT resolve to Bosnia
        self.assertEqual(self.g.geocode_offline("Bangkok")[0].country_code, "TH")

    def test_async_geocode(self):
        self.assertEqual(run(self.g.geocode("Tokyo"))[0].name, "Tokyo")


class TestReverseGeocoder(unittest.TestCase):
    def setUp(self):
        self.r = ReverseGeocoder()

    def test_near_bangkok(self):
        loc = self.r.reverse_offline(Coordinate(13.70, 100.60))
        self.assertEqual(loc.country_code, "TH")
        self.assertEqual(loc.timezone, "Asia/Bangkok")

    def test_open_ocean_low_confidence(self):
        loc = self.r.reverse_offline(Coordinate(0.0, -140.0))
        self.assertLess(loc.confidence, 0.5)


class TestTimezone(unittest.TestCase):
    def setUp(self):
        self.t = TimezoneResolver()

    def test_gazetteer(self):
        self.assertEqual(self.t.for_coordinate(Coordinate(35.68, 139.69)).tz,
                         "Asia/Tokyo")

    def test_offset_fallback_has_method(self):
        r = self.t.for_coordinate(Coordinate(0.0, -140.0))
        self.assertIn(r.method, ("offset", "country", "gazetteer"))


class TestPlaceResolver(unittest.TestCase):
    def setUp(self):
        self.p = PlaceResolver(Geocoder())

    def test_historical_alias(self):
        m = self.p.resolve("Constantinople")
        self.assertEqual(m.location.name, "Istanbul")
        self.assertEqual(m.kind, "alias")

    def test_normalize_preserves_thai(self):
        self.assertEqual(self.p.normalize_name("São Paulo"), "sao paulo")
        self.assertEqual(self.p.normalize_name("กรุงเทพ"),
                         "กรุงเทพ")


if __name__ == "__main__":
    unittest.main()
