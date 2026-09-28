import math
import unittest

from geo_osint.models.coordinate import (
    Coordinate, CoordinateParseError, haversine_km, geodesic_km,
    parse_dms, format_dms, latlon_to_utm, utm_to_latlon,
    latlon_to_mgrs, mgrs_to_latlon, encode_plus_code, decode_plus_code,
    parse_wkt_point, initial_bearing_deg, destination_point,
)


class TestCoordinate(unittest.TestCase):
    def test_construction_and_precision(self):
        c = Coordinate(13.7563, 100.5018)
        self.assertEqual(c.precision, 4)
        self.assertAlmostEqual(c.latitude, 13.7563)
        self.assertFalse(c.is_null_island)
        self.assertTrue(Coordinate(0, 0).is_null_island)

    def test_latitude_range_enforced(self):
        with self.assertRaises(CoordinateParseError):
            Coordinate(91.0, 0.0)

    def test_longitude_wraps(self):
        self.assertAlmostEqual(Coordinate(0, 190).longitude, -170.0)

    def test_distance_bkk_london(self):
        d = geodesic_km(13.75, 100.5, 51.5, -0.12)
        self.assertTrue(9400 < d < 9600, d)
        self.assertTrue(9400 < haversine_km(13.75, 100.5, 51.5, -0.12) < 9700)

    def test_utm_roundtrip_both_hemispheres(self):
        for lat, lon in [(13.7563, 100.5018), (51.5, -0.12), (-33.8688, 151.2093)]:
            u = latlon_to_utm(lat, lon)
            rlat, rlon = utm_to_latlon(u.zone, u.hemisphere, u.easting, u.northing)
            self.assertAlmostEqual(rlat, lat, places=5)
            self.assertAlmostEqual(rlon, lon, places=5)

    def test_mgrs_roundtrip(self):
        m = latlon_to_mgrs(13.7563, 100.5018, 5)
        rlat, rlon = mgrs_to_latlon(m)
        self.assertAlmostEqual(rlat, 13.7563, places=3)
        self.assertAlmostEqual(rlon, 100.5018, places=3)

    def test_plus_code_roundtrip(self):
        code = encode_plus_code(37.4223, -122.0840, 10)
        self.assertIn("+", code)
        lat, lon = decode_plus_code(code)
        self.assertAlmostEqual(lat, 37.4223, places=3)
        self.assertAlmostEqual(lon, -122.0840, places=3)

    def test_dms_parse_and_format(self):
        lat, lon = parse_dms('13°45\'22.7"N 100°30\'06.5"E')
        self.assertAlmostEqual(lat, 13.7563, places=3)
        self.assertIn("N", format_dms(13.75, 100.5))

    def test_wkt_axis_order(self):
        lat, lon = parse_wkt_point("POINT (100.5 13.75)")
        self.assertAlmostEqual(lat, 13.75)
        self.assertAlmostEqual(lon, 100.5)

    def test_from_any_dispatch(self):
        for v in [(13.75, 100.5), {"lat": 13.75, "lon": 100.5},
                  "13.75, 100.5", "POINT (100.5 13.75)",
                  {"type": "Point", "coordinates": [100.5, 13.75]}]:
            c = Coordinate.from_any(v)
            self.assertAlmostEqual(c.latitude, 13.75, places=2)

    def test_bearing_and_destination(self):
        b = initial_bearing_deg(0, 0, 0, 1)
        self.assertAlmostEqual(b, 90.0, places=1)
        lat, lon = destination_point(0, 0, 90, 111.32)
        self.assertAlmostEqual(lat, 0.0, places=2)
        self.assertTrue(lon > 0)

    def test_geojson_axis_order(self):
        gj = Coordinate(13.75, 100.5).to_geojson()
        self.assertEqual(gj["coordinates"][0], 100.5)
        self.assertEqual(gj["coordinates"][1], 13.75)


if __name__ == "__main__":
    unittest.main()
