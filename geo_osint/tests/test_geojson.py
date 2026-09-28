import json
import unittest

from geo_osint.visualization import GeoJSONBuilder
from geo_osint.models import Coordinate, Airport


class TestGeoJSON(unittest.TestCase):
    def setUp(self):
        self.b = GeoJSONBuilder()

    def test_point_axis_order(self):
        f = self.b.point(Coordinate(13.75, 100.5))
        self.assertEqual(f["geometry"]["coordinates"], [100.5, 13.75])

    def test_line_string(self):
        f = self.b.line_string([Coordinate(0, 0), Coordinate(1, 1)])
        self.assertEqual(f["geometry"]["type"], "LineString")

    def test_polygon_closes_ring(self):
        f = self.b.polygon([[0, 0], [1, 0], [1, 1]])
        ring = f["geometry"]["coordinates"][0]
        self.assertEqual(ring[0], ring[-1])

    def test_collection_and_validity(self):
        fc = self.b.collection([Coordinate(0, 0),
                                Airport(iata="BKK", coordinate=Coordinate(13.68, 100.75))])
        self.assertTrue(self.b.is_valid(fc))
        self.assertEqual(len(fc["features"]), 2)

    def test_stream_matches_collection(self):
        items = [Coordinate(0, 0), Coordinate(1, 1)]
        streamed = json.loads("".join(self.b.stream_collection(items)))
        self.assertEqual(streamed["type"], "FeatureCollection")
        self.assertEqual(len(streamed["features"]), 2)

    def test_invalid_detected(self):
        self.assertFalse(self.b.is_valid({"type": "X"}))


if __name__ == "__main__":
    unittest.main()
