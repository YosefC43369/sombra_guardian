import unittest

from geo_osint.visualization import (MapBuilder, ClusterMapBuilder, HeatmapBuilder,
                                     TimelineMapBuilder)
from geo_osint.correlation import ClusterEngine
from geo_osint.models import Coordinate, Airport, Route, RouteLeg, GeoObservation, LocationType
import time


class TestMapBuilder(unittest.TestCase):
    def test_markers_and_bounds_and_html(self):
        mb = MapBuilder()
        mb.add_markers("aps", [Airport(iata="BKK", coordinate=Coordinate(13.68, 100.75)),
                               Airport(iata="NRT", coordinate=Coordinate(35.77, 140.39))])
        self.assertEqual(len(mb.to_spec()["layers"]), 1)
        self.assertIsNotNone(mb.bounds())
        html = mb.to_html("t")
        self.assertIn("<html", html)
        self.assertIn("leaflet", html.lower())

    def test_route_layer(self):
        mb = MapBuilder()
        r = Route("x", mode="air")
        r.add_leg(RouteLeg("A", "B", Coordinate(0, 0), Coordinate(1, 1)))
        mb.add_route("r", r)
        self.assertEqual(mb.to_spec()["layers"][0]["kind"], "route")


class TestClusterMap(unittest.TestCase):
    def test_centroids_and_hulls(self):
        pts = [Coordinate(13.75, 100.50), Coordinate(13.76, 100.51),
               Coordinate(13.74, 100.49), Coordinate(35.68, 139.69),
               Coordinate(35.69, 139.70), Coordinate(35.67, 139.68)]
        cr = ClusterEngine().dbscan(pts, eps_km=20, min_samples=3)
        cmb = ClusterMapBuilder()
        self.assertEqual(len(cmb.centroids(cr)["features"]), 2)
        self.assertGreaterEqual(len(cmb.hulls(cr)["features"]), 1)


class TestHeatmap(unittest.TestCase):
    def test_weighted_points_and_grid(self):
        pts = [Coordinate(13.75, 100.50), Coordinate(13.76, 100.51)]
        hb = HeatmapBuilder()
        wp = hb.weighted_points(pts)
        self.assertEqual(len(wp[0]), 3)
        grid = hb.grid(pts, cell_deg=1.0)
        self.assertIn("intensity", grid["features"][0]["properties"])


class TestTimelineMap(unittest.TestCase):
    def test_features_and_path(self):
        obs = [GeoObservation("e", LocationType.CITY, coordinate=Coordinate(13.75, 100.5),
                              observation_timestamp=time.time() - 100),
               GeoObservation("e", LocationType.CITY, coordinate=Coordinate(1.35, 103.82),
                              observation_timestamp=time.time())]
        tmb = TimelineMapBuilder()
        self.assertIn("time", tmb.features(obs)["features"][0]["properties"])
        self.assertEqual(tmb.path(obs)["features"][0]["geometry"]["type"], "LineString")


if __name__ == "__main__":
    unittest.main()
