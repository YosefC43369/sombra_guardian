import unittest

from geo_osint.correlation import DistanceEngine, ClusterEngine
from geo_osint.models import Coordinate, City


class TestDistance(unittest.TestCase):
    def setUp(self):
        self.d = DistanceEngine()

    def test_between(self):
        km = self.d.between(Coordinate(13.75, 100.5), Coordinate(35.68, 139.69))
        self.assertTrue(4500 < km < 5000)

    def test_matrix_symmetric(self):
        m = self.d.matrix([Coordinate(0, 0), Coordinate(0, 1), Coordinate(1, 1)])
        self.assertEqual(m[0][1], m[1][0])
        self.assertEqual(m[0][0], 0.0)

    def test_city_to_city(self):
        a = City(name="A", coordinate=Coordinate(13.75, 100.5))
        b = City(name="B", coordinate=Coordinate(1.35, 103.82))
        self.assertGreater(self.d.city_to_city(a, b), 0)

    def test_total_path(self):
        pts = [Coordinate(0, 0), Coordinate(0, 1), Coordinate(0, 2)]
        self.assertGreater(self.d.total_path_km(pts), 0)


class TestCluster(unittest.TestCase):
    def setUp(self):
        self.c = ClusterEngine()
        self.pts = [Coordinate(13.75, 100.50), Coordinate(13.76, 100.51),
                    Coordinate(13.74, 100.49), Coordinate(35.68, 139.69),
                    Coordinate(35.69, 139.70), Coordinate(35.67, 139.68),
                    Coordinate(-33.87, 151.21)]

    def test_dbscan_two_clusters_one_noise(self):
        res = self.c.dbscan(self.pts, eps_km=20, min_samples=3)
        self.assertEqual(res.cluster_count, 2)
        self.assertEqual(len(res.noise), 1)

    def test_kmeans(self):
        res = self.c.kmeans(self.pts, k=2)
        self.assertEqual(res.cluster_count, 2)

    def test_centroid_present(self):
        res = self.c.dbscan(self.pts, eps_km=20, min_samples=3)
        self.assertIsNotNone(res.clusters[0].centroid)


if __name__ == "__main__":
    unittest.main()
