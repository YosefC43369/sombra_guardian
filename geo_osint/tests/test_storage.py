import tempfile
import unittest

from geo_osint.storage import GeoGridIndex, SQLiteGeoStore, CacheStore
from geo_osint.models import (Coordinate, GeoObservation, LocationType,
                             BoundingBox, Evidence)
from geo_osint.data import cities


class TestGridIndex(unittest.TestCase):
    def test_within_and_nearest(self):
        idx = GeoGridIndex(cell_deg=1.0)
        idx.index_objects(cities.all_cities(), id_attr="name")
        res = idx.within(Coordinate(13.70, 100.60), 100)
        self.assertTrue(any(getattr(p, "name", "") == "Bangkok" for p, _ in res))
        near = idx.nearest(Coordinate(35.68, 139.69), k=1)
        self.assertEqual(getattr(near[0][0], "name", ""), "Tokyo")


class TestSQLiteStore(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteGeoStore(":memory:")
        obs = [GeoObservation(f"e{i}", LocationType.CITY,
                              coordinate=Coordinate(13.0 + i * 0.1, 100.0 + i * 0.1),
                              city=f"c{i}", country_code="TH", source="s",
                              evidence=[Evidence("x", "c", 0.5)]) for i in range(30)]
        self.store.add_many(obs)

    def tearDown(self):
        self.store.close()

    def test_count_and_entity(self):
        self.assertEqual(self.store.count(), 30)
        self.assertEqual(self.store.by_entity("e5")[0].city, "c5")

    def test_bbox_and_radius(self):
        self.assertTrue(self.store.in_bbox(BoundingBox.around(13.2, 100.2, 80)))
        self.assertTrue(self.store.within_radius(Coordinate(13.0, 100.0), 60))

    def test_roundtrip_preserves_evidence(self):
        o = self.store.by_entity("e5")[0]
        self.assertTrue(o.evidence)


class TestCache(unittest.TestCase):
    def test_set_get_ttl(self):
        c = CacheStore(tempfile.mkdtemp(), default_ttl_s=100)
        c.set("ns", "k", {"v": 1})
        self.assertEqual(c.get("ns", "k"), {"v": 1})
        c.set("ns", "exp", {"a": 1}, ttl_s=-1)
        self.assertIsNone(c.get("ns", "exp"))

    def test_get_or_set_caches(self):
        c = CacheStore(tempfile.mkdtemp())
        calls = []
        def prod():
            calls.append(1)
            return {"v": 1}
        c.get_or_set("n", "q", prod)
        c.get_or_set("n", "q", prod)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
