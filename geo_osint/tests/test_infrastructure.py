import unittest

from geo_osint.infrastructure import (CloudRegionEngine, DataCenterEngine,
                                     FacilityEngine, SubmarineCableEngine)
from geo_osint.models import Coordinate, Facility, FacilityType, BoundingBox


class TestCloudRegions(unittest.TestCase):
    def setUp(self):
        self.e = CloudRegionEngine()

    def test_lookup_and_providers(self):
        self.assertIn("aws", self.e.providers())
        self.assertEqual(self.e.by_code("ap-southeast-1").city, "Singapore")
        self.assertGreater(len(self.e.by_provider("aws")), 20)

    def test_nearest(self):
        near = self.e.nearest(Coordinate(1.35, 103.82), limit=1)
        self.assertLess(near[0][1], 50)

    def test_observation_has_limitation(self):
        o = self.e.to_observation(self.e.by_code("eu-central-1"))
        self.assertEqual(o.city, "Frankfurt")
        self.assertIn("city precision", o.evidence[0].limitations)


class TestDataCenter(unittest.TestCase):
    def test_peeringdb_parsers(self):
        dce = DataCenterEngine()
        dcs = dce.parse_peeringdb_fac({"data": [{"id": 1, "name": "Equinix SG1",
            "org_name": "Equinix", "city": "Singapore", "country": "SG",
            "latitude": 1.32, "longitude": 103.69}]})
        self.assertEqual(dcs[0].name, "Equinix SG1")
        ix = dce.parse_peeringdb_ix({"data": [{"id": 1, "name": "SGIX",
            "city": "Singapore", "country": "SG", "net_count": 80}]})
        self.assertEqual(ix[0].participants, 80)


class TestFacility(unittest.TestCase):
    def test_nearest_and_overpass_query(self):
        fe = FacilityEngine()
        fe.register(Facility(name="Chula", facility_type=FacilityType.UNIVERSITY,
                             coordinate=Coordinate(13.74, 100.53), country_code="TH"))
        near = fe.nearest(Coordinate(13.75, 100.52), radius_km=10,
                          ftype=FacilityType.UNIVERSITY)
        self.assertEqual(near[0][0].name, "Chula")
        q = fe.build_overpass_query(FacilityType.HOSPITAL,
                                    BoundingBox.around(13.75, 100.5, 5))
        self.assertIn("hospital", q)

    def test_overpass_parser(self):
        fe = FacilityEngine()
        parsed = fe.parse_overpass({"elements": [{"type": "node", "id": 1,
            "lat": 13.7, "lon": 100.5, "tags": {"amenity": "hospital",
                                                 "name": "General"}}]},
            FacilityType.HOSPITAL)
        self.assertEqual(parsed[0].name, "General")


class TestSubmarineCable(unittest.TestCase):
    def test_seed_and_by_country(self):
        sce = SubmarineCableEngine()
        self.assertTrue(sce.all())
        th = sce.by_country("TH")
        self.assertTrue(any("AAE-1" in c.name for c in th))


if __name__ == "__main__":
    unittest.main()
