import json
import os
import tempfile
import unittest

from geo_osint.maps import (OSMClient, WikidataClient, GeoNamesClient,
                           NaturalEarthLayer, AdministrativeBoundaryEngine)


class TestOSMParser(unittest.TestCase):
    def test_parse(self):
        loc = OSMClient(client=None)._parse({
            "lat": "13.7563", "lon": "100.5018", "name": "Bangkok",
            "type": "city", "osm_type": "relation", "osm_id": 1, "importance": 0.8,
            "address": {"city": "Bangkok", "state": "Bangkok",
                        "country": "Thailand", "country_code": "th"}})
        self.assertEqual(loc.city, "Bangkok")
        self.assertEqual(loc.country_code, "TH")


class TestWikidata(unittest.TestCase):
    def test_parse_entity(self):
        payload = {"entities": {"Q1861": {"id": "Q1861",
            "labels": {"en": {"value": "Bangkok"}, "th": {"value": "กรุงเทพ"}},
            "aliases": {"en": [{"value": "Krung Thep"}]},
            "descriptions": {"en": {"value": "capital"}},
            "claims": {
                "P625": [{"mainsnak": {"datavalue": {"value": {"latitude": 13.75, "longitude": 100.49}}}}],
                "P17": [{"mainsnak": {"datavalue": {"value": {"id": "Q869"}}}}],
                "P1082": [{"mainsnak": {"datavalue": {"value": {"amount": "+8305218"}}}}]}}}}
        p = WikidataClient(client=None).parse_entity(payload, "Q1861")
        self.assertEqual(p.country_qid, "Q869")
        self.assertEqual(p.population, 8305218)
        self.assertIn("Krung Thep", p.aliases)


class TestGeoNames(unittest.TestCase):
    def test_parse_search(self):
        cities = GeoNamesClient(client=None).parse_search({"geonames": [{
            "name": "Bangkok", "lat": "13.75", "lng": "100.51", "countryCode": "TH",
            "population": 5104476, "fcode": "PPLC",
            "timezone": {"timeZoneId": "Asia/Bangkok"}}]})
        self.assertTrue(cities[0].is_capital)


class TestNaturalEarth(unittest.TestCase):
    def test_point_in_country(self):
        fc = {"type": "FeatureCollection", "features": [{"type": "Feature",
            "properties": {"ISO_A2": "TH", "ISO_A3": "THA", "NAME": "Thailand"},
            "geometry": {"type": "Polygon",
                         "coordinates": [[[97, 5], [106, 5], [106, 21], [97, 21], [97, 5]]]}}]}
        path = os.path.join(tempfile.mkdtemp(), "ne.geojson")
        with open(path, "w") as fh:
            json.dump(fc, fh)
        ne = NaturalEarthLayer(path)
        self.assertTrue(ne.available)
        self.assertTrue(ne.country_geofence("TH").contains(13.75, 100.5))
        self.assertEqual(ne.country_of(13.75, 100.5), "TH")

    def test_missing_file_degrades(self):
        ne = NaturalEarthLayer("/nonexistent/path.geojson")
        self.assertFalse(ne.available)


class TestAdminBoundaries(unittest.TestCase):
    def test_centroid_fallback(self):
        abe = AdministrativeBoundaryEngine()
        gf = abe.country_boundary("JP")
        self.assertIsNotNone(gf)
        self.assertIn("approximate", gf.metadata["note"])


if __name__ == "__main__":
    unittest.main()
