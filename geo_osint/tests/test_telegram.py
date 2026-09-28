import asyncio
import unittest

from geo_osint.telegram import GeoCommandService
from geo_osint.telegram.callbacks import parse_callback, dispatch, Callback
from geo_osint.telegram import keyboards
from geo_osint.configuration import GeoConfig, GeoMode


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestCommands(unittest.TestCase):
    def setUp(self):
        self.svc = GeoCommandService(GeoConfig.build(GeoMode.LOCAL))

    def test_geo(self):
        self.assertIn("Bangkok", run(self.svc.geo("Bangkok")))

    def test_geocode(self):
        self.assertIn("Tokyo", run(self.svc.geocode("Tokyo")))

    def test_reversegeo(self):
        self.assertIn("Thailand", run(self.svc.reversegeo("13.7563,100.5018")))

    def test_airport(self):
        self.assertIn("ATL", run(self.svc.airport("ATL")))

    def test_distance(self):
        self.assertIn("km", run(self.svc.distance("Bangkok | Singapore")))

    def test_country(self):
        out = run(self.svc.country("TH"))
        self.assertIn("Thailand", out)
        self.assertIn("+66", out)

    def test_city_alias(self):
        self.assertIn("Ho Chi Minh", run(self.svc.city("Saigon")))

    def test_datacenter(self):
        self.assertIn("ap-southeast-1", run(self.svc.datacenter("SG")))

    def test_ip_geo_offline_message(self):
        self.assertIn("offline", run(self.svc.ip_geo("8.8.8.8")).lower())

    def test_report(self):
        self.assertIn("Geo-OSINT Report", run(self.svc.geo_report("Bangkok")))


class TestCallbacks(unittest.TestCase):
    def test_parse(self):
        cb = parse_callback("geo:map:Bangkok")
        self.assertEqual(cb.action, "map")
        self.assertEqual(cb.entity, "Bangkok")
        fmt = parse_callback("geo:fmt:html:Tokyo")
        self.assertEqual(fmt.action, "report")
        self.assertEqual(fmt.fmt, "html")

    def test_dispatch(self):
        svc = GeoCommandService(GeoConfig.build(GeoMode.LOCAL))
        out = run(dispatch(Callback("map", "Bangkok"), svc))
        self.assertIn("Map", out)

    def test_keyboards_raw_spec(self):
        kb = keyboards.geo_actions("Bangkok")
        self.assertIsInstance(kb, list)


if __name__ == "__main__":
    unittest.main()
