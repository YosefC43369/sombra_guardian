import json
import unittest

from geo_osint import GeoPipeline, GeoConfig, GeoMode
from geo_osint.reports import (GeoReportBuilder, json_report, markdown_report,
                              html_report, csv_report)


class TestReports(unittest.TestCase):
    def setUp(self):
        pres = GeoPipeline(GeoConfig.build(GeoMode.LOCAL)).run_sync("Bangkok")
        self.report = GeoReportBuilder().build(pres.result, pres.proximity)

    def test_all_sections_present(self):
        for section in ("executive_summary", "geographic_inventory",
                        "infrastructure_map", "airport_analysis", "country_timeline",
                        "ip_asn_geolocation", "cloud_regions",
                        "facility_relationships", "evidence", "limitations"):
            self.assertIn(section, self.report.sections)

    def test_limitations_always_present(self):
        self.assertGreaterEqual(len(self.report.sections["limitations"]), 4)

    def test_json_render(self):
        self.assertEqual(json.loads(json_report.render(self.report))["entity"], "Bangkok")

    def test_markdown_render(self):
        md = markdown_report.render(self.report)
        self.assertIn("# Geo-OSINT Report", md)
        self.assertIn("## Limitations", md)
        self.assertIn("not a risk score", md)

    def test_html_render(self):
        html = html_report.render(self.report)
        self.assertIn("<html", html)
        self.assertIn("Infrastructure Map", html)

    def test_csv_render(self):
        self.assertIn("type,city,country_code", csv_report.render(self.report))


if __name__ == "__main__":
    unittest.main()
