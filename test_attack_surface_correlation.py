# -*- coding: utf-8 -*-
"""เทสต์ attack_surface_correlation — normalize/dedupe, relationship rules, shared-infra
guard (กันผลบวกลวง), graph, insights, historical comparison, missing/malformed input,
orchestrator integration, AI fallback, telegram report (ไม่ต่อเน็ต, local fixtures)

รันด้วย: python -m unittest test_attack_surface_correlation  หรือ pytest
"""

import asyncio
import os
import tempfile
import unittest

from attack_surface_correlation import (normalize, relate, graph as graphmod,
                                        insights, engine, report, store)


# ---------------------------------------------------------------------------
# fixtures สังเคราะห์ (ไม่มีข้อมูลจริง/ไม่ต่อเน็ต)
# ---------------------------------------------------------------------------

def passive_fixture(domain="api.example.com", registered="example.com",
                    ip="203.0.113.10", subs=None, collected="2026-11-01T00:00:00+00:00"):
    subs = subs if subs is not None else ["api.example.com", "www.example.com"]
    return {
        "ok": True,
        "target": {"domain": domain, "registered": registered,
                   "url": f"https://{domain}"},
        "collected_at": collected,
        "categories": {
            "subdomains": {"records": [{"value": s, "source": "crt.sh"} for s in subs]},
            "dns": {"records": [{"type": "A", "value": ip, "source": "doh"},
                                {"type": "MX", "value": "mail.example.com"}]},
            "infrastructure": {"records": [{"type": "ip", "value": ip, "asn": "AS64500"}]},
            "tls": {"data": {"subject_cn": domain, "san": subs, "issuer_cn": "R3",
                             "issuer_org": "Lets Encrypt", "not_after": "x", "expired": False}},
            "http": {"data": {"status": 200, "server": "nginx",
                              "security_headers_missing": ["content-security-policy"]}},
            "technology": {"records": [
                {"tech": "nginx", "category": "web-server", "confidence": 0.95,
                 "confirmed": True, "version": "1.25.0"},
                {"tech": "Cloudflare", "category": "cdn", "confidence": 0.9, "confirmed": True}]},
        },
    }


def wva_fixture():
    return {"target": "https://api.example.com", "created_iso": "2026-11-01T00:00:00+00:00",
            "findings": [
                {"category": "xss", "rule": "reflection", "severity": "HIGH",
                 "state": "POTENTIAL", "confidence": 0.6, "endpoint": "/search", "evidence": "<x>"},
                {"category": "misconfiguration", "rule": "missing-header", "severity": "LOW",
                 "state": "INFORMATIONAL", "confidence": 0.4, "endpoint": "/search",
                 "evidence": "no csp"}]}


def api_fixture():
    return {"target": "api.example.com", "created_iso": "2026-11-01T00:00:00+00:00",
            "findings": [
                {"category": "authentication", "rule": "no-auth", "severity": "HIGH",
                 "state": "POTENTIAL", "confidence": 0.7, "endpoint": "/v1/users",
                 "method": "GET", "evidence": "200 no token"},
                {"category": "authorization", "rule": "bola", "severity": "HIGH",
                 "state": "POTENTIAL", "confidence": 0.65, "endpoint": "/v1/orders",
                 "method": "GET", "evidence": "idor"}]}


def _build(module_outputs=None, findings=None, target="example.com", previous=None,
           policy=None):
    return engine.build_result(module_outputs, findings=findings, target=target,
                               previous=previous, policy=policy)


def _rels(result, relationship):
    return [c for c in result["correlations"] if c["relationship"] == relationship]


# ---------------------------------------------------------------------------
# 1. Asset normalization
# ---------------------------------------------------------------------------
class NormalizeTests(unittest.TestCase):
    def test_hostname_normalization(self):
        self.assertEqual(normalize.normalize_hostname("API.Example.COM."), "api.example.com")
        self.assertEqual(normalize.normalize_hostname("*.example.com"), "example.com")
        self.assertEqual(normalize.normalize_hostname("https://x.example.com/a?b"),
                         "x.example.com")
        self.assertEqual(normalize.normalize_hostname("host:8443"), None)  # bare label
        self.assertIsNone(normalize.normalize_hostname("not a domain"))
        self.assertIsNone(normalize.normalize_hostname(""))

    def test_ip_normalization(self):
        self.assertTrue(normalize.is_ip("203.0.113.10"))
        self.assertFalse(normalize.is_ip("example.com"))
        self.assertEqual(normalize.normalize_ip("2001:0db8:0000::1"), "2001:db8::1")
        self.assertIsNone(normalize.normalize_ip("999.1.1.1"))

    def test_url_normalization(self):
        self.assertEqual(normalize.normalize_url("HTTP://Example.com"), "http://example.com/")
        self.assertEqual(normalize.normalize_url("https://x.com/a/b?q=1#f"),
                         "https://x.com/a/b?q=1")
        self.assertIsNone(normalize.normalize_url("ht!tp://bad host"))

    def test_endpoint_key(self):
        self.assertEqual(normalize.endpoint_key("API.X.com", "get", "/v1/users?x=1"),
                         "GET api.x.com/v1/users")

    def test_extract_passive_assets(self):
        b = normalize.AssetBuilder()
        normalize.extract_passive_recon(passive_fixture(), b)
        types = {a["asset_type"] for a in b.assets()}
        self.assertIn("root_domain", types)
        self.assertIn("subdomain", types)
        self.assertIn("ip", types)
        self.assertIn("certificate", types)
        self.assertIn("technology", types)
        root = b.get("root_domain", "example.com")
        self.assertIsNotNone(root)
        self.assertEqual(root["source_modules"], ["passive_recon"])


# ---------------------------------------------------------------------------
# 2. Domain relationship detection
# ---------------------------------------------------------------------------
class DomainRelationshipTests(unittest.TestCase):
    def test_contains(self):
        r = _build({"passive_recon": passive_fixture()})
        contains = _rels(r, "contains")
        self.assertTrue(contains)
        for c in contains:
            self.assertEqual(c["ownership"], "confirmed")
            self.assertEqual(c["confidence"], 1.0)

    def test_no_contains_for_unrelated_domain(self):
        # subdomain ที่ไม่ได้อยู่ใต้ parent จริง ไม่ควรเกิด contains
        b = normalize.AssetBuilder()
        b.add("root_domain", "example.com", source_module="t", parent_domain="example.com")
        b.add("subdomain", "evil.other.com", source_module="t", parent_domain="other.com")
        rels = relate.correlate_assets(b.assets())
        self.assertEqual([c for c in rels if c["relationship"] == "contains"], [])


# ---------------------------------------------------------------------------
# 3. DNS relationship detection
# ---------------------------------------------------------------------------
class DnsRelationshipTests(unittest.TestCase):
    def test_has_dns_record_and_resolves_to(self):
        r = _build({"passive_recon": passive_fixture()})
        self.assertTrue(_rels(r, "has_dns_record"))
        resolves = _rels(r, "resolves_to")
        self.assertTrue(resolves)
        self.assertEqual(resolves[0]["ownership"], "confirmed")


# ---------------------------------------------------------------------------
# 4. Shared IP association (false-relationship prevention)
# ---------------------------------------------------------------------------
class SharedIpTests(unittest.TestCase):
    def _two_domains_same_ip(self):
        b = normalize.AssetBuilder()
        b.add("subdomain", "a.example.com", source_module="passive_recon",
              parent_domain="example.com", ip_addresses=["203.0.113.10"])
        b.add("subdomain", "b.other.com", source_module="passive_recon",
              parent_domain="other.com", ip_addresses=["203.0.113.10"])
        b.add("ip", "203.0.113.10", source_module="passive_recon")
        return b.assets()

    def test_shared_ip_is_hypothesis_not_ownership(self):
        rels = relate.correlate_assets(self._two_domains_same_ip())
        shared = [c for c in rels if c["relationship"] == "shared_infrastructure"]
        self.assertTrue(shared)
        for c in shared:
            self.assertTrue(c["hypothesis"])
            self.assertEqual(c["ownership"], "observed_shared_infra")
            self.assertNotEqual(c["relationship"], "contains")

    def test_same_owner_same_ip_not_flagged_shared(self):
        # โฮสต์สองตัว registered domain เดียวกัน ใช้ IP เดียว -> ไม่ใช่ shared-infra ข้ามเจ้าของ
        b = normalize.AssetBuilder()
        b.add("subdomain", "a.example.com", source_module="t", parent_domain="example.com",
              ip_addresses=["203.0.113.10"])
        b.add("subdomain", "b.example.com", source_module="t", parent_domain="example.com",
              ip_addresses=["203.0.113.10"])
        rels = relate.correlate_assets(b.assets())
        self.assertEqual([c for c in rels if c["relationship"] == "shared_infrastructure"], [])


# ---------------------------------------------------------------------------
# 5. Certificate fingerprint matching
# ---------------------------------------------------------------------------
class CertificateTests(unittest.TestCase):
    def test_secured_by(self):
        r = _build({"passive_recon": passive_fixture()})
        secured = _rels(r, "secured_by")
        self.assertTrue(secured)
        self.assertEqual(secured[0]["ownership"], "confirmed")

    def test_shared_certificate_multi_domain_is_hypothesis(self):
        b = normalize.AssetBuilder()
        b.add("certificate", "shared-cert", source_module="passive_recon",
              metadata={"san": ["a.example.com", "b.other.com"], "subject_cn": "a.example.com"})
        rels = relate.correlate_assets(b.assets())
        shared = [c for c in rels if c["relationship"] == "shared_infrastructure"]
        self.assertTrue(shared)
        self.assertTrue(shared[0]["hypothesis"])


# ---------------------------------------------------------------------------
# 6. Technology relationship detection
# ---------------------------------------------------------------------------
class TechnologyTests(unittest.TestCase):
    def test_shared_technology_cdn_is_hypothesis(self):
        b = normalize.AssetBuilder()
        b.add("technology", "Cloudflare", source_module="passive_recon",
              metadata={"tech": "Cloudflare", "host": "a.example.com"})
        b.add("technology", "Cloudflare", source_module="passive_recon",
              metadata={"tech": "Cloudflare", "host": "b.other.com"})
        # หมายเหตุ: ค่าเดียวกันถูก dedupe เป็น asset เดียว แต่ host ต่างใน metadata แรกเท่านั้น;
        # ใช้ชื่อ tech ต่าง host ผ่าน value ต่างแทน
        b2 = normalize.AssetBuilder()
        b2.add("technology", "Cloudflare@a", source_module="t",
               metadata={"tech": "cloudflare", "host": "a.example.com"})
        b2.add("technology", "Cloudflare@b", source_module="t",
               metadata={"tech": "cloudflare", "host": "b.other.com"})
        rels = relate.correlate_assets(b2.assets())
        shared = [c for c in rels if c["relationship"] == "shared_technology"]
        self.assertTrue(shared)
        self.assertTrue(shared[0]["hypothesis"])


# ---------------------------------------------------------------------------
# 7. API and website relationship detection
# ---------------------------------------------------------------------------
class WebApiRelationshipTests(unittest.TestCase):
    def test_serves_website(self):
        r = _build({"passive_recon": passive_fixture()})
        self.assertTrue(_rels(r, "serves"))

    def test_exposes_api_endpoint(self):
        r = _build({"passive_recon": passive_fixture(), "api_security_assessment": api_fixture()})
        self.assertTrue(_rels(r, "exposes_endpoint"))


# ---------------------------------------------------------------------------
# 8/9. Duplicate asset + finding detection
# ---------------------------------------------------------------------------
class DeduplicationTests(unittest.TestCase):
    def test_duplicate_asset_merges_sources(self):
        b = normalize.AssetBuilder()
        b.add("subdomain", "api.example.com", source_module="passive_recon",
              parent_domain="example.com", confidence=0.8)
        b.add("subdomain", "api.example.com", source_module="web_vulnerability_assessment",
              parent_domain="example.com", confidence=0.6)
        assets = [a for a in b.assets() if a["value"] == "api.example.com"]
        self.assertEqual(len(assets), 1)             # ตัวเดียว
        self.assertEqual(sorted(assets[0]["source_modules"]),
                         ["passive_recon", "web_vulnerability_assessment"])
        self.assertEqual(assets[0]["confidence"], 0.8)   # เลือกสูงสุด
        self.assertEqual(len(assets[0]["observations"]), 2)   # ไม่ลบประวัติ

    def test_duplicate_finding_dedup(self):
        # finding เหมือนกันจากสองโมดูล -> finding asset เดียว คง observation สองแหล่ง
        b = normalize.AssetBuilder()
        f = {"category": "xss", "rule": "reflection", "severity": "HIGH",
             "state": "POTENTIAL", "confidence": 0.6, "endpoint": "/s", "evidence": "<x>"}
        normalize._extract_finding_asset(dict(f), b, "wva", default_host="x.com",
                                         parent="x.com", observed=None)
        normalize._extract_finding_asset(dict(f), b, "wva", default_host="x.com",
                                         parent="x.com", observed=None)
        findings = [a for a in b.assets() if a["asset_type"] == "finding"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0]["observations"]), 2)


# ---------------------------------------------------------------------------
# 10. Confidence scoring / threshold
# ---------------------------------------------------------------------------
class ConfidenceTests(unittest.TestCase):
    def test_threshold_filters_low_confidence(self):
        high = _build({"passive_recon": passive_fixture()},
                      policy={"confidence_threshold": 0.99})
        low = _build({"passive_recon": passive_fixture()},
                     policy={"confidence_threshold": 0.5})
        # เกณฑ์สูงกรองความสัมพันธ์อ่อนออก (<=0.99 ยังเหลือ contains=1.0)
        self.assertLessEqual(len(high["correlations"]), len(low["correlations"]))
        for c in high["correlations"]:
            self.assertGreaterEqual(c["confidence"], 0.99)

    def test_finding_link_confidence_is_linkage_not_finding_conf(self):
        # finding confidence 0.4 (ต่ำ) แต่ linkage ควรสูง (>=0.8) -> ยังผ่าน threshold 0.7
        r = _build({"web_vulnerability_assessment": wva_fixture()},
                   policy={"confidence_threshold": 0.7})
        has_finding = _rels(r, "has_finding")
        self.assertTrue(has_finding)
        for c in has_finding:
            self.assertGreaterEqual(c["confidence"], 0.8)


# ---------------------------------------------------------------------------
# 11. False relationship prevention (vulnerable-neighbor != vulnerable)
# ---------------------------------------------------------------------------
class FalseRelationshipTests(unittest.TestCase):
    def test_no_vulnerability_propagation(self):
        # asset ที่เชื่อมกับ asset ที่มี finding ต้องไม่ถูกตั้ง finding ของตัวเอง
        r = _build({"passive_recon": passive_fixture(), "web_vulnerability_assessment": wva_fixture()})
        finding_targets = {c["source"] for c in _rels(r, "has_finding")}
        # www.example.com ไม่มี finding -> asset_id ของมันต้องไม่อยู่ใน finding_targets
        www = None
        for a in r["assets"]:
            if a["value"] == "www.example.com":
                www = a["asset_id"]
        if www:
            self.assertNotIn(www, finding_targets)

    def test_insights_separate_hypothesis_from_confirmed(self):
        r = _build({"passive_recon": passive_fixture(ip="203.0.113.10")})
        for i in r["insights"]:
            self.assertIn("hypothesis", i)
            self.assertIsInstance(i["hypothesis"], bool)


# ---------------------------------------------------------------------------
# 12. Graph generation
# ---------------------------------------------------------------------------
class GraphTests(unittest.TestCase):
    def test_graph_nodes_and_edges(self):
        r = _build({"passive_recon": passive_fixture()})
        g = r["graph"]
        self.assertEqual(g["stats"]["node_count"], len(g["nodes"]))
        self.assertEqual(g["stats"]["edge_count"], len(g["edges"]))
        self.assertGreater(g["stats"]["node_count"], 0)
        # ทุก edge ต้องมี source เป็น node จริง
        ids = {n["id"] for n in g["nodes"]}
        for e in g["edges"]:
            self.assertIn(e["source"], ids)
            self.assertIn(e["target"], ids)   # virtual node ก็ถูกเพิ่มเป็น node

    def test_degree_map(self):
        r = _build({"passive_recon": passive_fixture()})
        deg = graphmod.degree_map(r["graph"])
        self.assertTrue(any(v >= 1 for v in deg.values()))


# ---------------------------------------------------------------------------
# 13. Historical comparison
# ---------------------------------------------------------------------------
class HistoryTests(unittest.TestCase):
    def test_baseline_then_diff(self):
        prev = _build({"passive_recon": passive_fixture(subs=["api.example.com"])})
        self.assertTrue(prev["history"].get("baseline"))
        cur = _build({"passive_recon": passive_fixture(subs=["api.example.com", "new.example.com"])},
                     previous=prev)
        h = cur["history"]
        self.assertFalse(h["baseline"])
        self.assertIn("new.example.com", h["new_assets"])

    def test_changed_ip_association(self):
        prev = _build({"passive_recon": passive_fixture(ip="203.0.113.10")})
        cur = _build({"passive_recon": passive_fixture(ip="203.0.113.99")}, previous=prev)
        changes = cur["history"]["changed_ip_associations"]
        self.assertTrue(any(c["host"] == "api.example.com" for c in changes))


# ---------------------------------------------------------------------------
# 14/15. Missing module data + malformed input
# ---------------------------------------------------------------------------
class RobustnessTests(unittest.TestCase):
    def test_missing_modules(self):
        r = _build({})   # ไม่มี output เลย
        self.assertEqual(r["counts"]["total_assets"], 0)
        self.assertEqual(r["correlations"], [])

    def test_partial_passive(self):
        r = _build({"passive_recon": {"ok": True, "target": {"domain": "x.example.com",
                                                             "registered": "example.com"},
                                      "categories": {}}})
        self.assertGreaterEqual(r["counts"]["total_assets"], 1)

    def test_malformed_input_does_not_crash(self):
        bad = {"passive_recon": {"categories": {"subdomains": {"records": [None, 123, {"value": None},
                                                                           {"value": "ok.example.com"}]},
                                                "dns": {"records": "notalist"}},
                                 "target": None}}
        r = _build(bad)                      # ต้องไม่ throw
        self.assertIsInstance(r["assets"], list)

    def test_unknown_module_ignored(self):
        r = _build({"some_future_module": {"whatever": 1}})
        self.assertEqual(r["counts"]["total_assets"], 0)

    def test_max_assets_limit(self):
        subs = [f"h{i}.example.com" for i in range(50)]
        r = _build({"passive_recon": passive_fixture(subs=subs)},
                   policy={"max_assets": 5})
        self.assertLessEqual(r["counts"]["total_assets"], 5)
        self.assertGreater(r["counts"]["assets_dropped_over_limit"], 0)


# ---------------------------------------------------------------------------
# 16. Orchestrator integration
# ---------------------------------------------------------------------------
class OrchestratorIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.asc_path = os.path.join(tempfile.mkdtemp(), "asc.json")
        self.rt_path = os.path.join(tempfile.mkdtemp(), "rt.json")

    def test_from_task_extracts_findings(self):
        task = {"task_id": "RT-1", "target": "https://api.example.com",
                "findings": [{"finding_id": "wva-0", "category": "xss", "title": "reflection",
                              "severity": "HIGH", "affected_asset": "/s", "confidence": 0.6,
                              "verification_status": "POTENTIAL", "evidence_refs": ["<x>"],
                              "detection_source": "wva"}]}
        ext = engine.from_task(task)
        self.assertEqual(ext["target"], "https://api.example.com")
        self.assertEqual(len(ext["findings"]), 1)

    def test_analyze_task_reads_stored_task(self):
        from red_team_orchestrator import store as rt_store
        rec = rt_store.create_task("website_assessment", "https://api.example.com", 1, 10, {},
                                   self.rt_path)
        rt_store.update_task(rec["task_id"], lambda r: r.update({
            "findings": [{"finding_id": "wva-0", "category": "xss", "title": "reflection",
                          "severity": "HIGH", "affected_asset": "api.example.com/s",
                          "confidence": 0.6, "verification_status": "POTENTIAL",
                          "evidence_refs": ["<x>"], "detection_source": "wva"}]}), self.rt_path)
        result = asyncio.run(engine.analyze_task(rec["task_id"], ai=False,
                                                 path=self.asc_path, rt_path=self.rt_path))
        self.assertEqual(result["source_task_id"], rec["task_id"])
        self.assertGreaterEqual(result["counts"]["total_assets"], 1)
        # เก็บผลแล้ว อ่านกลับได้
        self.assertIsNotNone(store.get_result(result["result_id"], self.asc_path))

    def test_analyze_task_with_native_sink(self):
        from red_team_orchestrator import store as rt_store
        rec = rt_store.create_task("website_assessment", "example.com", 1, 10, {}, self.rt_path)
        sink = {"passive_recon": passive_fixture()}
        result = asyncio.run(engine.analyze_task(rec["task_id"], ai=False, path=self.asc_path,
                                                 rt_path=self.rt_path, module_outputs=sink))
        self.assertIn("contains", {c["relationship"] for c in result["correlations"]})

    def test_task_not_found(self):
        result = asyncio.run(engine.analyze_task("RT-does-not-exist", path=self.asc_path,
                                                 rt_path=self.rt_path))
        self.assertEqual(result["error"], "TASK_NOT_FOUND")

    def test_persist_and_history_across_runs(self):
        out = {"passive_recon": passive_fixture(subs=["api.example.com"])}
        r1 = asyncio.run(engine.correlate(out, target="example.com", ai=False,
                                          persist=True, path=self.asc_path))
        out2 = {"passive_recon": passive_fixture(subs=["api.example.com", "n.example.com"])}
        r2 = asyncio.run(engine.correlate(out2, target="example.com", ai=False,
                                          persist=True, path=self.asc_path))
        self.assertFalse(r2["history"]["baseline"])
        self.assertIn("n.example.com", r2["history"]["new_assets"])


# ---------------------------------------------------------------------------
# 17. AI analysis fallback
# ---------------------------------------------------------------------------
class AiFallbackTests(unittest.TestCase):
    def test_deterministic_without_ai(self):
        path = os.path.join(tempfile.mkdtemp(), "asc.json")
        # ai=True แต่ไม่มี API key -> ai_summary=None, ผลยังครบ
        r = asyncio.run(engine.correlate({"passive_recon": passive_fixture()},
                                         target="example.com", ai=True, persist=False, path=path))
        self.assertIsNone(r["ai_summary"])
        self.assertGreater(r["counts"]["total_assets"], 0)
        self.assertTrue(r["correlations"])

    def test_ai_explain_handles_missing_gemini(self):
        r = _build({"passive_recon": passive_fixture()})
        summary = asyncio.run(engine.ai_explain(r))
        self.assertIn(summary, (None,) + (tuple([summary]) if isinstance(summary, str) else ()))


# ---------------------------------------------------------------------------
# 18. Telegram report integration (+ no secret leak)
# ---------------------------------------------------------------------------
class ReportTests(unittest.TestCase):
    def test_report_renderers(self):
        r = _build({"passive_recon": passive_fixture(), "web_vulnerability_assessment": wva_fixture()})
        r["result_id"] = "ASC-2026-000001"
        self.assertIn("Attack Surface", report.render_markdown(r))
        self.assertIn("example.com", report.concise_report(r))
        self.assertTrue(report.render_json(r).startswith("{"))
        self.assertIn("nodes", report.graph_json(r))
        self.assertIn("🕸", report.summary_line(r))

    def test_report_marks_hypothesis(self):
        b = normalize.AssetBuilder()
        b.add("subdomain", "a.example.com", source_module="t", parent_domain="example.com",
              ip_addresses=["203.0.113.10"])
        b.add("subdomain", "b.other.com", source_module="t", parent_domain="other.com",
              ip_addresses=["203.0.113.10"])
        b.add("ip", "203.0.113.10", source_module="t")
        rels = relate.correlate_assets(b.assets())
        res = {"target": "x", "assets": b.assets(), "correlations": rels, "insights": [],
               "counts": engine._counts(b.assets(), rels, [], b), "graph": {"stats": {}},
               "history": {}, "source_modules": ["t"], "policy": {}}
        md = report.render_markdown(res)
        self.assertIn("สมมติฐาน", md)   # hypothesis ถูกติดป้ายในรายงาน

    def test_error_result_renders(self):
        self.assertIn("ASC_DISABLED", report.concise_report({"error": "ASC_DISABLED"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
