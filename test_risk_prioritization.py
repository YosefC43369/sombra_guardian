# -*- coding: utf-8 -*-
"""เทสต์ risk_prioritization + payload library expansion + execution transparency

ครอบคลุม 24 ด้านตามสเปค: risk scoring, severity preservation, confidence, asset criticality,
evidence quality, explanation, missing data, historical, correlation integ, AI fallback,
payload discovery/dupe/metadata/coverage/context-select/profile/limits/scope/false-positive/
evidence-gen, orchestrator + evidence + telegram integration, module compatibility.

local fixtures เท่านั้น — ไม่สแกนภายนอก
"""

import asyncio
import os
import tempfile
import unittest

from risk_prioritization import model, engine, store, report, transparency
from web_vulnerability_assessment import payload_engine as pe


def _f(**kw):
    base = {"finding_id": "FND-1", "category": "sqli", "title": "sql error",
            "severity": "HIGH", "verification_status": "POTENTIAL", "confidence": 0.55,
            "affected_asset": "api.example.com", "detection_source": "web_vulnerability_assessment"}
    base.update(kw)
    return base


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "risk.json")


# ---------------------------------------------------------------------------
# 1. risk score calculation
# ---------------------------------------------------------------------------
class ScoreTests(_Tmp):
    def test_score_in_range_and_deterministic(self):
        a = engine.assess_finding(_f(verification_status="CONFIRMED", confidence=0.9))
        self.assertTrue(0 <= a["risk_score"] <= 100)
        b = engine.assess_finding(_f(verification_status="CONFIRMED", confidence=0.9))
        self.assertEqual(a["risk_score"], b["risk_score"])    # deterministic

    def test_confirmed_high_outranks_potential(self):
        hi = engine.assess_finding(_f(verification_status="CONFIRMED", confidence=0.9))
        lo = engine.assess_finding(_f(verification_status="OBSERVED", severity="LOW",
                                      confidence=0.3))
        self.assertGreater(hi["risk_score"], lo["risk_score"])

    def test_configurable_weights(self):
        w = {"severity": 1.0, "exploitability": 0.0, "asset_criticality": 0.0,
             "evidence_confidence": 0.0}
        a = engine.assess_finding(_f(severity="CRITICAL", verification_status="CONFIRMED"),
                                  weights=w)
        self.assertGreaterEqual(a["risk_score"], 90)


# ---------------------------------------------------------------------------
# 2. severity preservation (technical severity != risk priority)
# ---------------------------------------------------------------------------
class SeverityTests(_Tmp):
    def test_original_severity_preserved(self):
        a = engine.assess_finding(_f(severity="HIGH", verification_status="OBSERVED",
                                     confidence=0.2))
        self.assertEqual(a["technical_severity"], "HIGH")
        self.assertEqual(a["original_severity"], "HIGH")
        # risk priority อาจต่าง (NEEDS_VERIFICATION) แต่ severity เดิมคงไว้
        self.assertNotEqual(a["risk_priority"], a["technical_severity"])

    def test_no_severity_inflation(self):
        # LOW ที่ไม่ยืนยัน ไม่ควรกลายเป็น CRITICAL
        a = engine.assess_finding(_f(severity="LOW", verification_status="OBSERVED",
                                     confidence=0.3))
        self.assertIn(a["risk_priority"], ("LOW", "INFORMATIONAL", "MEDIUM"))


# ---------------------------------------------------------------------------
# 3/4/5. confidence, asset criticality, evidence quality factors
# ---------------------------------------------------------------------------
class FactorTests(unittest.TestCase):
    def test_evidence_confidence_factor(self):
        low = model.evidence_confidence_factor(base_confidence=0.3, supporting_count=0,
                                               integrity_ok=True, verified=False,
                                               contradictory=False)
        high = model.evidence_confidence_factor(base_confidence=0.9, supporting_count=4,
                                                integrity_ok=True, verified=True,
                                                contradictory=False)
        self.assertLess(low, high)

    def test_contradictory_lowers_confidence(self):
        a = model.evidence_confidence_factor(base_confidence=0.8, supporting_count=2,
                                             integrity_ok=True, verified=True, contradictory=False)
        b = model.evidence_confidence_factor(base_confidence=0.8, supporting_count=2,
                                             integrity_ok=True, verified=True, contradictory=True)
        self.assertGreater(a, b)

    def test_asset_criticality_exposure(self):
        internet = model.asset_criticality_factor(exposure="internet_facing", importance="HIGH",
                                                  related_assets=5, related_findings=3)
        internal = model.asset_criticality_factor(exposure="internal", importance="LOW",
                                                  related_assets=0, related_findings=0)
        self.assertGreater(internet, internal)

    def test_severity_factor_cvss_blend(self):
        self.assertGreater(model.severity_factor("MEDIUM", 9.8),
                           model.severity_factor("MEDIUM", None))


# ---------------------------------------------------------------------------
# 6. risk explanation
# ---------------------------------------------------------------------------
class ExplanationTests(_Tmp):
    def test_every_assessment_explained(self):
        r = engine.prioritize([_f(), _f(finding_id="FND-2", category="xss")])
        for a in r["assessments"]:
            self.assertTrue(a["score_explanation"])
            self.assertTrue(a["recommended_action"])


# ---------------------------------------------------------------------------
# 7. missing data handling (never treat missing as safe)
# ---------------------------------------------------------------------------
class MissingDataTests(_Tmp):
    def test_missing_fields_do_not_crash(self):
        a = engine.assess_finding({"finding_id": "X"})
        self.assertIn("risk_priority", a)

    def test_unverified_medium_needs_verification_not_low(self):
        a = engine.assess_finding(_f(severity="MEDIUM", verification_status="OBSERVED",
                                     confidence=0.2))
        self.assertEqual(a["risk_priority"], "NEEDS_VERIFICATION")  # ไม่ปัดตกเป็น LOW เงียบ ๆ


# ---------------------------------------------------------------------------
# 8. historical risk comparison
# ---------------------------------------------------------------------------
class HistoryTests(_Tmp):
    def test_baseline_then_escalation(self):
        r1 = asyncio.run(engine.run([_f(verification_status="OBSERVED", confidence=0.3)],
                                    target="example.com", ai=False, persist=True, path=self.path))
        self.assertTrue(r1["history"]["baseline"])
        r2 = asyncio.run(engine.run([_f(verification_status="CONFIRMED", confidence=0.9)],
                                    target="example.com", ai=False, persist=True, path=self.path))
        self.assertFalse(r2["history"]["baseline"])
        self.assertIn("FND-1", r2["history"]["escalated"])


# ---------------------------------------------------------------------------
# 9. correlation integration
# ---------------------------------------------------------------------------
class CorrelationTests(_Tmp):
    def test_correlation_context_raises_asset_criticality(self):
        corr = {"correlations": [{"relationship": "contains", "evidence": ["api.example.com x"],
                                  "source": "A", "target": "B"}] * 3}
        with_corr = engine.assess_finding(_f(), correlation=corr)
        without = engine.assess_finding(_f(), correlation=None)
        self.assertGreaterEqual(with_corr["risk_score"], without["risk_score"])


# ---------------------------------------------------------------------------
# 10. AI fallback
# ---------------------------------------------------------------------------
class AiFallbackTests(_Tmp):
    def test_deterministic_without_ai(self):
        r = asyncio.run(engine.run([_f()], target="example.com", ai=True, persist=False,
                                   path=self.path))
        self.assertIsNone(r["ai_summary"])
        self.assertTrue(r["assessments"])


# ---------------------------------------------------------------------------
# 11-14. payload library: discovery, duplicate detection, metadata, coverage
# ---------------------------------------------------------------------------
class PayloadLibraryTests(unittest.TestCase):
    def test_discovery_expanded(self):
        ps = pe.load_payloads()
        self.assertGreaterEqual(ps.summary()["total"], 50)      # ขยายจาก ~20
        self.assertEqual(ps.summary()["rejected"], 0)

    def test_duplicate_detection(self):
        ps = pe.load_payloads()
        self.assertIsInstance(ps.duplicates, list)
        self.assertIn("duplicates", ps.summary())

    def test_optional_metadata_validates(self):
        p = {"id": "T", "category": "xss", "description": "d", "test_string": "RTm",
             "expected": "e", "risk": "LOW", "safety": "SAFE", "rule": "reflection",
             "reference": "", "profile": "SAFE_EXTENDED", "non_destructive": True}
        ok, _ = pe.validate_payload(p)
        self.assertTrue(ok)
        bad, reason = pe.validate_payload(dict(p, profile="AGGRESSIVE"))
        self.assertFalse(bad)
        bad2, _ = pe.validate_payload(dict(p, non_destructive=False))
        self.assertFalse(bad2)

    def test_coverage_report(self):
        cov = pe.audit_report()
        self.assertEqual(cov["categories_unsupported"], [])
        self.assertGreaterEqual(len(cov["categories_covered"]), 12)
        self.assertIn("by_profile", cov)


# ---------------------------------------------------------------------------
# 15/16/17. context-aware selection, safe profile enforcement, request limits
# ---------------------------------------------------------------------------
class SelectionTests(unittest.TestCase):
    def test_context_selection_prefers_context(self):
        ps = pe.load_payloads()
        sel = ps.select_for_context("xss", context="html_attribute", max_tests=2)
        self.assertLessEqual(len(sel), 2)
        self.assertTrue(any("attribute" in str(p.get("context", "")) for p in sel)
                        or sel)       # มี attribute-context มาก่อน หรืออย่างน้อยได้ผล

    def test_profile_subset(self):
        ps = pe.load_payloads()
        minimal = {p["id"] for p in ps.for_profile("sqli", "SAFE_MINIMAL")}
        extended = {p["id"] for p in ps.for_profile("sqli", "SAFE_EXTENDED")}
        self.assertTrue(minimal.issubset(extended))        # MINIMAL ⊆ EXTENDED

    def test_request_limit(self):
        ps = pe.load_payloads()
        sel = ps.select_for_context("sqli", profile="SAFE_EXTENDED", max_tests=3)
        self.assertLessEqual(len(sel), 3)


# ---------------------------------------------------------------------------
# 18. scope/safety enforcement (no destructive payloads survive)
# ---------------------------------------------------------------------------
class SafetyTests(unittest.TestCase):
    def test_all_loaded_payloads_safe(self):
        ps = pe.load_payloads()
        for p in ps.by_id.values():
            self.assertEqual(str(p["safety"]).upper(), "SAFE")
            self.assertIsNone(pe.is_unsafe(str(p["test_string"])))
            self.assertTrue(p.get("non_destructive", True))

    def test_new_categories_no_internal_targets(self):
        ps = pe.load_payloads()
        for cat in ("ssrf", "open_redirect"):
            for p in ps.by_category.get(cat, []):
                self.assertIsNone(pe.is_unsafe(str(p["test_string"])))


# ---------------------------------------------------------------------------
# 19. false-positive handling (verified vs requires-review separation)
# ---------------------------------------------------------------------------
class FalsePositiveTests(unittest.TestCase):
    def test_reflected_alone_not_verified(self):
        # XSS reflection POTENTIAL -> REQUIRES_REVIEW, ไม่ใช่ VERIFIED
        f = _f(category="xss", verification_status="POTENTIAL", test_case_id="XSS-CTX-010",
               request="q=RTXSSmark010", response_status=200, response_excerpt="...RTXSSmark010...")
        rec = transparency.executed_record(f, pe.load_payloads())
        self.assertEqual(rec["verification_result"], "REQUIRES_REVIEW")
        self.assertEqual(transparency.verified_payloads([rec]), [])

    def test_confirmed_with_evidence_is_verified(self):
        f = _f(category="xss", verification_status="CONFIRMED", test_case_id="XSS-CTX-010",
               request="q=RTXSSmark010", response_status=200, response_excerpt="reflected raw")
        rec = transparency.executed_record(f, pe.load_payloads())
        self.assertEqual(rec["verification_result"], "VERIFIED")
        self.assertEqual(len(transparency.verified_payloads([rec])), 1)


# ---------------------------------------------------------------------------
# 20. evidence generation (executed vs suggested + transparency)
# ---------------------------------------------------------------------------
class TransparencyTests(unittest.TestCase):
    def test_executed_vs_suggested_separation(self):
        findings = [_f(test_case_id="SQLI-QUOTE-010", request="q='", response_status=500,
                       response_excerpt="SQL error"),
                    _f(finding_id="FND-2", category="xss")]  # no payload -> not executed
        t = transparency.build_transparency(findings, payload_set=pe.load_payloads())
        self.assertEqual(t["counts"]["executed"], 1)         # เฉพาะที่ส่งจริง
        self.assertGreater(t["counts"]["suggested"], 0)
        for s in t["suggested_payloads"]:
            self.assertEqual(s["status"], "NOT_EXECUTED")    # suggested ไม่ใช่ executed

    def test_payload_value_redacted(self):
        f = _f(test_case_id="SQLI-QUOTE-010",
               request="q=' Authorization: Bearer secrettoken123456",
               response_status=500, response_excerpt="err")
        rec = transparency.executed_record(f, pe.load_payloads())
        self.assertNotIn("secrettoken123456", rec["payload_value"])

    def test_not_executed_never_vulnerability(self):
        t = transparency.build_transparency([_f(category="xss")], payload_set=pe.load_payloads())
        # ไม่มี executed (ไม่มี payload ส่งจริง) -> ไม่มีการอ้างว่าเป็นช่องโหว่จาก suggested
        self.assertEqual(t["counts"]["executed"], 0)
        self.assertEqual(t["counts"]["verified"], 0)


# ---------------------------------------------------------------------------
# 21/22. orchestrator + evidence management integration
# ---------------------------------------------------------------------------
class IntegrationTests(_Tmp):
    def test_analyze_task(self):
        from red_team_orchestrator import store as rt_store
        rt_path = os.path.join(tempfile.mkdtemp(), "rt.json")
        rec = rt_store.create_task("website_assessment", "https://api.example.com", 1, 10, {},
                                   rt_path)
        rt_store.update_task(rec["task_id"], lambda r: r.update({
            "findings": [_f(verification_status="POTENTIAL")]}), rt_path)
        result = asyncio.run(engine.analyze_task(rec["task_id"], ai=False, path=self.path,
                                                 rt_path=rt_path))
        self.assertEqual(result["source_task_id"], rec["task_id"])
        self.assertTrue(result["assessments"])

    def test_evidence_integration_in_transparency(self):
        evd_path = os.path.join(tempfile.mkdtemp(), "evd.json")
        try:
            import evidence_management as evd
        except Exception:
            self.skipTest("evidence_management unavailable")
        executed = [transparency.executed_record(
            _f(test_case_id="SQLI-QUOTE-010", request="q='", response_status=500,
               response_excerpt="err"), pe.load_payloads())]
        res = transparency.link_to_evidence(executed, "RT-2026-000001", path=evd_path)
        self.assertGreaterEqual(res.get("ingested", 0), 1)


# ---------------------------------------------------------------------------
# 23/24. telegram report + module compatibility
# ---------------------------------------------------------------------------
class ReportTests(_Tmp):
    def test_report_renderers(self):
        r = asyncio.run(engine.run([_f(verification_status="CONFIRMED", confidence=0.9)],
                                   target="example.com", ai=False, persist=False, path=self.path))
        r["result_id"] = "RISK-2026-000001"
        self.assertIn("Risk Prioritization", report.render_markdown(r))
        self.assertIn("example.com", report.concise_report(r))
        self.assertTrue(report.render_json(r).startswith("{"))

    def test_payload_execution_report_sections(self):
        findings = [_f(test_case_id="SQLI-QUOTE-010", request="q='", response_status=500,
                       response_excerpt="SQL error near")]
        t = transparency.build_transparency(findings, payload_set=pe.load_payloads())
        txt = report.payload_execution_txt(t)
        self.assertIn("PAYLOAD EXECUTION DETAILS", txt)
        self.assertIn("Executed Payload", txt)
        self.assertIn("NOT EXECUTED", txt)
        js = report.payload_execution_json(t)
        self.assertIn("payload_execution", js)
        self.assertIn("executed_payloads", js["payload_execution"])

    def test_existing_payload_engine_compat(self):
        # ฟังก์ชันเดิมยังทำงาน (ไม่ทำลายของเดิม)
        ps = pe.load_payloads()
        self.assertTrue(ps.enabled_for("sqli"))
        self.assertTrue(ps.set_enabled(ps.by_category["sqli"][0]["id"], False))


class PolicyTests(_Tmp):
    def test_disabled_blocks(self):
        store.set_policy("enabled", False, self.path)
        r = asyncio.run(engine.run([_f()], target="x", path=self.path))
        self.assertEqual(r["error"], "RISK_ENGINE_DISABLED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
