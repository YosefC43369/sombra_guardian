# -*- coding: utf-8 -*-
"""เทสต์ red_team_orchestrator — registry, planning, scope, approval, run pipeline,
cancellation, timeout, failure isolation, normalization, dedup, redaction"""

import os
import asyncio
import tempfile
import unittest

from red_team_orchestrator import store, registry, engine, report


def _mr(name, status, findings=None, errors=None):
    return registry.module_result(name, status, findings=findings or [],
                                  errors=errors or [], started="s", completed="c")


class RegistryTests(unittest.TestCase):
    def test_modules_registered(self):
        for m in ("passive_recon", "vuln_probe", "web_vulnerability_assessment",
                  "api_security_assessment", "active_scan"):
            self.assertIn(m, registry.REGISTRY)

    def test_select_website_pipeline(self):
        mods = registry.select_modules("website_assessment")
        self.assertEqual(mods[0], "passive_recon")
        self.assertIn("web_vulnerability_assessment", mods)

    def test_select_requested_subset(self):
        mods = registry.select_modules("website_assessment", ["passive_recon"])
        self.assertEqual(mods, ["passive_recon"])

    def test_normalize_vuln_probe(self):
        run = {"status": "completed", "target": "https://x.com",
               "indicators": [{"category": "sqli", "severity": "HIGH", "confidence": 0.7,
                               "detail": "d", "evidence": "e"}]}
        fs = registry._norm_vuln_probe(run)
        self.assertEqual(fs[0]["detection_source"], "vuln_probe")
        self.assertEqual(fs[0]["severity"], "HIGH")
        self.assertEqual(fs[0]["verification_status"], "POTENTIAL")

    def test_normalize_wva_schema(self):
        a = {"findings": [{"category": "xss", "rule": "reflection", "severity": "HIGH",
                           "state": "POTENTIAL", "confidence": 0.6, "endpoint": "/s",
                           "detail": "d", "evidence": "<x>", "recommendation": "encode"}]}
        fs = registry._norm_findings_schema(a, "wva")
        self.assertEqual(fs[0]["verification_status"], "POTENTIAL")
        self.assertEqual(fs[0]["affected_asset"], "/s")
        self.assertEqual(fs[0]["remediation"], "encode")


class PlanningScopeTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "rt.json")
        self._orig = engine.simple_scope.program_for if engine._HAS_DEPS else None

    def tearDown(self):
        if engine._HAS_DEPS:
            engine.simple_scope.program_for = self._orig

    def test_plan_active_requires_program(self):
        if not engine._HAS_DEPS:
            self.skipTest("deps unavailable")
        engine.simple_scope.program_for = lambda url: None
        engine.normalize_target = lambda t: object()  # valid
        plan = engine.build_plan("website_assessment", "https://x.com", None, self.path)
        self.assertTrue(plan["authorization_required"])
        self.assertFalse(plan["scope_authorized"])

    def test_create_task_blocks_unauthorized_active(self):
        if not engine._HAS_DEPS:
            self.skipTest("deps unavailable")
        engine.simple_scope.program_for = lambda url: None
        engine.normalize_target = lambda t: object()
        rec = engine.create_task("website_assessment", "https://x.com", 1, 10, {}, path=self.path)
        self.assertEqual(rec["status"], "FAILED")
        self.assertIn("NOT_AUTHORIZED", rec["status_reason"])

    def test_create_task_authorized_awaits_approval(self):
        if not engine._HAS_DEPS:
            self.skipTest("deps unavailable")
        engine.simple_scope.program_for = lambda url: 42
        engine.normalize_target = lambda t: object()
        store.set_policy("require_approval", True, self.path)
        rec = engine.create_task("website_assessment", "https://x.com", 1, 10, {}, path=self.path)
        self.assertEqual(rec["status"], "AWAITING_APPROVAL")
        self.assertEqual(rec["plan"]["program_id"], 42)

    def test_passive_only_no_program_needed(self):
        if not engine._HAS_DEPS:
            self.skipTest("deps unavailable")
        engine.simple_scope.program_for = lambda url: None
        engine.normalize_target = lambda t: object()
        rec = engine.create_task("recon_only", "https://x.com", 1, 10, {}, path=self.path)
        self.assertIn(rec["status"], ("AWAITING_APPROVAL", "RUNNING"))

    def test_duplicate_task_prevented(self):
        if not engine._HAS_DEPS:
            self.skipTest("deps unavailable")
        engine.simple_scope.program_for = lambda url: 42
        engine.normalize_target = lambda t: object()
        engine.create_task("website_assessment", "https://x.com", 1, 10, {}, path=self.path)
        dup = engine.create_task("website_assessment", "https://x.com", 1, 10, {}, path=self.path)
        self.assertEqual(dup["error"], "DUPLICATE_ACTIVE_TASK")


class RunPipelineTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "rt.json")
        self._saved = {n: registry.REGISTRY[n].adapter for n in registry.REGISTRY}

    def tearDown(self):
        for n, a in self._saved.items():
            registry.REGISTRY[n].adapter = a

    def _mk_task(self, order, program=42):
        rec = store.create_task("website_assessment", "https://x.com", 1, 10, {}, self.path)
        store.update_task(rec["task_id"], lambda r: r.update(
            {"status": "RUNNING", "plan": {"execution_order": order, "program_id": program,
             "active_modules": [m for m in order if registry.REGISTRY[m].kind == "active"]}}),
            self.path)
        return rec["task_id"]

    def test_completed_aggregates_and_normalizes(self):
        async def ok_pr(ctx):
            return _mr("passive_recon", "completed",
                       findings=[registry.finding("passive_recon", "security_exposure",
                                                  "LOW", "t", "d")])
        async def ok_wva(ctx):
            return _mr("web_vulnerability_assessment", "completed",
                       findings=[registry.finding("wva", "xss", "HIGH", "x", "d",
                                                  verification="POTENTIAL")])
        registry.REGISTRY["passive_recon"].adapter = ok_pr
        registry.REGISTRY["web_vulnerability_assessment"].adapter = ok_wva
        tid = self._mk_task(["passive_recon", "web_vulnerability_assessment"])
        t = asyncio.run(engine.run_task(tid, path=self.path))
        self.assertEqual(t["status"], "COMPLETED")
        self.assertEqual(t["counts"]["total_findings"], 2)
        self.assertEqual(t["counts"]["HIGH"], 1)

    def test_partial_when_one_fails(self):
        async def ok_pr(ctx):
            return _mr("passive_recon", "completed",
                       findings=[registry.finding("passive_recon", "x", "LOW", "t", "d")])
        async def fail_wva(ctx):
            return _mr("web_vulnerability_assessment", "failed", errors=["boom"])
        registry.REGISTRY["passive_recon"].adapter = ok_pr
        registry.REGISTRY["web_vulnerability_assessment"].adapter = fail_wva
        tid = self._mk_task(["passive_recon", "web_vulnerability_assessment"])
        t = asyncio.run(engine.run_task(tid, path=self.path))
        self.assertEqual(t["status"], "PARTIALLY_COMPLETED")
        self.assertEqual(t["counts"]["modules_failed"], 1)

    def test_all_fail_is_failed(self):
        async def fail(ctx):
            return _mr("passive_recon", "failed", errors=["x"])
        registry.REGISTRY["passive_recon"].adapter = fail
        tid = self._mk_task(["passive_recon"])
        t = asyncio.run(engine.run_task(tid, path=self.path))
        self.assertEqual(t["status"], "FAILED")

    def test_timeout_isolated(self):
        store.set_policy("module_timeout", 1, self.path)
        async def slow(ctx):
            await asyncio.sleep(5)
            return _mr("passive_recon", "completed")
        async def ok_wva(ctx):
            return _mr("web_vulnerability_assessment", "completed",
                       findings=[registry.finding("wva", "xss", "HIGH", "x", "d")])
        registry.REGISTRY["passive_recon"].adapter = slow
        registry.REGISTRY["web_vulnerability_assessment"].adapter = ok_wva
        tid = self._mk_task(["passive_recon", "web_vulnerability_assessment"])
        t = asyncio.run(engine.run_task(tid, path=self.path))
        # passive timeout -> failed; wva ok -> partial, wva finding yังอยู่
        self.assertEqual(t["status"], "PARTIALLY_COMPLETED")
        self.assertTrue(any("TIMEOUT" in e for m in t["module_results"]
                            for e in m["errors"]))
        self.assertEqual(t["counts"]["HIGH"], 1)

    def test_cancellation_mid_pipeline(self):
        async def ok_then_cancel(ctx):
            # ยกเลิกหลังโมดูลแรก
            store.request_cancel(ctx_task[0], self.path)
            return _mr("passive_recon", "completed")
        tid = self._mk_task(["passive_recon", "web_vulnerability_assessment"])
        ctx_task = [tid]
        registry.REGISTRY["passive_recon"].adapter = ok_then_cancel
        t = asyncio.run(engine.run_task(tid, path=self.path))
        self.assertEqual(t["status"], "CANCELLED")

    def test_correlation_dedup(self):
        f1 = registry.finding("passive_recon", "c", "LOW", "same", "d", asset="a")
        f2 = registry.finding("wva", "c", "HIGH", "same", "d", asset="a")
        out = engine._correlate([f1, f2])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "HIGH")


class RedactionTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "rt.json")

    def test_token_redacted_in_task(self):
        rec = store.create_task("api_assessment", "https://api.x", 1, 10,
                                {"token": "secret123", "token_a": "aaa", "profile": "quick"},
                                self.path)
        self.assertEqual(rec["options"]["token"], "[REDACTED]")
        self.assertEqual(rec["options"]["token_a"], "[REDACTED]")
        self.assertEqual(rec["options"]["profile"], "quick")

    def test_report_has_no_raw_token(self):
        rec = store.create_task("api_assessment", "https://api.x", 1, 10,
                                {"token": "secret123"}, self.path)
        md = report.render_markdown(rec)
        js = report.render_json(rec)
        self.assertNotIn("secret123", md)
        self.assertNotIn("secret123", js)


if __name__ == "__main__":
    unittest.main(verbosity=2)
