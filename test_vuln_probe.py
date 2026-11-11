# -*- coding: utf-8 -*-
"""เทสต์ vuln_probe — probes (pure analyzers) + store + engine (gate/fetch stubbed)"""

import os
import asyncio
import tempfile
import unittest

from vuln_probe import probes, store, engine


class ProbeAnalyzerTests(unittest.TestCase):
    def test_reflection_dangerous_html(self):
        m = "sombraABCD1234"
        ind = probes.analyze_reflection(m, f"<div><{m}></div>", "text/html")
        self.assertIsNotNone(ind)
        self.assertEqual(ind["category"], "reflected_xss")

    def test_reflection_encoded_is_safe_lowsev(self):
        m = "sombraABCD1234"
        # สะท้อนแบบธรรมดาไม่มีสัญลักษณ์อันตรายล้อม -> ไม่ใช่ xss ตรง ๆ
        ind = probes.analyze_reflection(m, f"<p>hello {m} world</p>", "text/html")
        self.assertEqual(ind["category"], "input_reflection")

    def test_reflection_absent(self):
        self.assertIsNone(probes.analyze_reflection("marker", "nothing here", "text/html"))

    def test_sql_error_new_signature(self):
        base = "<html>normal</html>"
        probe = "<html>You have an error in your SQL syntax; near ...</html>"
        ind = probes.analyze_sql_error(base, probe)
        self.assertIsNotNone(ind)
        self.assertEqual(ind["severity"], "HIGH")

    def test_sql_error_preexisting_not_flagged(self):
        both = "You have an error in your SQL syntax"
        self.assertIsNone(probes.analyze_sql_error(both, both))

    def test_ssti_eval(self):
        ind = probes.analyze_ssti("t12ab", "49", "result: t12ab49 done")
        self.assertIsNotNone(ind)
        self.assertEqual(ind["category"], "ssti")
        self.assertIsNone(probes.analyze_ssti("t12ab", "49", "result: t12ab{{7*7}}"))

    def test_open_redirect(self):
        ind = probes.analyze_open_redirect(302, "https://oob.sombra-probe.invalid/x",
                                           "oob.sombra-probe.invalid")
        self.assertIsNotNone(ind)
        self.assertIsNone(probes.analyze_open_redirect(200, "https://oob.x/", "oob.x"))
        self.assertIsNone(probes.analyze_open_redirect(302, "/local/path", "oob.x"))

    def test_cors(self):
        hi = probes.analyze_cors("https://evil.x", "https://evil.x", "true")
        self.assertEqual(hi["severity"], "HIGH")
        lo = probes.analyze_cors("https://evil.x", "https://evil.x", "")
        self.assertEqual(lo["severity"], "LOW")
        self.assertIsNone(probes.analyze_cors("https://evil.x", "https://trusted.x", "true"))

    def test_takeover(self):
        ind = probes.analyze_takeover(404, "There isn't a GitHub Pages site here.")
        self.assertIsNotNone(ind)
        self.assertEqual(ind["category"], "subdomain_takeover")
        self.assertIsNone(probes.analyze_takeover(200, "normal site"))

    def test_marker_unique(self):
        self.assertNotEqual(probes.new_marker(), probes.new_marker())


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "vprobe.json")

    def test_run_lifecycle(self):
        rec = store.create_run(5, "https://x.com", 1, self.path)
        self.assertEqual(rec["id"], 1)
        store.update_run(1, lambda r: r.__setitem__("status", "completed"), self.path)
        self.assertEqual(store.get_run(1, self.path)["status"], "completed")

    def test_policy_guard(self):
        with self.assertRaises(ValueError):
            store.set_policy("nope", 1, self.path)
        store.set_policy("param_name", "search", self.path)
        self.assertEqual(store.get_policy(self.path)["param_name"], "search")


class EngineGateTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "vprobe.json")

    def test_denied_when_scope_blocks(self):
        async def run():
            if not engine._HAS_DEPS:
                self.skipTest("security_testing/scope_policy not importable")
            class _D:
                allowed = False
                reason = "TARGET_OUT_OF_SCOPE"
            orig = engine.evaluate_target
            engine.evaluate_target = lambda pid, t: _D()
            try:
                return await engine.run_probe(5, "https://evil.test", 1, path=self.path)
            finally:
                engine.evaluate_target = orig
        run_rec = asyncio.run(run())
        self.assertEqual(run_rec["status"], "denied")
        self.assertIn("SCOPE_DENY", run_rec["denied_reason"])

    def test_disabled_policy(self):
        store.set_policy("enabled", False, self.path)
        rec = asyncio.run(engine.run_probe(5, "https://x.com", 1, path=self.path))
        self.assertEqual(rec["status"], "failed")
        self.assertEqual(rec["denied_reason"], "VULN_PROBE_DISABLED")

    def test_completed_with_stubbed_fetch(self):
        async def run():
            if not engine._HAS_DEPS:
                self.skipTest("deps not importable")
            # stub gate ให้ allow + normalize/endpoint + fetch
            class _A:
                allowed = True
                reason = "OK"
            class _N:
                target_type = "URL"
                domain = "x.com"
                raw = "https://x.com/"
            orig_eval = engine.evaluate_target
            orig_norm = engine.normalize_target
            orig_ep = engine._endpoint_from_target
            engine.evaluate_target = lambda pid, t: _A()
            engine.normalize_target = lambda t: _N()
            engine._endpoint_from_target = lambda n: ({"scheme": "https", "host": "x.com",
                                                       "port": 443, "path": "/"}, None)
            async def fake_fetch(program_id, endpoint, host, ttype, headers=None):
                p = endpoint["path"]
                if "%27" in p:   # probe ที่ใส่ quote -> error-based signature
                    return {"status": 200, "headers": {"content-type": "text/html"},
                            "body": "You have an error in your SQL syntax near", "location": ""}, None
                return {"status": 200, "headers": {"content-type": "text/html"},
                        "body": "<html>clean</html>", "location": ""}, None
            orig_f = engine._fetch
            engine._fetch = fake_fetch
            try:
                return await engine.run_probe(5, "https://x.com", 1,
                                              checks=["sqli", "takeover"], path=self.path)
            finally:
                engine.evaluate_target = orig_eval
                engine.normalize_target = orig_norm
                engine._endpoint_from_target = orig_ep
                engine._fetch = orig_f
        rec = asyncio.run(run())
        self.assertEqual(rec["status"], "completed")
        self.assertTrue(any(i["category"] == "sql_injection" for i in rec["indicators"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
