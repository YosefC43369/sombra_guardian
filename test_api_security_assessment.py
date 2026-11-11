# -*- coding: utf-8 -*-
"""เทสต์ api_security_assessment — spec parsing, analyzers, engine (gate/fetch stubbed)"""

import os
import json
import asyncio
import tempfile
import unittest

from api_security_assessment import spec, analyzers, store, engine


# ---------------------------------------------------------------------------
# spec parsing
# ---------------------------------------------------------------------------
class SpecTests(unittest.TestCase):
    def test_openapi3_json(self):
        resp_schema = {"properties": {"password": {}, "name": {}}}
        req_schema = {"properties": {"is_admin": {}, "name": {}}}
        get_op = {"security": [{"bearer": []}],
                  "parameters": [{"name": "id", "in": "path", "required": True}],
                  "responses": {"200": {"content": {"application/json": {"schema": resp_schema}}}}}
        post_op = {"requestBody": {"content": {"application/json": {"schema": req_schema}}}}
        doc = {"openapi": "3.0.0", "info": {"title": "T", "version": "1.0"},
               "paths": {"/users/{id}": {"get": get_op, "post": post_op},
                         "/admin/config": {"get": {}}}}
        r = spec.from_spec(json.dumps(doc))
        self.assertTrue(r["ok"])
        self.assertEqual(r["kind"], "openapi3")
        paths = {(e["method"], e["path"]) for e in r["endpoints"]}
        self.assertIn(("GET", "/users/{id}"), paths)
        self.assertIn(("POST", "/users/{id}"), paths)
        getu = next(e for e in r["endpoints"] if e["method"] == "GET" and e["path"] == "/users/{id}")
        self.assertEqual(getu["auth_required"], True)
        self.assertIn("password", getu["response_fields"])
        postu = next(e for e in r["endpoints"] if e["method"] == "POST")
        self.assertIn("is_admin", postu["request_fields"])
        admin = next(e for e in r["endpoints"] if "admin" in e["path"])
        self.assertTrue(admin["admin"])

    def test_openapi_yaml(self):
        y = ("swagger: '2.0'\ninfo:\n  title: Y\n  version: '2'\n"
             "paths:\n  /ping:\n    get:\n      responses:\n        '200': {}\n")
        r = spec.from_spec(y)
        self.assertTrue(r["ok"])
        self.assertEqual(r["kind"], "openapi2")
        self.assertTrue(any(e["path"] == "/ping" for e in r["endpoints"]))

    def test_postman(self):
        doc = {"info": {"_postman_id": "x", "name": "C"},
               "item": [{"name": "g", "request": {"method": "GET",
                    "url": {"raw": "https://api.x/v1/orders/1", "path": ["v1", "orders", "1"]},
                    "header": [{"key": "Authorization", "value": "Bearer x"}]}}]}
        r = spec.from_spec(json.dumps(doc))
        self.assertTrue(r["ok"])
        self.assertEqual(r["kind"], "postman")
        e = r["endpoints"][0]
        self.assertEqual(e["method"], "GET")
        self.assertEqual(e["auth_required"], True)

    def test_dedupe_and_classify(self):
        eps = spec.from_endpoint_list([{"path": "/a"}, {"path": "/a"},
                                       {"path": "/admin/x"}, {"path": "/orders/{id}"}])
        self.assertEqual(len([e for e in eps if e["path"] == "/a"]), 1)
        cls = spec.classify_endpoints(eps)
        self.assertTrue(cls["admin"])
        self.assertTrue(cls["with_object_id"])

    def test_bad_spec(self):
        self.assertFalse(spec.from_spec("not valid at all {{{")["ok"])


# ---------------------------------------------------------------------------
# analyzers
# ---------------------------------------------------------------------------
class AnalyzerTests(unittest.TestCase):
    def _jwt(self, header, payload):
        import base64
        def enc(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
        return f"{enc(header)}.{enc(payload)}.sig"

    def test_jwt_alg_none(self):
        info = analyzers.inspect_jwt(self._jwt({"alg": "none"}, {"sub": "1"}))
        self.assertEqual(info["alg"], "NONE")
        self.assertTrue(any("alg=none" in i for i in info["issues"]))
        o = analyzers.jwt_observation(info)
        self.assertEqual(o["severity_hint"], "HIGH")
        self.assertEqual(o["state"], "CONFIRMED")

    def test_jwt_missing_exp(self):
        info = analyzers.inspect_jwt(self._jwt({"alg": "HS256"}, {"sub": "1"}))
        self.assertFalse(info["has_exp"])

    def test_auth_enforcement(self):
        ep = {"method": "GET", "path": "/admin/users", "auth_required": True,
              "sensitive": True, "admin": True}
        o = analyzers.auth_enforcement(ep, 200, '{"users":[...]}')
        self.assertIsNotNone(o)
        self.assertEqual(o["severity_hint"], "HIGH")
        self.assertIsNone(analyzers.auth_enforcement(ep, 401, ""))

    def test_authz_bola(self):
        o = analyzers.authz_compare("/orders/{id}", "GET", 200, '{"order":1,"total":99}',
                                    200, '{"order":1,"total":99}', kind="BOLA")
        self.assertEqual(o["severity_hint"], "HIGH")
        self.assertEqual(o["rule"], "bola")
        # บัญชีอื่นถูกปฏิเสธ -> ไม่มี finding
        self.assertIsNone(analyzers.authz_compare("/orders/{id}", "GET", 200, "x", 403, "", "BOLA"))

    def test_graphql_introspection(self):
        o = analyzers.graphql_introspection({"data": {"__schema": {"types": [{"name": "Q"}]}}})
        self.assertIsNotNone(o)
        self.assertEqual(o["state"], "CONFIRMED")
        self.assertIsNone(analyzers.graphql_introspection({"data": {"user": {}}}))

    def test_mass_assignment_static(self):
        o = analyzers.mass_assignment_static(["name", "is_admin", "role"])
        self.assertIsNotNone(o)
        self.assertIn("is_admin", o["evidence"])
        self.assertIsNone(analyzers.mass_assignment_static(["name", "email"]))

    def test_excessive_data(self):
        o = analyzers.excessive_data(["id", "name", "password_hash"])
        self.assertIsNotNone(o)

    def test_rate_limit_absent(self):
        self.assertIsNotNone(analyzers.rate_limit_headers({"Server": "nginx"}))
        self.assertIsNone(analyzers.rate_limit_headers({"X-RateLimit-Limit": "100"}))

    def test_server_disclosure(self):
        self.assertIsNotNone(analyzers.server_disclosure({"X-Powered-By": "PHP/8.2"}))


# ---------------------------------------------------------------------------
# engine (gate + fetch stubbed)
# ---------------------------------------------------------------------------
class EngineTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "api.json")

    def test_denied_scope(self):
        async def run():
            if not engine._HAS_DEPS:
                self.skipTest("deps unavailable")
            class _D: allowed = False; reason = "TARGET_OUT_OF_SCOPE"
            o = engine.evaluate_target
            engine.evaluate_target = lambda p, t: _D()
            try:
                return await engine.run_assessment(5, "https://api.evil.test", 1, path=self.path)
            finally:
                engine.evaluate_target = o
        a = asyncio.run(run())
        self.assertEqual(a["status"], "denied")

    def test_completed_detects(self):
        async def run():
            if not engine._HAS_DEPS:
                self.skipTest("deps unavailable")
            class _A: allowed = True; reason = "OK"
            class _N: target_type = "URL"; domain = "api.x"; raw = "https://api.x/"; scheme = "https"
            openapi = {"openapi": "3.0.0", "info": {"title": "T"},
                       "paths": {"/admin/users": {"get": {"security": [{"b": []}]}}}}
            o1, o2, o3, o4 = (engine.evaluate_target, engine.normalize_target,
                              engine._endpoint_from_target, engine._api_fetch)
            engine.evaluate_target = lambda p, t: _A()
            engine.normalize_target = lambda t: _N()
            engine._endpoint_from_target = lambda n: ({"scheme": "https", "host": "api.x",
                                                       "port": 443, "path": "/"}, None)
            async def fake_fetch(pid, ep, host, tt, p, method="GET", headers=None,
                                 json_body=None, allow_state_changing=False):
                # /admin/users ตอบ 200 โดยไม่มี token -> missing auth
                return {"status": 200, "headers": {"Server": "nginx"},
                        "body": '{"users":["a","b"]}', "json": None, "location": ""}, None
            engine._api_fetch = fake_fetch
            try:
                return await engine.run_assessment(
                    5, "https://api.x", 1, spec_text=json.dumps(openapi),
                    categories=["authentication", "misconfiguration", "info_disclosure"],
                    path=self.path)
            finally:
                (engine.evaluate_target, engine.normalize_target,
                 engine._endpoint_from_target, engine._api_fetch) = o1, o2, o3, o4
        a = asyncio.run(run())
        self.assertEqual(a["status"], "completed")
        self.assertGreaterEqual(a["endpoints_analyzed"], 1)
        cats = {f["category"] for f in a["findings"]}
        self.assertIn("authentication", cats)        # missing auth on /admin/users
        self.assertIn("misconfiguration", cats)      # missing security headers

    def test_cancellation(self):
        async def run():
            if not engine._HAS_DEPS:
                self.skipTest("deps unavailable")
            class _A: allowed = True; reason = "OK"
            class _N: target_type = "URL"; domain = "api.x"; raw = "https://api.x/"; scheme = "https"
            o1, o2, o3, o4 = (engine.evaluate_target, engine.normalize_target,
                              engine._endpoint_from_target, engine._api_fetch)
            engine.evaluate_target = lambda p, t: _A()
            engine.normalize_target = lambda t: _N()
            engine._endpoint_from_target = lambda n: ({"scheme": "https", "host": "api.x",
                                                       "port": 443, "path": "/"}, None)
            async def fake_fetch(pid, ep, host, tt, p, **kw):
                store.request_cancel(1, self.path)
                return {"status": 200, "headers": {}, "body": "", "json": None, "location": ""}, None
            engine._api_fetch = fake_fetch
            openapi = {"openapi": "3.0.0", "info": {},
                       "paths": {"/a": {"get": {}}, "/b": {"get": {}}, "/c": {"get": {}}}}
            try:
                return await engine.run_assessment(5, "https://api.x", 1,
                    spec_text=json.dumps(openapi), categories=["authentication"], path=self.path)
            finally:
                (engine.evaluate_target, engine.normalize_target,
                 engine._endpoint_from_target, engine._api_fetch) = o1, o2, o3, o4
        a = asyncio.run(run())
        self.assertEqual(a["status"], "cancelled")

    def test_disabled(self):
        store.set_policy("enabled", False, self.path)
        a = asyncio.run(engine.run_assessment(5, "https://api.x", 1, path=self.path))
        self.assertEqual(a["status"], "failed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
