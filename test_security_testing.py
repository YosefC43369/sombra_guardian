"""
test_security_testing.py — Phase 8 test suite.

Same isolation pattern as the other suites: a fresh temp SQLite file per
test, Programs/Authorizations/Scope built through scope_policy.py's real
API. Every network operation is mocked -- no test in this file resolves
a real hostname, opens a socket, or contacts a real host.

The most important tests here are the negative ones: that no DNS lookup,
TCP connection, or HTTP request happens unless evaluate_target() said
ALLOW first.
"""

import os
import ssl
import socket
import asyncio
import sqlite3
import tempfile
import unittest
from unittest import mock

import security
import scope_policy as sp
import security_testing as st


class _Tripwire(Exception):
    """Raised by a stub that must never be reached."""


class SecurityTestingTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = path
        security.DB_PATH = path
        sp.DB_PATH = path
        st.DB_PATH = path
        security.security_db_init()
        sp.scope_policy_db_init()
        st.security_testing_db_init()

    def tearDown(self):
        try:
            os.remove(self._db_path)
        except OSError:
            pass

    # ---- fixture helpers ----

    def _program(self, status="ACTIVE", chat_id=1):
        pid = sp.create_program(chat_id, "Acme BB", created_by=999)
        if status != "PAUSED":
            sp.set_program_status(pid, status, 999)
        return pid

    def _authorize(self, pid, approve=True, revoke=False,
                   effective_at=None, expires_at=None):
        aid = sp.import_authorization(
            pid, source_type="email", actor_user_id=999,
            source_reference="security@acme.test", authorization_reference="A-1",
            effective_at=effective_at, expires_at=expires_at,
        )
        sp.review_authorization(aid, approve=approve, reviewer_user_id=1000)
        if revoke:
            sp.revoke_authorization(aid, actor_user_id=999)
        return aid

    def _scoped_program(self, include="example.com", exclude=None,
                        include_type="DOMAIN", **kwargs):
        pid = self._program()
        self._authorize(pid, **kwargs)
        if include:
            sp.add_scope_rule(pid, "INCLUDE", include_type, include, actor_user_id=999)
        if exclude:
            sp.add_scope_rule(pid, "EXCLUDE", "DOMAIN", exclude, actor_user_id=999)
        return pid

    def _url_scoped_program(self, include="https://example.com/"):
        """scope_policy treats DOMAIN and URL rules as distinct: a DOMAIN
        rule does not cover a URL target. A program that will be scanned
        by URL therefore needs a URL rule, plus a DOMAIN rule so redirect
        hops to sibling hosts can be re-checked."""
        pid = self._program()
        self._authorize(pid)
        sp.add_scope_rule(pid, "INCLUDE", "URL", include, actor_user_id=999)
        sp.add_scope_rule(pid, "INCLUDE", "DOMAIN", "example.com", actor_user_id=999)
        return pid

    def _audit_actions(self):
        conn = sqlite3.connect(self._db_path)
        rows = [r[0] for r in conn.execute("SELECT action FROM audit_log ORDER BY id")]
        conn.close()
        return rows

    # ---- stubs ----

    def _no_network(self):
        """Patches every active primitive with a tripwire. Any test using
        this asserts that authorization failed *before* the network."""
        async def boom_resolve(host, port):
            raise _Tripwire(f"DNS lookup attempted for {host}")

        async def boom_fetch(endpoint):
            raise _Tripwire("HTTP request attempted")

        def boom_tls(host, ip, port):
            raise _Tripwire("TLS handshake attempted")

        return (
            mock.patch.object(st, "resolve_and_validate", boom_resolve),
            mock.patch.object(st, "_fetch_once", boom_fetch),
            mock.patch.object(st, "_tls_peek", boom_tls),
        )

    async def _run_expecting_no_network(self, **kwargs):
        patches = self._no_network()
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patches])
        return await st.run_security_check(**kwargs)

    def _ok_resolver(self, addresses=("93.184.216.34",)):
        async def resolver(host, port):
            return list(addresses), None
        return mock.patch.object(st, "resolve_and_validate", resolver)

    def _response(self, status_code=200, headers=None, set_cookies=None, url=None):
        return st.HttpResponse(
            status_code=status_code,
            headers={k.lower(): v for k, v in (headers or {}).items()},
            set_cookies=list(set_cookies or []),
            body_preview="",
            url=url or "https://example.com/",
        )

    def _fetcher(self, responses):
        """Serves canned responses in order, recording requested URLs."""
        calls = []

        async def fetch(endpoint):
            calls.append(st._endpoint_url(endpoint))
            if not responses:
                return None, "REQUEST_FAILED"
            item = responses.pop(0)
            if isinstance(item, str):
                return None, item
            return item, None

        return mock.patch.object(st, "_fetch_once", fetch), calls

    # ================= Authorization gate =================

    async def test_unknown_program_denied_without_touching_network(self):
        result = await self._run_expecting_no_network(
            program_id=999999, target="example.com", check_type="headers", actor=555)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "DENIED")
        self.assertEqual(result["reason"], "PROGRAM_NOT_FOUND")

    async def test_inactive_program_denied(self):
        pid = self._program(status="PAUSED")
        self._authorize(pid)
        sp.add_scope_rule(pid, "INCLUDE", "DOMAIN", "example.com", actor_user_id=999)
        result = await self._run_expecting_no_network(
            program_id=pid, target="example.com", check_type="headers", actor=555)
        self.assertEqual(result["reason"], "PROGRAM_NOT_ACTIVE")

    async def test_archived_program_denied(self):
        pid = self._scoped_program()
        sp.set_program_status(pid, "ARCHIVED", 999)
        result = await self._run_expecting_no_network(
            program_id=pid, target="example.com", check_type="headers", actor=555)
        self.assertEqual(result["reason"], "PROGRAM_NOT_ACTIVE")

    async def test_missing_authorization_denied(self):
        pid = self._program()
        sp.add_scope_rule(pid, "INCLUDE", "DOMAIN", "example.com", actor_user_id=999)
        result = await self._run_expecting_no_network(
            program_id=pid, target="example.com", check_type="headers", actor=555)
        self.assertEqual(result["reason"], "AUTHORIZATION_NOT_FOUND")

    async def test_unreviewed_authorization_denied(self):
        pid = self._program()
        sp.import_authorization(pid, source_type="email", actor_user_id=999,
                                source_reference="s@acme.test",
                                authorization_reference="A-1")
        sp.add_scope_rule(pid, "INCLUDE", "DOMAIN", "example.com", actor_user_id=999)
        result = await self._run_expecting_no_network(
            program_id=pid, target="example.com", check_type="headers", actor=555)
        self.assertEqual(result["reason"], "AUTHORIZATION_PENDING")

    async def test_rejected_authorization_denied(self):
        pid = self._scoped_program(approve=False)
        result = await self._run_expecting_no_network(
            program_id=pid, target="example.com", check_type="headers", actor=555)
        self.assertEqual(result["reason"], "AUTHORIZATION_REJECTED")

    async def test_revoked_authorization_denied(self):
        pid = self._scoped_program(revoke=True)
        result = await self._run_expecting_no_network(
            program_id=pid, target="example.com", check_type="headers", actor=555)
        self.assertEqual(result["reason"], "AUTHORIZATION_REVOKED")

    async def test_expired_authorization_denied(self):
        now = int(__import__("time").time())
        pid = self._scoped_program(expires_at=now - 10)
        result = await self._run_expecting_no_network(
            program_id=pid, target="example.com", check_type="headers", actor=555)
        self.assertEqual(result["reason"], "AUTHORIZATION_EXPIRED")

    async def test_not_yet_effective_authorization_denied(self):
        now = int(__import__("time").time())
        pid = self._scoped_program(effective_at=now + 3600)
        result = await self._run_expecting_no_network(
            program_id=pid, target="example.com", check_type="headers", actor=555)
        self.assertEqual(result["reason"], "AUTHORIZATION_NOT_EFFECTIVE")

    async def test_out_of_scope_target_denied(self):
        pid = self._scoped_program(include="example.com")
        result = await self._run_expecting_no_network(
            program_id=pid, target="evil.test", check_type="headers", actor=555)
        self.assertEqual(result["reason"], "NO_INCLUDE_MATCH")

    async def test_program_with_no_scope_rules_denies(self):
        pid = self._program()
        self._authorize(pid)
        result = await self._run_expecting_no_network(
            program_id=pid, target="example.com", check_type="headers", actor=555)
        self.assertEqual(result["reason"], "TARGET_OUT_OF_SCOPE")

    async def test_exclude_overrides_include(self):
        pid = self._program()
        self._authorize(pid)
        sp.add_scope_rule(pid, "INCLUDE", "DOMAIN", "example.com", actor_user_id=999)
        sp.add_scope_rule(pid, "EXCLUDE", "DOMAIN", "internal.example.com",
                          actor_user_id=999)
        result = await self._run_expecting_no_network(
            program_id=pid, target="internal.example.com", check_type="headers", actor=555)
        self.assertEqual(result["reason"], "TARGET_EXCLUDED")

    async def test_engine_has_no_is_admin_input_anywhere(self):
        """Admin status cannot be expressed to this engine, so it cannot
        widen scope. Structural, not a runtime check."""
        import ast, inspect, textwrap
        self.assertNotIn("is_admin", inspect.signature(st.run_security_check).parameters)
        tree = ast.parse(textwrap.dedent(inspect.getsource(st)))
        identifiers = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        identifiers |= {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)}
        identifiers |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertNotIn("is_admin", identifiers)

    async def test_admin_actor_gets_the_same_denial_as_anyone_else(self):
        pid = self._scoped_program(include="example.com")
        results = [
            await self._run_expecting_no_network(
                program_id=pid, target="evil.test", check_type="headers", actor=actor)
            for actor in (555, 999)   # 999 created the program and reviewed it
        ]
        self.assertEqual(results[0]["reason"], results[1]["reason"])
        self.assertTrue(all(r["status"] == "DENIED" for r in results))

    # ================= Check type validation =================

    async def test_all_declared_check_types_are_callable(self):
        self.assertEqual(st.VALID_CHECK_TYPES,
                         {"headers", "tls", "cookies", "redirects", "cors", "technology"})
        for name, fn in st.CHECK_TYPES.items():
            with self.subTest(check=name):
                self.assertTrue(asyncio.iscoroutinefunction(fn))

    async def test_unknown_check_type_denied(self):
        pid = self._scoped_program()
        for bad in ("nmap", "HEADERS", "", "exploit", "sqlmap", None, 7, ["headers"]):
            with self.subTest(check_type=bad):
                result = await self._run_expecting_no_network(
                    program_id=pid, target="example.com", check_type=bad, actor=555)
                self.assertEqual(result["reason"], "UNKNOWN_CHECK")

    async def test_command_and_code_strings_rejected_as_check_type(self):
        pid = self._scoped_program()
        for payload in ("__import__('os').system('id')",
                        "; rm -rf /",
                        "headers; curl evil.test",
                        "eval(open('/etc/passwd').read())",
                        "../../etc/passwd"):
            with self.subTest(payload=payload):
                result = await self._run_expecting_no_network(
                    program_id=pid, target="example.com", check_type=payload, actor=555)
                self.assertEqual(result["reason"], "UNKNOWN_CHECK")

    async def test_check_type_is_never_resolved_dynamically(self):
        """The dispatch table is the only path to a check function."""
        import ast, inspect
        tree = ast.parse(inspect.getsource(st))
        called = {n.func.id for n in ast.walk(tree)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        for forbidden in ("eval", "exec", "compile", "__import__"):
            with self.subTest(call=forbidden):
                self.assertNotIn(forbidden, called)
        # dispatch happens through the literal table subscript and nowhere else
        source = inspect.getsource(st.run_security_check)
        self.assertIn("CHECK_TYPES[check_type]", source)

    async def test_module_never_uses_a_shell(self):
        import ast, inspect
        tree = ast.parse(inspect.getsource(st))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        for forbidden in ("subprocess", "os", "pty", "commands"):
            with self.subTest(module=forbidden):
                self.assertNotIn(forbidden, imported)

    # ================= Target-type and port restrictions =================

    async def test_bare_ip_target_refused_even_when_in_scope(self):
        """Scanning IPs is IP scanning. Scope may allow the record; the
        engine still refuses to connect."""
        pid = self._program()
        self._authorize(pid)
        sp.add_scope_rule(pid, "INCLUDE", "IP", "93.184.216.34", actor_user_id=999)
        self.assertTrue(sp.evaluate_target(pid, "93.184.216.34").allowed)
        result = await self._run_expecting_no_network(
            program_id=pid, target="93.184.216.34", check_type="headers", actor=555)
        self.assertEqual(result["reason"], "TARGET_TYPE_NOT_SCANNABLE")

    async def test_cidr_target_refused_even_when_in_scope(self):
        pid = self._program()
        self._authorize(pid)
        sp.add_scope_rule(pid, "INCLUDE", "CIDR", "93.184.216.0/24", actor_user_id=999)
        self.assertTrue(sp.evaluate_target(pid, "93.184.216.0/24").allowed)
        result = await self._run_expecting_no_network(
            program_id=pid, target="93.184.216.0/24", check_type="headers", actor=555)
        self.assertEqual(result["reason"], "TARGET_TYPE_NOT_SCANNABLE")

    async def test_non_web_port_refused(self):
        pid = self._program()
        self._authorize(pid)
        sp.add_scope_rule(pid, "INCLUDE", "URL", "https://example.com:8443/",
                          actor_user_id=999)
        result = await self._run_expecting_no_network(
            program_id=pid, target="https://example.com:8443/", check_type="headers",
            actor=555)
        self.assertIn(result["reason"], ("PORT_NOT_ALLOWED", "NO_INCLUDE_MATCH"))

    def test_only_web_ports_are_reachable(self):
        self.assertEqual(st.ALLOWED_PORTS, frozenset({80, 443}))
        self.assertEqual(st.ALLOWED_SCHEMES, frozenset({"http", "https"}))

    # ================= SSRF / destination guard =================

    def test_forbidden_destination_classes(self):
        cases = {
            "127.0.0.1": "DESTINATION_LOOPBACK",
            "127.10.20.30": "DESTINATION_LOOPBACK",
            "::1": "DESTINATION_LOOPBACK",
            "169.254.169.254": "DESTINATION_LINK_LOCAL",   # AWS/Azure metadata
            "169.254.170.2": "DESTINATION_LINK_LOCAL",     # ECS task metadata
            "fe80::1": "DESTINATION_LINK_LOCAL",
            "10.0.0.5": "DESTINATION_PRIVATE",
            "172.16.31.4": "DESTINATION_PRIVATE",
            "192.168.1.1": "DESTINATION_PRIVATE",
            "fd00::1": "DESTINATION_PRIVATE",
            "0.0.0.0": "DESTINATION_UNSPECIFIED",
            "::": "DESTINATION_UNSPECIFIED",
            "224.0.0.1": "DESTINATION_MULTICAST",
            "not-an-ip": "DESTINATION_UNPARSEABLE",
            "": "DESTINATION_UNPARSEABLE",
        }
        for address, expected in cases.items():
            with self.subTest(address=address):
                self.assertEqual(st._forbidden_ip_reason(address), expected)

    def test_ipv4_mapped_ipv6_cannot_smuggle_a_private_address(self):
        for address in ("::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1"):
            with self.subTest(address=address):
                self.assertIsNotNone(st._forbidden_ip_reason(address))

    def test_public_addresses_are_allowed(self):
        for address in ("93.184.216.34", "1.1.1.1", "2606:2800:220:1:248:1893:25c8:1946"):
            with self.subTest(address=address):
                self.assertIsNone(st._forbidden_ip_reason(address))

    async def test_scope_rule_cannot_re_enable_loopback(self):
        """The whole point of the network guard: an operator writing an
        INCLUDE rule for their own host must still not get a connection.
        Scope says ALLOW; the engine says DENY anyway."""
        pid = self._program()
        self._authorize(pid)
        sp.add_scope_rule(pid, "INCLUDE", "DOMAIN", "localhost.attacker.test",
                          actor_user_id=999)
        self.assertTrue(sp.evaluate_target(pid, "localhost.attacker.test").allowed)

        def resolves_to_loopback(host, port):
            return ["127.0.0.1"]

        with mock.patch.object(st, "_resolve_host", resolves_to_loopback), \
             mock.patch.object(st, "_fetch_once", mock.AsyncMock(
                 side_effect=_Tripwire("must not connect"))):
            result = await st.run_security_check(
                program_id=pid, target="localhost.attacker.test",
                check_type="headers", actor=555)
        self.assertEqual(result["status"], "DENIED")
        self.assertEqual(result["reason"], "DESTINATION_LOOPBACK")

    async def test_metadata_endpoint_is_refused(self):
        pid = self._scoped_program(include="metadata.attacker.test")
        with mock.patch.object(st, "_resolve_host", lambda h, p: ["169.254.169.254"]), \
             mock.patch.object(st, "_fetch_once", mock.AsyncMock(
                 side_effect=_Tripwire("must not connect"))):
            result = await st.run_security_check(
                program_id=pid, target="metadata.attacker.test",
                check_type="headers", actor=555)
        self.assertEqual(result["reason"], "DESTINATION_LINK_LOCAL")

    async def test_any_forbidden_address_in_the_set_rejects_the_host(self):
        """A host answering with one public and one private address is
        the DNS-rebinding shape; rejecting on *any* bad address closes it."""
        with mock.patch.object(st, "_resolve_host",
                               lambda h, p: ["93.184.216.34", "10.0.0.7"]):
            addresses, reason = await st.resolve_and_validate("example.com", 443)
        self.assertEqual(addresses, [])
        self.assertEqual(reason, "DESTINATION_PRIVATE")

    async def test_dns_failure_fails_closed(self):
        with mock.patch.object(st, "_resolve_host",
                               mock.Mock(side_effect=socket.gaierror("nope"))):
            addresses, reason = await st.resolve_and_validate("example.com", 443)
        self.assertEqual(addresses, [])
        self.assertEqual(reason, "DNS_RESOLUTION_FAILED")

    async def test_empty_dns_answer_fails_closed(self):
        with mock.patch.object(st, "_resolve_host", lambda h, p: []):
            addresses, reason = await st.resolve_and_validate("example.com", 443)
        self.assertEqual(reason, "DNS_NO_ADDRESS")

    # ================= Redirect handling =================

    async def test_redirect_to_out_of_scope_host_is_stopped(self):
        pid = self._url_scoped_program()
        patch, calls = self._fetcher([
            self._response(301, {"location": "https://evil.test/"}),
            self._response(200),   # must never be served
        ])
        with self._ok_resolver(), patch:
            result = await st.run_security_check(
                program_id=pid, target="https://example.com/",
                check_type="redirects", actor=555)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("https://evil.test/", calls)
        codes = [o["code"] for o in result["findings"]]
        self.assertIn("REDIRECT_CHAIN_STOPPED", codes)

    async def test_redirect_within_scope_is_followed(self):
        """A sibling host must be in scope in its own right. scope_policy
        does not let a URL rule for example.com cover www.example.com, so
        following the hop requires authorizing it -- which is the correct
        conservative behaviour, not something to loosen."""
        pid = self._url_scoped_program()
        sp.add_scope_rule(pid, "INCLUDE", "URL", "https://www.example.com/",
                          actor_user_id=999)
        patch, calls = self._fetcher([
            self._response(301, {"location": "https://www.example.com/"}),
            self._response(200, url="https://www.example.com/"),
        ])
        with self._ok_resolver(), patch:
            result = await st.run_security_check(
                program_id=pid, target="https://example.com/",
                check_type="redirects", actor=555)
        self.assertTrue(result["ok"])
        self.assertEqual(len(calls), 2)
        self.assertEqual(result["data"]["hop_count"], 1)

    async def test_redirect_limit_enforced(self):
        pid = self._url_scoped_program()
        loop = [self._response(302, {"location": "https://example.com/next"})
                for _ in range(st.MAX_REDIRECTS + 3)]
        patch, calls = self._fetcher(loop)
        with self._ok_resolver(), patch:
            result = await st.run_security_check(
                program_id=pid, target="https://example.com/",
                check_type="redirects", actor=555)
        self.assertLessEqual(len(calls), st.MAX_REDIRECTS + 1)
        self.assertIn("TOO_MANY_REDIRECTS",
                      [o["detail"] for o in result["findings"]])

    async def test_redirect_into_a_private_address_is_refused(self):
        pid = self._url_scoped_program()
        patch, calls = self._fetcher([
            self._response(302, {"location": "https://internal.example.com/"}),
            self._response(200),
        ])

        def resolver(host, port):
            return ["10.0.0.9"] if host.startswith("internal") else ["93.184.216.34"]

        with mock.patch.object(st, "_resolve_host", resolver), patch:
            await st.run_security_check(
                program_id=pid, target="https://example.com/",
                check_type="redirects", actor=555)
        self.assertEqual(len(calls), 1)

    async def test_unparseable_redirect_stops_the_chain(self):
        pid = self._url_scoped_program()
        patch, calls = self._fetcher([
            self._response(302, {"location": "gopher://example.com/x"}),
            self._response(200),
        ])
        with self._ok_resolver(), patch:
            await st.run_security_check(
                program_id=pid, target="https://example.com/",
                check_type="redirects", actor=555)
        self.assertEqual(len(calls), 1)

    # ================= Network safety primitives =================

    async def test_timeout_is_reported_not_raised(self):
        pid = self._scoped_program(include="example.com")
        patch, _calls = self._fetcher(["REQUEST_TIMEOUT"])
        with self._ok_resolver(), patch:
            result = await st.run_security_check(
                program_id=pid, target="example.com", check_type="headers", actor=555)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["reason"], "REQUEST_TIMEOUT")

    async def test_response_size_limit_truncates(self):
        """Exercises the real streaming loop in _fetch_once against a
        fake httpx, so the cap is tested rather than assumed."""
        oversized = b"A" * (st.MAX_RESPONSE_BYTES * 3)
        fake = _FakeHttpx(status_code=200, headers={"Server": "test"}, body=oversized)
        with mock.patch.object(st, "httpx", fake), \
             mock.patch.object(st, "_HTTPX_AVAILABLE", True):
            response, error = await st._fetch_once(
                {"scheme": "https", "host": "example.com", "port": 443, "path": "/"})
        self.assertIsNone(error)
        self.assertTrue(response.truncated)
        self.assertLessEqual(fake.bytes_delivered, st.MAX_RESPONSE_BYTES + fake.chunk_size)

    async def test_http_client_missing_is_reported_cleanly(self):
        with mock.patch.object(st, "_HTTPX_AVAILABLE", False):
            response, error = await st._fetch_once(
                {"scheme": "https", "host": "example.com", "port": 443, "path": "/"})
        self.assertIsNone(response)
        self.assertEqual(error, "HTTP_CLIENT_UNAVAILABLE")

    def test_limits_are_fixed_constants_not_user_input(self):
        import inspect
        params = inspect.signature(st.run_security_check).parameters
        for knob in ("timeout", "max_redirects", "max_bytes", "limit", "concurrency"):
            with self.subTest(knob=knob):
                self.assertNotIn(knob, params)
        self.assertGreater(st.REQUEST_TIMEOUT_SECONDS, 0)
        self.assertGreater(st.MAX_RESPONSE_BYTES, 0)
        self.assertGreater(st.MAX_REDIRECTS, 0)

    # ================= Rate limiting =================

    async def test_per_target_rate_limit(self):
        pid = self._scoped_program(include="example.com")
        for _ in range(st.MAX_REQUESTS_PER_TARGET):
            allowed, _reason = st._check_and_use_scan_quota(pid, "example.com")
            self.assertTrue(allowed)
        allowed, reason = st._check_and_use_scan_quota(pid, "example.com")
        self.assertFalse(allowed)
        self.assertEqual(reason, "RATE_LIMIT_TARGET")

    async def test_rate_limited_request_is_denied_before_the_network(self):
        pid = self._scoped_program(include="example.com")
        for _ in range(st.MAX_REQUESTS_PER_TARGET):
            st._check_and_use_scan_quota(pid, "example.com")
        result = await self._run_expecting_no_network(
            program_id=pid, target="example.com", check_type="headers", actor=555)
        self.assertEqual(result["reason"], "RATE_LIMIT_TARGET")

    def test_blocked_request_does_not_consume_quota(self):
        pid = self._scoped_program(include="example.com")
        for _ in range(st.MAX_REQUESTS_PER_TARGET):
            st._check_and_use_scan_quota(pid, "example.com")
        before = self._target_count(pid, "example.com")
        st._check_and_use_scan_quota(pid, "example.com")
        self.assertEqual(self._target_count(pid, "example.com"), before)

    def _target_count(self, pid, target):
        conn = sqlite3.connect(self._db_path)
        row = conn.execute(
            "SELECT COALESCE(SUM(count), 0) FROM bb_scan_usage WHERE program_id=? AND target=?",
            (pid, target)).fetchone()
        conn.close()
        return row[0]

    def test_scan_quota_does_not_reuse_the_ai_quota_tables(self):
        conn = sqlite3.connect(self._db_path)
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        self.assertIn("bb_scan_usage", names)
        self.assertNotIn("ai_usage", names)   # quota.py owns that, untouched here

    def test_db_init_is_idempotent(self):
        pid = self._scoped_program(include="example.com")
        st._check_and_use_scan_quota(pid, "example.com")
        before = self._target_count(pid, "example.com")
        for _ in range(3):
            st.security_testing_db_init()
        self.assertEqual(self._target_count(pid, "example.com"), before)

    # ================= Check behaviour =================

    async def _run_ok(self, check_type, response, include="example.com", target=None):
        pid = self._scoped_program(include=include)
        patch, _calls = self._fetcher([response])
        with self._ok_resolver(), patch:
            return await st.run_security_check(
                program_id=pid, target=target or "example.com",
                check_type=check_type, actor=555)

    async def test_headers_check_flags_missing_security_headers(self):
        result = await self._run_ok("headers", self._response(200, {"Server": "nginx/1.2"}))
        self.assertTrue(result["ok"])
        codes = [o["code"] for o in result["findings"]]
        self.assertIn("MISSING_SECURITY_HEADER", codes)
        self.assertIn("VERSION_DISCLOSURE", codes)

    async def test_headers_check_is_quiet_on_a_well_configured_host(self):
        headers = {h: "x" for h in st._SECURITY_HEADERS}
        result = await self._run_ok("headers", self._response(200, headers))
        self.assertEqual(result["findings"], [])

    async def test_cookie_flags_are_inspected(self):
        response = self._response(200, set_cookies=["sid=abc; Path=/"])
        result = await self._run_ok("cookies", response)
        codes = {o["code"] for o in result["findings"]}
        self.assertEqual(codes, {"COOKIE_MISSING_SECURE", "COOKIE_MISSING_HTTPONLY",
                                 "COOKIE_MISSING_SAMESITE"})

    async def test_secure_cookie_produces_no_observations(self):
        response = self._response(
            200, set_cookies=["sid=abc; Secure; HttpOnly; SameSite=Lax"])
        result = await self._run_ok("cookies", response)
        self.assertEqual(result["findings"], [])

    async def test_cors_wildcard_with_credentials_flagged(self):
        response = self._response(200, {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true"})
        result = await self._run_ok("cors", response)
        self.assertIn("CORS_WILDCARD_WITH_CREDENTIALS",
                      [o["code"] for o in result["findings"]])

    async def test_technology_check_is_passive_single_request(self):
        pid = self._scoped_program(include="example.com")
        patch, calls = self._fetcher([self._response(200, {"X-Powered-By": "PHP/8.1"})])
        with self._ok_resolver(), patch:
            result = await st.run_security_check(
                program_id=pid, target="example.com",
                check_type="technology", actor=555)
        self.assertEqual(len(calls), 1, "technology check must not probe extra paths")
        self.assertIn("x-powered-by", result["data"]["signals"])

    async def test_tls_check_uses_the_validated_ip_not_a_fresh_lookup(self):
        pid = self._scoped_program(include="example.com")
        seen = {}

        def fake_tls(host, ip, port):
            seen.update({"host": host, "ip": ip, "port": port})
            return {"tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                    "subject": {}, "issuer": {}, "not_before": None,
                    "not_after": None, "san_count": 1}

        with self._ok_resolver(addresses=("93.184.216.34",)), \
             mock.patch.object(st, "_tls_peek", fake_tls):
            result = await st.run_security_check(
                program_id=pid, target="example.com",
                check_type="tls", actor=555)
        self.assertTrue(result["ok"])
        self.assertEqual(seen["ip"], "93.184.216.34")
        self.assertEqual(seen["host"], "example.com")

    async def test_tls_handshake_failure_is_structured(self):
        pid = self._scoped_program(include="example.com")
        with self._ok_resolver(), mock.patch.object(
                st, "_tls_peek", mock.Mock(side_effect=ssl.SSLError("boom"))):
            result = await st.run_security_check(
                program_id=pid, target="example.com",
                check_type="tls", actor=555)
        self.assertEqual(result["reason"], "TLS_HANDSHAKE_FAILED")

    # ================= Failure safety =================

    async def test_unexpected_exception_does_not_bypass_authorization(self):
        pid = self._scoped_program(include="example.com")
        with self._ok_resolver(), mock.patch.object(
                st, "_fetch_once", mock.AsyncMock(side_effect=RuntimeError("kaboom"))):
            result = await st.run_security_check(
                program_id=pid, target="example.com", check_type="headers", actor=555)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "INTERNAL_ERROR")

    async def test_errors_never_leak_internals(self):
        pid = self._scoped_program(include="example.com")
        secret = "/home/secret/path/apikey-AKIAEXAMPLE"
        with self._ok_resolver(), mock.patch.object(
                st, "_fetch_once", mock.AsyncMock(side_effect=RuntimeError(secret))):
            result = await st.run_security_check(
                program_id=pid, target="example.com", check_type="headers", actor=555)
        blob = repr(result)
        for leak in (secret, "Traceback", "File \"", "apikey", "/home/"):
            with self.subTest(leak=leak):
                self.assertNotIn(leak, blob)

    async def test_concurrency_slot_is_released_after_a_failure(self):
        pid = self._scoped_program(include="example.com")
        before = st._concurrency._value
        with self._ok_resolver(), mock.patch.object(
                st, "_fetch_once", mock.AsyncMock(side_effect=RuntimeError("kaboom"))):
            await st.run_security_check(
                program_id=pid, target="example.com", check_type="headers", actor=555)
        self.assertEqual(st._concurrency._value, before)

    async def test_concurrency_limit_is_bounded(self):
        self.assertEqual(st._concurrency._value, st.MAX_CONCURRENT_CHECKS)
        self.assertLessEqual(st.MAX_CONCURRENT_CHECKS, 4)

    # ================= Audit logging =================

    async def test_successful_check_writes_the_full_audit_trail(self):
        pid = self._scoped_program(include="example.com")
        patch, _calls = self._fetcher([self._response(200)])
        with self._ok_resolver(), patch:
            await st.run_security_check(
                program_id=pid, target="example.com", check_type="headers", actor=555)
        actions = self._audit_actions()
        for expected in ("SECURITY_CHECK_REQUESTED", "SECURITY_CHECK_STARTED",
                         "SECURITY_CHECK_COMPLETED"):
            with self.subTest(action=expected):
                self.assertIn(expected, actions)

    async def test_denial_is_audited(self):
        pid = self._scoped_program(include="example.com")
        await self._run_expecting_no_network(
            program_id=pid, target="evil.test", check_type="headers", actor=555)
        actions = self._audit_actions()
        self.assertIn("SECURITY_CHECK_REQUESTED", actions)
        self.assertIn("SECURITY_CHECK_DENIED", actions)
        self.assertNotIn("SECURITY_CHECK_STARTED", actions)

    async def test_failure_is_audited(self):
        pid = self._scoped_program(include="example.com")
        patch, _calls = self._fetcher(["REQUEST_TIMEOUT"])
        with self._ok_resolver(), patch:
            await st.run_security_check(
                program_id=pid, target="example.com", check_type="headers", actor=555)
        self.assertIn("SECURITY_CHECK_FAILED", self._audit_actions())

    async def test_audit_detail_carries_context_but_no_response_body(self):
        pid = self._scoped_program(include="example.com")
        patch, _calls = self._fetcher([
            self._response(200, {"set-cookie": "sid=SUPERSECRETVALUE"})])
        with self._ok_resolver(), patch:
            await st.run_security_check(
                program_id=pid, target="example.com", check_type="headers", actor=555)
        conn = sqlite3.connect(self._db_path)
        details = " ".join(r[0] or "" for r in conn.execute(
            "SELECT detail FROM audit_log WHERE action LIKE 'SECURITY_CHECK%'"))
        conn.close()
        self.assertIn(f"program_id={pid}", details)
        self.assertIn("check_type=headers", details)
        self.assertNotIn("SUPERSECRETVALUE", details)

    def test_no_second_audit_system(self):
        conn = sqlite3.connect(self._db_path)
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        self.assertEqual({n for n in names if "audit" in n.lower()}, {"audit_log"})

    # ================= Finding integration boundary =================

    async def test_a_check_never_creates_a_finding(self):
        pid = self._scoped_program(include="example.com")
        import findings as f
        f.DB_PATH = self._db_path
        f.findings_db_init()
        patch, _calls = self._fetcher([self._response(200, {"Server": "nginx/1.0"})])
        with self._ok_resolver(), patch:
            result = await st.run_security_check(
                program_id=pid, target="example.com", check_type="headers", actor=555)
        self.assertTrue(result["findings"], "the check should have observations")
        self.assertEqual(f.list_findings(pid), [],
                         "observations must never auto-create a Finding")

    def test_module_does_not_import_finding_creation(self):
        import ast, inspect
        names = set()
        for node in ast.walk(ast.parse(inspect.getsource(st))):
            if isinstance(node, ast.ImportFrom):
                names.update(a.name for a in node.names)
        self.assertNotIn("create_finding", names)

    def test_result_shape_is_stable(self):
        result = st._denied("NO_INCLUDE_MATCH", program_id=1, target="x",
                            check_type="headers").as_dict()
        self.assertEqual(
            set(result),
            {"ok", "status", "reason", "program_id", "target", "check_type",
             "findings", "data"})
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "DENIED")

    def test_formatter_renders_denials_and_results_without_internals(self):
        denied = st.format_check_result(
            st._denied("DESTINATION_LOOPBACK").as_dict())
        self.assertTrue(denied.startswith("❌"))
        ok = st.CheckResult(ok=True, status="COMPLETED", program_id=1,
                            target="example.com", check_type="headers")
        ok.observations = [st.Observation("LOW", "MISSING_SECURITY_HEADER", "x-frame-options")]
        text = st.format_check_result(ok.as_dict())
        self.assertIn("MISSING_SECURITY_HEADER", text)
        self.assertIn("/bbfinding new", text)


# ---------------- Minimal fake httpx for the streaming test ----------------

class _FakeHeaders(dict):
    def multi_items(self):
        return list(self.items())


class _FakeStreamResponse:
    def __init__(self, status_code, headers, body, chunk_size):
        self.status_code = status_code
        self.headers = _FakeHeaders(headers)
        self._body = body
        self._chunk_size = chunk_size
        self.delivered = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def aiter_bytes(self):
        for start in range(0, len(self._body), self._chunk_size):
            chunk = self._body[start:start + self._chunk_size]
            self.delivered += len(chunk)
            yield chunk


class _FakeHttpx:
    """Just enough of httpx for _fetch_once's streaming path."""

    def __init__(self, status_code, headers, body, chunk_size=8192):
        self.status_code = status_code
        self._headers = headers
        self._body = body
        self.chunk_size = chunk_size
        self.bytes_delivered = 0
        self._response = None
        outer = self

        class _Timeout:
            def __init__(self, *a, **k):
                pass

        class _AsyncClient:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            def stream(self, method, url):
                outer._response = _FakeStreamResponse(
                    outer.status_code, outer._headers, outer._body, outer.chunk_size)
                return outer._response

        self.Timeout = _Timeout
        self.AsyncClient = _AsyncClient
        self.HTTPError = Exception

    @property
    def bytes_delivered(self):
        return self._response.delivered if self._response else 0

    @bytes_delivered.setter
    def bytes_delivered(self, value):
        pass


if __name__ == "__main__":
    unittest.main()