# -*- coding: utf-8 -*-
"""เทสต์ active_scan — store, scanner (รวม TCP scan จริงบน localhost), AXFR parser,
guard (IP + CIDR), engine (gate/scan แบบ stub)"""

import os
import struct
import asyncio
import tempfile
import unittest

from active_scan import store, scanner, guard, engine


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------
class StoreTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "ascan.json")

    def test_create_update_get(self):
        rec = store.create_scan(10, "example.com", "quick", 1, self.path)
        self.assertEqual(rec["id"], 1)
        store.update_scan(1, lambda r: r.__setitem__("status", "completed"), self.path)
        self.assertEqual(store.get_scan(1, self.path)["status"], "completed")

    def test_list_filter_by_program(self):
        store.create_scan(10, "a.com", "quick", 1, self.path)
        store.create_scan(20, "b.com", "quick", 1, self.path)
        self.assertEqual(len(store.list_scans(10, path=self.path)), 1)
        self.assertEqual(len(store.list_scans(None, path=self.path)), 2)

    def test_policy_guard(self):
        with self.assertRaises(ValueError):
            store.set_policy("nope", 1, self.path)
        store.set_policy("concurrency", 50, self.path)
        self.assertEqual(store.get_policy(self.path)["concurrency"], 50)


# ---------------------------------------------------------------------------
# scanner — pure helpers
# ---------------------------------------------------------------------------
class ScannerPureTests(unittest.TestCase):
    def test_service_for(self):
        self.assertEqual(scanner.service_for(22), "ssh")
        self.assertEqual(scanner.service_for(9999, "SSH-2.0-OpenSSH_8.9"), "ssh")
        self.assertEqual(scanner.service_for(1234, "HTTP/1.1 200 OK"), "http")

    def test_profiles_exist(self):
        for p in ("quick", "top100", "web", "db"):
            self.assertIn(p, scanner.PROFILES)
            self.assertTrue(scanner.PROFILES[p])

    def test_encode_qname(self):
        self.assertEqual(scanner._encode_qname("a.bc"), b"\x01a\x02bc\x00")

    def test_decode_name_simple(self):
        buf = b"\x03www\x07example\x03com\x00"
        name, off = scanner._decode_name(buf, 0)
        self.assertEqual(name, "www.example.com")
        self.assertEqual(off, len(buf))

    def test_decode_name_compression(self):
        # "example.com" at offset 0, then "www" + pointer to 0
        base = b"\x07example\x03com\x00"
        msg = base + b"\x03www" + struct.pack("!H", 0xC000 | 0)
        name, _ = scanner._decode_name(msg, len(base))
        self.assertEqual(name, "www.example.com")

    def test_parse_axfr_refused(self):
        # header rcode=5 (REFUSED)
        header = struct.pack("!HHHHHH", 1, 0x8005, 0, 0, 0, 0)
        names, refused = scanner._parse_axfr_message(header)
        self.assertTrue(refused)

    def test_parse_axfr_extracts_names(self):
        header = struct.pack("!HHHHHH", 1, 0x8400, 0, 1, 0, 0)  # an=1, rcode=0
        name = b"\x04host\x07example\x03com\x00"
        rr = name + struct.pack("!HHIH", 1, 1, 300, 4) + b"\x01\x02\x03\x04"
        names, refused = scanner._parse_axfr_message(header + rr)
        self.assertFalse(refused)
        self.assertIn("host.example.com", names)


# ---------------------------------------------------------------------------
# scanner — การสแกน TCP จริงบน localhost (พิสูจน์ primitive ทำงาน)
# ---------------------------------------------------------------------------
class RealTcpScanTests(unittest.TestCase):
    def test_scan_open_and_closed_port(self):
        async def run():
            server = await asyncio.start_server(
                lambda r, w: w.close(), "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            sem = asyncio.Semaphore(10)
            lim = scanner.RateLimiter(100, burst=10)
            try:
                opened = await scanner.scan_port("127.0.0.1", port,
                    connect_timeout=1.0, banner_timeout=0.5, sem=sem, limiter=lim, grab=False)
                # พอร์ตที่ไม่มีใครฟัง (เลือกพอร์ตสูงที่ว่าง)
                closed = await scanner.scan_port("127.0.0.1", 1,
                    connect_timeout=0.3, banner_timeout=0.3, sem=sem, limiter=lim, grab=False)
                return opened, closed
            finally:
                server.close()
                await server.wait_closed()
        opened, closed = asyncio.run(run())
        self.assertIsNotNone(opened)
        self.assertEqual(opened["state"], "open")
        self.assertIsNone(closed)

    def test_scan_host_collects_open(self):
        async def run():
            server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            try:
                return await scanner.scan_host("127.0.0.1", "localhost", [port, 2, 3],
                    policy={"concurrency": 5, "rate_per_sec": 100, "connect_timeout": 1.0,
                            "banner_timeout": 0.3, "max_ports_per_host": 10})
            finally:
                server.close()
                await server.wait_closed()
        res = asyncio.run(run())
        self.assertTrue(res["up"])
        self.assertEqual(len(res["ports"]), 1)


# ---------------------------------------------------------------------------
# guard — IP + CIDR (ด่าน public-IP)
# ---------------------------------------------------------------------------
class GuardTests(unittest.TestCase):
    def test_revalidate_ip(self):
        self.assertIsNone(guard.revalidate_ip("8.8.8.8"))
        self.assertIsNotNone(guard.revalidate_ip("127.0.0.1"))
        self.assertIsNotNone(guard.revalidate_ip("10.0.0.1"))
        self.assertIsNotNone(guard.revalidate_ip("169.254.169.254"))  # metadata

    def test_expand_cidr_cap(self):
        ips, err = guard._expand_cidr("192.0.2.0/30", 256)
        self.assertIsNone(err)
        self.assertTrue(len(ips) >= 2)
        _, err2 = guard._expand_cidr("10.0.0.0/8", 256)
        self.assertIn("TOO_LARGE", err2)


# ---------------------------------------------------------------------------
# engine — gate + scan (stub ไม่ต่อเน็ต)
# ---------------------------------------------------------------------------
class EngineTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "ascan.json")

    def test_denied_when_scope_blocks(self):
        async def run():
            async def fake_auth(program_id, target, max_hosts):
                return {"ok": False, "reason": "SCOPE_DENY:TARGET_OUT_OF_SCOPE",
                        "target_type": None, "hosts": []}
            orig = guard.authorize_and_resolve
            engine.guard.authorize_and_resolve = fake_auth
            try:
                return await engine.run_scan(5, "evil.test", 1, "quick", path=self.path)
            finally:
                engine.guard.authorize_and_resolve = orig
        scan = asyncio.run(run())
        self.assertEqual(scan["status"], "denied")
        self.assertIn("SCOPE_DENY", scan["denied_reason"])

    def test_completed_with_stubbed_scan(self):
        async def run():
            async def fake_auth(program_id, target, max_hosts):
                return {"ok": True, "reason": "OK", "target_type": "IP",
                        "hosts": [{"ip": "93.184.216.34", "hostname": "example.com"}],
                        "normalized_domain": None}
            async def fake_scan_host(ip, hostname, ports, policy):
                return {"ip": ip, "hostname": hostname, "up": True,
                        "ports": [{"port": 443, "state": "open", "service": "https",
                                   "banner": "", "latency_ms": 12}]}
            oa, os_ = guard.authorize_and_resolve, scanner.scan_host
            orig_reval = guard.revalidate_ip
            engine.guard.authorize_and_resolve = fake_auth
            engine.scanner.scan_host = fake_scan_host
            engine.guard.revalidate_ip = lambda ip: None
            try:
                return await engine.run_scan(5, "93.184.216.34", 1, "quick", path=self.path)
            finally:
                engine.guard.authorize_and_resolve = oa
                engine.scanner.scan_host = os_
                engine.guard.revalidate_ip = orig_reval
        scan = asyncio.run(run())
        self.assertEqual(scan["status"], "completed")
        self.assertEqual(scan["summary"]["open_ports_total"], 1)
        self.assertIn("https", scan["summary"]["services"])

    def test_disabled_policy(self):
        store.set_policy("enabled", False, self.path)
        scan = asyncio.run(engine.run_scan(5, "x.com", 1, "quick", path=self.path))
        self.assertEqual(scan["status"], "failed")
        self.assertEqual(scan["denied_reason"], "ACTIVE_SCAN_DISABLED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
