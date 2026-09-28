"""
tests/test_blueteam_intel_service.py — feed parsers, decompression-bomb guard,
SSRF-guarded fetcher (injected transport), and the full IntelService ingest path
over the real SQLite adapter (migration 0004). Offline, deterministic.
"""

import gzip
import io
import os
import sys
import tempfile
import zipfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import migrations
from blueteam.intel.domain import IOCType
from blueteam.intel.feeds import (FeedDef, FeedFetcher, decompress_guard, parse_feed)
from blueteam.intel.adapters import SqliteIntelRepository
from blueteam.intel.service import IntelService

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


# ---------------- decompression guard ----------------
payload = b"line\n" * 1000
gz = gzip.compress(payload)
check("gzip decompresses", decompress_guard(gz, encoding="gzip") == payload)
check("plain passthrough", decompress_guard(b"hello", encoding="") == b"hello")
# a bomb: tiny gzip that expands hugely
bomb = gzip.compress(b"\x00" * (5 * 1024 * 1024))
try:
    decompress_guard(bomb, encoding="gzip", max_ratio=5, max_bytes=1024)
    check("gzip bomb blocked", False)
except ValueError:
    check("gzip bomb blocked", True)
# zip
zbuf = io.BytesIO()
with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("f.txt", payload)
check("zip decompresses", decompress_guard(zbuf.getvalue(), url="x.zip") == payload)

# ---------------- parsers ----------------
uh = FeedDef("urlhaus", "https://u/", "urlhaus_csv", severity="high")
uh_csv = b'# comment\n"1","2024-01-01","https://evil.test/a","online","","AgentTesla","tag1,tag2","link","rep"\n'
p = parse_feed(uh, uh_csv)
check("urlhaus csv parses url", len(p) == 1 and p[0].ioc_type == IOCType.URL and p[0].family == "AgentTesla")

tf = FeedDef("threatfox", "https://t/", "threatfox_csv", severity="high")
tf_csv = b'"2024-01-01 00:00:00","111","1.2.3.4:443","ip:port","botnet_cc","Cobalt Strike"\n'
p = parse_feed(tf, tf_csv)
check("threatfox csv ip:port -> ip", len(p) == 1 and p[0].ioc_type == IOCType.IP and p[0].value == "1.2.3.4")

mb = FeedDef("mb", "https://m/", "malwarebazaar_csv", severity="high")
mb_csv = ('"2024-01-01","' + "a" * 64 + '","md5","sha1","rep","f.exe","exe","app","Emotet"\n').encode()
p = parse_feed(mb, mb_csv)
check("malwarebazaar csv -> sha256", len(p) == 1 and p[0].ioc_type == IOCType.SHA256 and p[0].family == "Emotet")

kev = FeedDef("kev", "https://k/", "cisa_kev_json", severity="high")
kev_json = b'{"vulnerabilities":[{"cveID":"CVE-2024-1234","vulnerabilityName":"RCE","product":"Foo"}]}'
p = parse_feed(kev, kev_json)
check("cisa kev -> advisory", len(p) == 1 and p[0].ioc_type == IOCType.ADVISORY and p[0].value == "CVE-2024-1234")

op = FeedDef("op", "https://o/", "plaintext_urls", severity="high")
p = parse_feed(op, b"https://phish.test/login\n# c\n\nhttps://phish2.test/\n")
check("plaintext urls parse", len(p) == 2)

# ---------------- FeedFetcher: https + SSRF + conditional GET ----------------
def transport_ok(url, headers, timeout):
    if headers.get("If-None-Match") == "etag-1":
        return 304, {}, b""
    return 200, {"ETag": "etag-1", "Content-Type": "text/csv"}, uh_csv

fetcher = FeedFetcher(transport=transport_ok)
r = fetcher.fetch(uh)
check("fetch 200 returns body+etag", r.status == 200 and r.etag == "etag-1")
r2 = fetcher.fetch(uh, etag="etag-1")
check("conditional GET 304", r2.status == 304 and r2.from_cache)

# https enforcement
http_feed = FeedDef("bad", "http://insecure.test/", "plaintext_urls")
check("http feed rejected", fetcher.fetch(http_feed).status == 0)

# SSRF screen: inject a screen_host that flags a private resolve
def fake_screen(host, resolver):
    ips = resolver(host)
    return (all(not ip.startswith(("10.", "127.")) for ip in ips), "private", ips)

def fake_resolver(host):
    return ["10.0.0.5"] if host == "internal" else ["8.8.8.8"]

ssrf_fetcher = FeedFetcher(screen_host=fake_screen, resolver=fake_resolver, transport=transport_ok)
internal_feed = FeedDef("int", "https://internal/", "urlhaus_csv", license_ok=True)
check("SSRF blocks private resolve", ssrf_fetcher.fetch(internal_feed).status == 0)
pub_feed = FeedDef("pub", "https://public/", "urlhaus_csv", license_ok=True)
check("SSRF allows public resolve", ssrf_fetcher.fetch(pub_feed).status == 200)

# ---------------- IntelService full ingest over sqlite ----------------
db = tempfile.mkstemp(suffix=".db")[1]
migrations.MigrationRunner(db).migrate_up()
repo = SqliteIntelRepository(db)

feeds = {
    "urlhaus": FeedDef("urlhaus", "https://urlhaus/", "urlhaus_csv",
                       license_ok=True, enabled_default=True, source_weight=0.85,
                       severity="high", default_ttl_days=30),
    "openphish": FeedDef("openphish", "https://openphish/", "plaintext_urls",
                         license_ok=False, enabled_default=False),
}

t = [1000.0]
svc = IntelService(repo, feeds=feeds, fetcher=FeedFetcher(transport=transport_ok),
                   clock=lambda: t[0])
res = svc.sync_feed("urlhaus")
check("service ingests feed", res["status"] == "ok" and res["ingested"] == 1)
mr = svc.lookup("https://evil.test/a", IOCType.URL)
check("lookup finds ingested ioc after sync", mr is not None and mr.confidence > 0)

# license-blocked feed
check("license-blocked feed skipped", svc.sync_feed("openphish")["status"] == "license_blocked")

# 304 -> no re-ingest
res2 = svc.sync_feed("urlhaus")
check("304 skips re-ingest", res2["status"] == "not_modified")

# growth quarantine: craft a feed that suddenly returns many
big_rows = b"".join(
    ('"i","2024","https://m%d.test/","online","","fam","","",""\n' % i).encode()
    for i in range(2000))

def transport_big(url, headers, timeout):
    return 200, {"ETag": "e2"}, big_rows

qfeeds = {"g": FeedDef("g", "https://g/", "urlhaus_csv", license_ok=True,
                       enabled_default=True, default_ttl_days=30)}
qsvc = IntelService(repo, feeds=qfeeds, fetcher=FeedFetcher(transport=transport_big),
                    clock=lambda: t[0], growth_quarantine_ratio=10.0, growth_quarantine_floor=5)
# seed a small last-good count
repo.save_feed_state("g", {"url": "https://g/", "item_count": 10, "failures": 0})
qres = qsvc.sync_feed("g")
check("growth quarantine trips", qres["status"] == "quarantined")

# allowlist: whitelisted domain never ingested
repo.add_whitelist("evil.test", added_by=1, now=t[0])
svc2 = IntelService(repo, feeds=feeds, fetcher=FeedFetcher(transport=transport_ok),
                    clock=lambda: t[0])
# force re-fetch by clearing etag
repo.save_feed_state("urlhaus", {"url": "https://urlhaus/", "item_count": 1, "failures": 0})
ares = svc2.sync_feed("urlhaus")
check("allowlisted domain skipped on ingest", ares["ingested"] == 0)

# local IOC add + delete
svc.add_local("bad.example", severity="high", added_by=42)
check("local ioc added and matchable", svc.lookup("sub.bad.example", IOCType.DOMAIN) is not None)
check("local ioc deleted", svc.delete_local("bad.example") and
      svc.lookup("bad.example", IOCType.DOMAIN) is None)

# export STIX
bundle = svc.export_stix()
check("stix export produces bundle", bundle["type"] == "bundle")

# adapter round-trip + stats
st = svc.stats()
check("stats reports totals", st["total"] >= 1 and "by_type" in st)

# ---------------- command surface: role gating + defang ----------------
from blueteam.intel.commands import IntelCommandService
from blueteam.platform.tenancy import Role

cmd = IntelCommandService(svc)
# viewer cannot sync/add
check("cmd blocks write for viewer", "OWNER" in cmd.handle(["sync"], role=Role.VIEWER))
# owner can add, and output is defanged
svc.add_local("https://evilcmd.test/x", ioc_type=IOCType.URL, added_by=1)
lk = cmd.handle(["lookup", "https://evilcmd.test/x"], role=Role.ADMIN)
check("cmd lookup output defanged", "hxxps" in lk or "[.]" in lk)
check("cmd status renders", "Threat Intel" in cmd.handle(["status"], role=Role.VIEWER))
check("cmd feeds renders", "urlhaus" in cmd.handle(["feeds"], role=Role.ADMIN))

repo.close()
os.remove(db)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
