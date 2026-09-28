"""
tests/test_blueteam_intel_core.py — Intel pure core: canonicalization, confidence
model, Bloom (no false negatives), and the LookupEngine's trie/CIDR/exact paths
verified against a brute-force reference over fixed-seed random data. Also STIX
determinism and the double-buffer snapshot swap.

Standalone; offline; deterministic (fixed seed).
"""

import ipaddress
import os
import random
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from blueteam.intel import domain as D
from blueteam.intel.bloom import BloomFilter
from blueteam.intel.lookup import LookupEngine, build_snapshot
from blueteam.intel.domain import IOC, IOCType

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


# ---------------- canonicalization ----------------
check("canon domain idna+lower+trailing dot",
      D.canonicalize(IOCType.DOMAIN, "Evil.COM.") == "evil.com")
check("canon ip normalizes", D.canonicalize(IOCType.IP, "2001:0DB8::0001") == "2001:db8::1")
check("canon cidr strict=false", D.canonicalize(IOCType.CIDR, "10.0.0.5/24") == "10.0.0.0/24")
check("canon sha256 lower", D.canonicalize(IOCType.SHA256, "A" * 64) == "a" * 64)
check("canon tme strips prefix", D.canonicalize(IOCType.TME_HANDLE, "https://t.me/ScamBot") == "scambot")
try:
    D.canonicalize(IOCType.DOMAIN, "not a domain")
    check("canon rejects bad domain", False)
except D.CanonicalizeError:
    check("canon rejects bad domain", True)

# detect_type
check("detect sha256", D.detect_type("b" * 64) == IOCType.SHA256)
check("detect ip", D.detect_type("8.8.8.8") == IOCType.IP)
check("detect cidr", D.detect_type("10.0.0.0/8") == IOCType.CIDR)
check("detect url", D.detect_type("https://x.test/a") == IOCType.URL)
check("detect domain", D.detect_type("evil.example") == IOCType.DOMAIN)

# ---------------- confidence model ----------------
c_fresh, b_fresh = D.compute_confidence(sources=["urlhaus", "threatfox"], age_days=0)
c_old, _ = D.compute_confidence(sources=["urlhaus", "threatfox"], age_days=120)
c_single, _ = D.compute_confidence(sources=["openphish"], age_days=0)
check("confidence in range", 0 <= c_fresh <= 100 and 0 <= c_old <= 100)
check("corroboration beats single source", c_fresh > c_single)
check("freshness decays with age", c_old < c_fresh)
check("local verdict boosts",
      D.compute_confidence(sources=["urlhaus"], age_days=0, local_verdict=True)[0]
      >= D.compute_confidence(sources=["urlhaus"], age_days=0)[0])
check("fp reports penalize",
      D.compute_confidence(sources=["urlhaus"], age_days=0, fp_reports=5)[0]
      < D.compute_confidence(sources=["urlhaus"], age_days=0)[0])
check("breakdown explains", set(b_fresh) >= {"sources", "corroboration", "freshness", "final"})

# ---------------- Bloom: no false negatives ----------------
rnd = random.Random(1337)
present = [f"val-{rnd.randrange(10**9)}" for _ in range(5000)]
bloom = BloomFilter(capacity=5000, error_rate=0.001)
bloom.add_all(present)
check("bloom no false negatives", all(bloom.maybe_contains(v) for v in present))
absent = [f"absent-{i}" for i in range(20000)]
fp = sum(1 for v in absent if bloom.maybe_contains(v))
check("bloom fp rate near target", fp / len(absent) < 0.01, f"fp={fp/len(absent):.4f}")

# ---------------- LookupEngine vs brute force (fixed seed) ----------------
rnd = random.Random(20250928)


def rand_domain():
    labels = rnd.choice([2, 3])
    return ".".join("".join(rnd.choice("abcdefghij") for _ in range(rnd.randint(3, 7)))
                    for _ in range(labels))


def rand_ipv4():
    return str(ipaddress.IPv4Address(rnd.randrange(2 ** 32)))


# build a corpus of domain + CIDR + hash IOCs
iocs = []
flagged_domains = set()
for _ in range(300):
    d = rand_domain()
    flagged_domains.add(d)
    iocs.append(IOC(IOCType.DOMAIN, d, sources=["test"], confidence=80))

cidr_nets = []
for _ in range(200):
    base = rnd.randrange(2 ** 32) & 0xFFFFFF00
    prefix = rnd.choice([24, 25, 26, 28])
    net = ipaddress.ip_network((base, prefix), strict=False)
    cidr_nets.append(net)
    iocs.append(IOC(IOCType.CIDR, str(net), sources=["test"], confidence=70))

flagged_hashes = set()
for _ in range(300):
    h = "".join(rnd.choice("0123456789abcdef") for _ in range(64))
    flagged_hashes.add(h)
    iocs.append(IOC(IOCType.SHA256, h, sources=["test"], confidence=90))

eng = LookupEngine(build_snapshot(iocs, now=0.0))

# --- domain suffix correctness vs brute force ---
def brute_domain(q):
    # a query matches if it equals or is a subdomain of any flagged domain
    for fd in flagged_domains:
        if q == fd or q.endswith("." + fd):
            return True
    return False


dom_mismatch = 0
for _ in range(3000):
    if rnd.random() < 0.5:
        # subdomain of a flagged domain
        fd = rnd.choice(list(flagged_domains))
        q = "sub" + str(rnd.randrange(100)) + "." + fd
    else:
        q = rand_domain()
    engine_hit = eng.lookup(q, IOCType.DOMAIN) is not None
    if engine_hit != brute_domain(q):
        dom_mismatch += 1
check("lookup domain trie matches brute force", dom_mismatch == 0, f"mismatches={dom_mismatch}")

# --- CIDR correctness vs brute force ---
def brute_ip(ip):
    ipa = ipaddress.ip_address(ip)
    for net in cidr_nets:
        if ipa in net:
            return True
    return False


ip_mismatch = 0
for _ in range(3000):
    ip = rand_ipv4()
    engine_hit = eng.lookup(ip, IOCType.IP) is not None
    if engine_hit != brute_ip(ip):
        ip_mismatch += 1
check("lookup CIDR bisect matches brute force", ip_mismatch == 0, f"mismatches={ip_mismatch}")

# --- hash exact correctness ---
hash_ok = all(eng.lookup(h, IOCType.SHA256) is not None for h in list(flagged_hashes)[:100])
hash_neg = all(eng.lookup("f" * 64, IOCType.SHA256) is None for _ in range(1))
check("lookup exact hash hits", hash_ok)
check("lookup exact hash miss returns None", eng.lookup("e" * 64, IOCType.SHA256) is None or hash_neg)

# match reason + details
mr = eng.lookup("sub1." + next(iter(flagged_domains)), IOCType.DOMAIN)
check("match result carries reason/confidence", mr is not None and mr.reason == "domain_suffix" and mr.confidence == 80)

# ---------------- snapshot double-buffer swap ----------------
before = eng.lookup(next(iter(flagged_hashes)), IOCType.SHA256)
eng.swap(build_snapshot([], now=1.0))     # swap to empty index
after = eng.lookup(next(iter(flagged_hashes)), IOCType.SHA256)
check("swap replaces index and clears cache", before is not None and after is None)

# ---------------- STIX determinism ----------------
sample = [IOC(IOCType.DOMAIN, "evil.com", sources=["urlhaus"], confidence=90, family="agent_tesla"),
          IOC(IOCType.SHA256, "a" * 64, sources=["malwarebazaar"], confidence=95)]
b1 = D.to_stix_bundle(sample)
b2 = D.to_stix_bundle(list(reversed(sample)))
ids1 = sorted(o["id"] for o in b1["objects"])
ids2 = sorted(o["id"] for o in b2["objects"])
check("stix ids deterministic across order", ids1 == ids2 and b1["id"] == b2["id"])
check("stix has indicator+malware", any(o["type"] == "malware" for o in b1["objects"])
      and any(o["type"] == "indicator" for o in b1["objects"]))

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
