"""
tests/bench_intel_dac_posture.py — micro-benchmarks for v0.8 hot paths.

Offline, stdlib only. Prints throughput/latency for:
  * Intel lookup (exact hash, domain-suffix trie, IP-in-CIDR) over a large index
  * DaC evaluation of a full rule set over messages (with Aho-Corasick prefilter)
  * Posture score computation

Run: python tests/bench_intel_dac_posture.py [scale]
Numbers are indicative (single core, no warmup tuning); they exist to catch
order-of-magnitude regressions, not to be exact.
"""

import ipaddress
import os
import random
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from blueteam.intel.domain import IOC, IOCType
from blueteam.intel.lookup import LookupEngine, build_snapshot
from blueteam.dac.domain import compile_rule
from blueteam.dac.matcher import RuleEngine, ENABLED
from blueteam.dac.records import build_record
from blueteam.posture.domain import Control, Assessment, compute_score

SCALE = int(sys.argv[1]) if len(sys.argv) > 1 else 1
rnd = random.Random(7)


def _timed(label, iters, fn):
    t0 = time.perf_counter()
    fn()
    dt = time.perf_counter() - t0
    per = dt / iters * 1e6
    print(f"{label:<42} {iters:>8} ops  {dt*1000:8.1f} ms  {per:8.2f} us/op  "
          f"{iters/dt:>12,.0f} ops/s")


# ---------------- Intel lookup ----------------
n_iocs = 100_000 * SCALE
iocs = []
for i in range(n_iocs // 2):
    iocs.append(IOC(IOCType.SHA256, "%064x" % rnd.getrandbits(256), sources=["b"]))
for i in range(n_iocs // 4):
    iocs.append(IOC(IOCType.DOMAIN, f"evil{i}.example{i % 97}.com", sources=["b"]))
for i in range(n_iocs // 4):
    base = rnd.randrange(2**32) & 0xFFFFFF00
    iocs.append(IOC(IOCType.CIDR, str(ipaddress.ip_network((base, 24), strict=False)), sources=["b"]))

t0 = time.perf_counter()
snap = build_snapshot(iocs, now=0.0)
print(f"{'Intel build_snapshot':<42} {len(iocs):>8} iocs {(time.perf_counter()-t0)*1000:8.1f} ms")
eng = LookupEngine(snap, lru_size=0)   # disable LRU to measure raw structure cost

hashes = [i.value for i in iocs if i.ioc_type == IOCType.SHA256][:20000]
miss_ips = [str(ipaddress.IPv4Address(rnd.randrange(2**32))) for _ in range(20000)]

_timed("Intel lookup exact-hash (hit)", len(hashes),
       lambda: [eng.lookup(h, IOCType.SHA256) for h in hashes])
_timed("Intel lookup IP-in-CIDR (mostly miss)", len(miss_ips),
       lambda: [eng.lookup(ip, IOCType.IP) for ip in miss_ips])
sub = [f"host.evil{i}.example{i % 97}.com" for i in range(20000)]
_timed("Intel lookup domain-suffix trie", len(sub),
       lambda: [eng.lookup(d, IOCType.DOMAIN) for d in sub])

# ---------------- DaC evaluation ----------------
import json
pack_path = os.path.join(_ROOT, "reference_data", "blueteam", "dac", "rules", "starter_pack.json")
with open(pack_path, encoding="utf-8") as fh:
    pack = json.load(fh)["rules"]
compiled = [compile_rule(b) for b in pack]
rengine = RuleEngine()
rengine.set_rules(compiled, {c.rule_id: ENABLED for c in compiled})

msgs = []
samples = ["good morning everyone how are you", "check this out https://ok.example.com/a",
           "connect wallet to claim tokens now https://drain.top/x",
           "verify your account here https://bank-verify.ru/login urgent within 24h",
           "join our vip signal group guaranteed profit"]
for _ in range(50000):
    text = rnd.choice(samples)
    msgs.append(build_record(text=text, urls=[], user_id=rnd.randrange(1000), chat_id=1,
                             entities={"mention": rnd.randrange(3)}))

_timed(f"DaC evaluate ({len(compiled)} rules, AC prefilter)", len(msgs),
       lambda: [rengine.evaluate(m, chat_id=1) for m in msgs])

# ---------------- Posture score ----------------
cat = {f"c{i}": Control(f"c{i}", f"C{i}", "x", weight=rnd.choice([1, 2, 3, 5]),
                        critical=(i % 7 == 0)) for i in range(20)}
lv = ["fail", "weak", "partial", "strong", "pass", "unknown"]
asmt = {cid: Assessment(cid, rnd.choice(lv)) for cid in cat}
_timed("Posture compute_score (20 controls)", 100000,
       lambda: [compute_score(cat, asmt) for _ in range(100000)])

print("\nnote: single-core, cold; indicative only.")
