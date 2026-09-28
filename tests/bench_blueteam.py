"""
tests/bench_blueteam.py — throughput + latency smoke benchmark for the Blue Team
offline pipeline (Link Guard tier 1-2 + Scam Guard).

Prints a table of p50/p95/p99 latency per message and messages/sec. Assertions are
deliberately LOOSE (so CI is not flaky on a slow shared runner) while the printed
numbers show the real p95 against the <5 ms target. Not named ``test_*`` so the
standard suite does not run it; invoke directly:

    python tests/bench_blueteam.py
"""

import os
import sys
import time
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import migrations
from blueteam.store import BlueTeamStore
from blueteam.linkguard import LinkGuard
from blueteam.scamguard import ScamGuard

SAMPLES = [
    ("benign", "สวัสดีครับทุกคน วันนี้ประชุมกี่โมง แล้วเจอกันนะ", None),
    ("link", "check https://paypa1-verify.zip/login-wallet now", None),
    ("textlink", "telegram.org", [{"type": "text_link", "offset": 0, "length": 12,
                                    "url": "http://free-nitro.tk/verify"}]),
    ("scam_th", "ลงทุนคริปโต การันตีกำไร 300% ต่อวัน ทักไลน์ด่วน แจ้งรหัส OTP", None),
    ("scam_en", "Work from home, earn $500 per day, DM me, claim your prize now", None),
    ("longish", "ทดสอบข้อความยาว " * 60 + " http://a.co/x", None),
]


def _pct(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(len(s) - 1, int(round(p / 100.0 * (len(s) - 1))))
    return s[idx]


def main() -> int:
    db = tempfile.mkstemp(suffix=".db")[1]
    migrations.apply_startup_migrations(db)
    store = BlueTeamStore(db)
    store.set_policy(-1, "linkguard", enabled=True, mode="MONITOR", threshold=45)
    store.set_policy(-1, "scamguard", enabled=True, mode="MONITOR", threshold=45)
    lg = LinkGuard(store)
    sg = ScamGuard(store)

    iters = 3000
    per_case = {}
    all_latencies = []
    t_start = time.perf_counter()
    for name, text, ents in SAMPLES:
        lat = []
        for i in range(iters):
            t0 = time.perf_counter()
            results = lg.analyze_message(-1, text, ents)
            lg.worst(results)
            sg.analyze(-1, text, user_id=(i % 50), sensitivity="balanced")
            lat.append((time.perf_counter() - t0) * 1000.0)
        per_case[name] = lat
        all_latencies.extend(lat)
    wall = time.perf_counter() - t_start
    total_msgs = iters * len(SAMPLES)
    store.close()
    os.remove(db)

    print("\nBlue Team offline pipeline benchmark (Link Guard t1-2 + Scam Guard)")
    print(f"{'case':<10} {'n':>6} {'p50 ms':>8} {'p95 ms':>8} {'p99 ms':>8} {'max ms':>8}")
    print("-" * 52)
    for name, lat in per_case.items():
        print(f"{name:<10} {len(lat):>6} {_pct(lat,50):>8.3f} {_pct(lat,95):>8.3f} "
              f"{_pct(lat,99):>8.3f} {max(lat):>8.3f}")
    overall_p95 = _pct(all_latencies, 95)
    throughput = total_msgs / wall
    print("-" * 52)
    print(f"overall    {total_msgs:>6} {_pct(all_latencies,50):>8.3f} "
          f"{overall_p95:>8.3f} {_pct(all_latencies,99):>8.3f} {max(all_latencies):>8.3f}")
    print(f"\nthroughput: {throughput:,.0f} msg/s  (single process, one thread)")
    print(f"target: offline p95 <= 5 ms/msg, >= 2000 msg/min")
    print(f"result: p95={overall_p95:.3f} ms, {throughput*60:,.0f} msg/min")

    # LOOSE assertions (avoid flakiness on shared CI); real numbers printed above.
    ok = overall_p95 < 50.0 and throughput * 60 >= 2000
    print("\n==== bench {} ====".format("OK" if ok else "SLOW"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
