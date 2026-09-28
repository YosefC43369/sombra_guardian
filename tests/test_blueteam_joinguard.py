"""
tests/test_blueteam_joinguard.py — Join Guard / Anti-Raid:
HMAC challenge callbacks (tamper / wrong-user / wrong-chat / replay-via-store,
<=64 bytes), adaptive join-rate anomaly, the raid state machine with hysteresis
(fake clock), name-signature clustering, and lockdown snapshot/restore across a
simulated restart (dead-man switch).

Standalone; fully offline; does not import telegram.
"""

import os
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import migrations
from blueteam.store import BlueTeamStore
from blueteam import challenge as ch
from blueteam.joinguard import JoinGuard, JoinGuardParams, RaidState

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


SECRET = "unit-test-secret"

# ---- challenge HMAC ----
c = ch.build_challenge(ttl_seconds=120, num_choices=4)
buttons = c.buttons(SECRET, chat_id=-1001, user_id=555)
check("callback_data within 64 bytes", all(len(cb) <= 64 for _, cb in buttons))
correct = [cb for (label, tok), (_, cb) in zip(c.choices, buttons) if tok == c.answer][0]
ok, choice, nonce = ch.verify_callback(SECRET, -1001, 555, correct)
check("valid callback verifies", ok and choice == c.answer and nonce == c.nonce)
tampered = correct[:-2] + ("AA" if not correct.endswith("AA") else "BB")
check("tampered callback rejected", not ch.verify_callback(SECRET, -1001, 555, tampered)[0])
check("wrong user rejected (binding)", not ch.verify_callback(SECRET, -1001, 999, correct)[0])
check("wrong chat rejected", not ch.verify_callback(SECRET, -2002, 555, correct)[0])
check("wrong secret rejected", not ch.verify_callback("other", -1001, 555, correct)[0])
check("garbage callback rejected", not ch.verify_callback(SECRET, -1001, 555, "xx:1:2:3")[0])

db = tempfile.mkstemp(suffix=".db")[1]
migrations.apply_startup_migrations(db)
store = BlueTeamStore(db)
store.create_challenge(-1001, 555, c.nonce, c.answer, 120)
check("challenge starts PENDING", store.get_challenge(-1001, 555)["status"] == "PENDING")
store.set_challenge_status(-1001, 555, "PASSED")
check("replay guard: not PENDING after pass", store.get_challenge(-1001, 555)["status"] == "PASSED")

# ---- state machine (fake clock) ----
p = JoinGuardParams(window_seconds=60, min_samples=5, cold_elevated=6, cold_raid=12,
                    hard_raid=20, cooldown_rate=3, min_dwell_seconds=30)
jg = JoinGuard(store=store, params=p, clock=lambda: 0.0)
t = [0.0]


def join(name, invite="", chat=-2001):
    return jg.observe_join(chat, display_name=name, invite=invite, now=t[0])


for i, n in enumerate(["Alice", "Bob", "Charlie"]):
    t[0] = i * 20.0
    d = join(n)
check("diverse trickle stays NORMAL", d.state == RaidState.NORMAL, d.state.value)

for i in range(15):
    t[0] = 100.0 + i
    d = join(f"raidbot_{i}", invite="INV1")
check("burst of similar joins => RAID", d.state == RaidState.RAID and d.lockdown_required)
check("raid requires challenge + lockdown", d.challenge_required and d.lockdown_required)
check("raid signals explainable", any(s.id in ("join_rate_anomaly", "name_cluster") for s in d.assessment.signals))
check("raid state persisted", store.get_raid_state(-2001)["state"] == "RAID")

t[0] = 118.0
d = join("realuser")
check("hysteresis: stays RAID before dwell", d.state == RaidState.RAID)
t[0] = 210.0
d = join("realuser2")
check("de-escalates after quiet + dwell", d.state in (RaidState.COOLDOWN, RaidState.NORMAL))

# ---- lockdown snapshot survives restart (dead-man switch) ----
store.save_perm_snapshot(-2001, {"can_send_messages": True, "can_send_media_messages": True},
                         lockdown_until=99999)
store.close()
store2 = BlueTeamStore(db)  # simulate a restart
snap = store2.get_perm_snapshot(-2001)
check("permission snapshot survives restart", bool(snap) and snap["permissions"]["can_send_messages"] is True)
check("dead-man switch can find active lockdowns", any(s["chat_id"] == -2001 for s in store2.active_lockdowns()))
store2.clear_perm_snapshot(-2001)
check("lockdown restore is idempotent (cleared)", store2.get_perm_snapshot(-2001) is None)
store2.close()
os.remove(db)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
