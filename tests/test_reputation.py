"""เทส reputation.py — Community Reputation Engine (คะแนนน้ำใจ + decay + anti-abuse)"""
import sys, os, tempfile, logging
from datetime import datetime, timezone, timedelta
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)
logging.basicConfig(level=logging.ERROR)

import reputation as R

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

def _p():
    return os.path.join(tempfile.mkdtemp(), "rep.json")

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
CHAT = -100555

# ---------- tiers & weight ----------
check("tier: 0 -> หน้าใหม่", R.tier_for(0)[1] == "newcomer")
check("tier: 30 -> น่าเชื่อถือ", R.tier_for(30)[1] == "trusted")
check("tier: 999 -> ตำนาน (สูงสุด)", R.tier_for(999)[1] == "legend")
check("weight: ปิด weighted = 1.0", R.giver_weight(500, False) == 1.0)
check("weight: newcomer < legend", R.giver_weight(0, True) < R.giver_weight(500, True))

# ---------- give พื้นฐาน ----------
P = _p()
r = R.give(CHAT, 1, 2, 1, "ช่วยตอบคำถาม", giver_name="@a", receiver_name="@b", now=T0, path=P)
check("give: สำเร็จ", r["ok"] and r["amount"] == 1)
check("give: คะแนนผู้รับ > 0", R.current_score(CHAT, 2, now=T0, path=P) > 0)

# ---------- anti-abuse ----------
check("abuse: ให้ตัวเองไม่ได้", R.give(CHAT, 2, 2, 1, now=T0, path=P)["error"] == "self")
check("abuse: ให้บอตไม่ได้",
      R.give(CHAT, 5, 9, 1, receiver_is_bot=True, now=T0, path=P)["error"] == "bot")
check("abuse: cooldown (ให้คนเดิมซ้ำ)", R.give(CHAT, 1, 2, 1, now=T0, path=P)["error"] == "cooldown")
check("abuse: เกินเพดานต่อครั้ง (max_amount=3)",
      R.give(CHAT, 6, 2, 99, now=T0, path=P)["error"] == "bad_amount")
check("abuse: หักคะแนนไม่ได้ (allow_negative=False)",
      R.give(CHAT, 7, 2, -1, now=T0, path=P)["error"] == "negative_not_allowed")

# ---------- daily budget ----------
Pb = _p()
R.set_config(CHAT, "daily_budget", "2", path=Pb)
R.give(CHAT, 10, 20, 1, now=T0, path=Pb)
R.give(CHAT, 10, 21, 1, now=T0, path=Pb)      # ใช้ครบ 2
over = R.give(CHAT, 10, 22, 1, now=T0, path=Pb)
check("budget: เกินโควตารายวัน -> error budget", over["error"] == "budget")
# วันถัดไปรีเซ็ต
nxt = R.give(CHAT, 10, 22, 1, now=T0 + timedelta(days=1), path=Pb)
check("budget: วันใหม่รีเซ็ตโควตา", nxt["ok"])

# ---------- time-decay (half-life) ----------
Pd = _p()
R.set_config(CHAT, "halflife_days", "10", path=Pd)
R.set_config(CHAT, "weighted", "off", path=Pd)       # ตัดน้ำหนักเพื่อเช็ค decay ตรง ๆ
R.give(CHAT, 30, 40, 2, now=T0, path=Pd)
s0 = R.current_score(CHAT, 40, now=T0, path=Pd)
s10 = R.current_score(CHAT, 40, now=T0 + timedelta(days=10), path=Pd)
check("decay: ครบ 1 ครึ่งชีวิต -> ~ครึ่งหนึ่ง", abs(s10 - s0 / 2) < 0.11, f"{s0}->{s10}")

# ---------- leaderboard / rank ----------
Pl = _p()
R.give(CHAT, 1, 100, 3, now=T0, path=Pl)
R.give(CHAT, 2, 100, 2, now=T0, path=Pl)
R.give(CHAT, 1, 200, 1, now=T0, path=Pl)
lead = R.leaderboard(CHAT, 5, now=T0, path=Pl)
check("leaderboard: เรียงคะแนนมากไปน้อย (100 นำ 200)",
      lead[0]["user_id"] == "100" and lead[0]["score"] >= lead[1]["score"])
rk = R.rank_of(CHAT, 200, now=T0, path=Pl)
check("rank: อันดับ 2 จาก 2 คน", rk and rk["rank"] == 2 and rk["total"] == 2)
check("rank: ไม่มีคะแนน -> None", R.rank_of(CHAT, 999, now=T0, path=Pl) is None)

# ---------- undo ----------
Pu = _p()
R.give(CHAT, 1, 2, 2, "เผลอให้", now=T0, path=Pu)
before = R.current_score(CHAT, 2, now=T0, path=Pu)
u = R.undo_last(CHAT, 1, now=T0 + timedelta(seconds=10), path=Pu)
check("undo: สำเร็จภายในเวลา", u["ok"] and u["to"] == "2")
check("undo: คะแนนกลับเป็น 0", R.current_score(CHAT, 2, now=T0, path=Pu) == 0 and before > 0)
check("undo: ไม่มีอะไรให้ถอน -> nothing", R.undo_last(CHAT, 1, now=T0, path=Pu)["error"] == "nothing")
# เลยเวลา
Pu2 = _p()
R.give(CHAT, 3, 4, 1, now=T0, path=Pu2)
check("undo: เลยหน้าต่างเวลา -> expired",
      R.undo_last(CHAT, 3, now=T0 + timedelta(hours=1), path=Pu2)["error"] == "expired")

# ---------- profile / trend / digest / diversity ----------
Pp = _p()
R.give(CHAT, 1, 50, 3, "ดีมาก", now=T0, path=Pp)
R.give(CHAT, 2, 50, 3, now=T0 + timedelta(days=1), path=Pp)
prof = R.get_profile(CHAT, 50, now=T0 + timedelta(days=1), path=Pp)
check("profile: มี score/tier/rank/trend", all(k in prof for k in ("score", "tier", "rank", "trend")))
check("profile: diversity นับผู้ให้ต่างกัน 2 คน", prof["diversity"]["distinct"] == 2)
check("digest: มีหัวข้อสรุปสัปดาห์", "สรุปน้ำใจ" in R.format_digest(CHAT, now=T0 + timedelta(days=1), path=Pp))
gains = R.week_gains(CHAT, 5, now=T0 + timedelta(days=1), path=Pp)
check("week_gains: มีผู้ใช้ 50 โตขึ้น", any(g["user_id"] == "50" for g in gains))

# ---------- config ----------
Pc = _p()
check("config: set bool", R.set_config(CHAT, "enabled", "off", path=Pc)["ok"])
check("config: disabled -> ให้ไม่ได้", R.give(CHAT, 1, 2, 1, now=T0, path=Pc)["error"] == "disabled")
check("config: unknown key", R.set_config(CHAT, "nope", "1", path=Pc)["error"] == "unknown_key")
check("config: ค่าติดลบไม่ได้", R.set_config(CHAT, "daily_budget", "-1", path=Pc)["error"] == "negative")
R.reset_config(CHAT, path=Pc)
check("config: reset -> enabled กลับมา", R.get_config(CHAT, path=Pc)["enabled"] is True)

# ---------- namespace / persistence ----------
Pn = _p()
R.give(CHAT, 1, 2, 1, now=T0, path=Pn)
check("namespace: กลุ่มอื่นคะแนน 0", R.current_score(-999, 2, now=T0, path=Pn) == 0)
import json
raw = json.load(open(Pn, encoding="utf-8"))
check("persist: เขียนไฟล์จริง แยก chat", str(CHAT) in raw and "users" in raw[str(CHAT)])

# ---------- formatting ----------
fp = R.format_profile(R.get_profile(CHAT, 2, now=T0, path=Pn))
check("format_profile: มีเหรียญ+หัวข้อ", "โปรไฟล์ชื่อเสียง" in fp)
fl = R.format_leaderboard(R.leaderboard(CHAT, 5, now=T0, path=Pn))
check("format_leaderboard: มีหัวข้อ", "กระดานผู้นำ" in fl or "ยังว่าง" in fl)
check("format_give_result(ok): มี +", "ให้คะแนน" in R.format_give_result(
    {"ok": True, "amount": 1, "weight": 1.0, "new_score": 1.0, "tier": (0, "newcomer", "หน้าใหม่", "🌱"),
     "budget_left": 4, "leveled_up": False}, "@a", "@b"))
check("format_give_result(err): แปล error", "ตัวเอง" in R.format_give_result({"ok": False, "error": "self"}, None, None))

# ---------- prune ----------
Ppr = _p()
R.set_config(CHAT, "halflife_days", "1", path=Ppr)
R.give(CHAT, 1, 2, 1, now=T0, path=Ppr)
st = R.prune_chat(CHAT, now=T0 + timedelta(days=30), path=Ppr)   # เก่ามาก -> ตัด event
check("prune: ตัด event เก่าที่เสื่อมหมด", st["events_pruned"] >= 1, st)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
