"""
tests/test_blueteam_scamguard.py — Scam & Impersonation Detector:
Thai/English scam recall on synthetic samples, false-positive control on normal
messages, sensitivity presets, admin/allow-phrase exemption, campaign clustering,
behavioural signals, and impersonation (homoglyph clone + near username + real
identity not flagged + graceful dHash without Pillow).

Standalone; fully offline; does not import telegram.
"""

import os
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import migrations
from blueteam.store import BlueTeamStore
from blueteam.scamguard import ScamGuard, CampaignTracker
from blueteam.impersonation import ImpersonationDetector, Target
from blueteam.models import Verdict

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


sg = ScamGuard()

SCAMS_TH = [
    "ลงทุนคริปโต การันตีกำไร 300% ต่อวัน ไม่มีความเสี่ยง ทักไลน์ด่วน",
    "รับสมัครงานพาร์ทไทม์ รายได้ 2000 บาทต่อวัน แค่กดไลก์ ทักแชทมาเลย",
    "ธนาคารแจ้ง บัญชีของคุณถูกระงับ กรุณายืนยันตัวตนที่ลิงก์ด่วน",
    "คุณคือผู้โชคดี ได้รับสิทธิ์รับเงินฟรี 5000 บาท กดรับที่นี่",
    "แจ้งรหัส OTP 6 หลักเพื่อยืนยันการรับรางวัล",
]
SCAMS_EN = [
    "Invest in crypto, guaranteed 300% return risk-free, DM me now",
    "Work from home, earn $500 per day, just click here",
    "Your account is suspended, verify your identity at this link",
    "Congratulations! You are a winner, claim your prize now",
    "Send the 6-digit verification code to unlock your account",
]
BENIGN = [
    "สวัสดีครับทุกคน วันนี้ประชุมกี่โมงครับ",
    "ขอบคุณสำหรับข้อมูลนะครับ เดี๋ยวผมลองอ่านดู",
    "ใครมีร้านกาแฟแนะนำแถวอโศกบ้างครับ",
    "พรุ่งนี้ฝนน่าจะตก อย่าลืมพกร่มกันนะ",
    "โค้ดรันได้แล้วครับ ขอบคุณที่ช่วยดู bug ให้",
    "hey everyone what time is the meeting today",
    "thanks for the info, I will read it later",
    "anyone know a good coffee shop near asoke",
    "the deploy passed, thanks for reviewing my PR",
]


def band(text, **kw):
    return sg.analyze(1, text, user_id=1, **kw).verdict


th_hit = sum(band(t) >= Verdict.SUSPICIOUS for t in SCAMS_TH)
en_hit = sum(band(t) >= Verdict.SUSPICIOUS for t in SCAMS_EN)
fp = sum(band(t) >= Verdict.SUSPICIOUS for t in BENIGN)
check("Thai scam recall (>=4/5)", th_hit >= 4, f"{th_hit}/5")
check("English scam recall (>=4/5)", en_hit >= 4, f"{en_hit}/5")
check("no false positives on normal messages", fp == 0, f"{fp} FPs")

a = sg.analyze(1, SCAMS_TH[0], user_id=1)
check("scam signals are explainable + ATT&CK-tagged",
      bool(a.attack_tags) and all(s.fact for s in a.signals))
check("scam categories surfaced", bool(a.meta.get("categories")))

relaxed = band("ลงทุนคริปโต การันตี ทักด่วน", sensitivity="relaxed")
strict = band("ลงทุนคริปโต การันตี ทักด่วน", sensitivity="strict")
check("sensitivity: strict >= relaxed severity", strict >= relaxed)

exempt = sg.analyze(1, SCAMS_TH[0], user_id=1, context={"is_admin": True})
check("admin exemption dampens verdict", exempt.verdict <= Verdict.LOW)
allow = sg.analyze(1, SCAMS_TH[0], user_id=1, allow_phrases=["การันตีกำไร 300%"])
check("allow-phrase dampens verdict", allow.verdict <= Verdict.LOW)

# campaign clustering across senders
ct = CampaignTracker(window_seconds=900, hamming_threshold=8)
sg2 = ScamGuard(campaign=ct)
msg = "ลงทุนคริปโตกำไรดี ทักไลน์ @richfast รับกำไรวันนี้เลย"
last = None
for uid in (11, 12, 13, 14):
    last = sg2.analyze(1, msg + ("!" * (uid - 11)), user_id=uid)
check("campaign clustering across senders",
      last.meta["campaign"]["distinct_users"] >= 3 and any(s.id == "campaign" for s in last.signals))
check("campaign tracker memory bounded",
      CampaignTracker(buffer=4).observe(1, 123, 1)[0] == 1)

# behavioural signals
b = sg.analyze(1, "สวัสดีครับ", user_id=99,
               context={"is_first_message": True, "has_link_or_contact": True, "link_score": 60})
check("behavioural: first-message-with-link + risky link",
      any(s.id == "first_msg_link" for s in b.signals) and any(s.id == "malicious_link" for s in b.signals))

# ---- impersonation ----
imp = ImpersonationDetector()
admins = [Target(user_id=1000, display_name="Somchai Admin", username="somchai_admin", role="admin")]
homoglyph = imp.check(1, 2000, "Somchаi Admin", "", admins=admins)  # Cyrillic 'а'
check("homoglyph display-name clone flagged", any(s.id == "impersonation" for s in homoglyph.signals))
near = imp.check(1, 2001, "x", "somchai_admln", admins=admins)
check("near username flagged", near.score > 0)
check("real admin not flagged", imp.check(1, 1000, "Somchai Admin", "somchai_admin", admins=admins).score == 0)
check("unrelated member not flagged", imp.check(1, 3000, "Malee Cat", "malee99", admins=admins).score == 0)
check("dHash degrades without Pillow", ImpersonationDetector.dhash(b"x") is None)

# VIP list from store feeds impersonation targets
db = tempfile.mkstemp(suffix=".db")[1]
migrations.apply_startup_migrations(db)
store = BlueTeamStore(db)
store.add_vip(1, user_id=500, display_name="CEO Ploy", username="ceo_ploy", role="vip", actor=1)
imp2 = ImpersonationDetector(store)
vip_imp = imp2.check(1, 600, "CEO Ploy", "", admins=[])
check("VIP impersonation from stored list", any(s.id == "impersonation" for s in vip_imp.signals))
store.close()
os.remove(db)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
