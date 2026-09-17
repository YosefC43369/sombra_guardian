"""เทส notes.py — คลังบันทึกกลุ่ม (Group Notes / Saved Tags)"""
import sys, os, json, tempfile, logging
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)
logging.basicConfig(level=logging.ERROR)

import notes

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

# ไฟล์ทดสอบแยก (ไม่แตะไฟล์จริง)
_TMP = os.path.join(tempfile.mkdtemp(), "notes.json")
CHAT = -100123
CHAT2 = -100999

# ---------- normalize_key ----------
check("key: ตัด #/ นำหน้า + lower", notes.normalize_key("#Rules") == "rules")
check("key: ไทยได้", notes.normalize_key("กติกา") == "กติกา")
check("key: มีช่องว่าง -> None", notes.normalize_key("a b") is None)
check("key: ว่าง -> None", notes.normalize_key("  ") is None)

# ---------- add / get ----------
r = notes.add_note(CHAT, "rules", "ห้ามสแปม ห้ามหยาบคาย", author="somchai", path=_TMP)
check("add: สำเร็จ (ไม่ทับ)", r["ok"] and r["replaced"] is False and r["key"] == "rules")
n = notes.get_note(CHAT, "rules", path=_TMP)
check("get: คืนข้อความถูก", n and n["text"] == "ห้ามสแปม ห้ามหยาบคาย" and n["author"] == "somchai")
check("get: uses เริ่มที่ 0", n["uses"] == 0)

# ---------- get + bump ----------
notes.get_note(CHAT, "rules", bump=True, path=_TMP)
n2 = notes.get_note(CHAT, "#RULES", bump=True, path=_TMP)   # เรียกด้วย #/ตัวใหญ่ ก็ต้องเจอ
check("get(bump): uses เพิ่มขึ้น + key ไม่สนรูปแบบ", n2["uses"] == 2, n2.get("uses"))

# ---------- replace ----------
r2 = notes.add_note(CHAT, "rules", "กติกาใหม่", author="admin2", path=_TMP)
check("add: ทับของเดิม (replaced=True)", r2["ok"] and r2["replaced"] is True)
n3 = notes.get_note(CHAT, "rules", path=_TMP)
check("replace: ข้อความอัปเดต แต่ uses/created คงไว้", n3["text"] == "กติกาใหม่" and n3["uses"] == 2)

# ---------- validation ----------
check("add: key ผิด -> error bad_key", notes.add_note(CHAT, "a b", "x", path=_TMP)["error"] == "bad_key")
check("add: ข้อความว่าง -> error empty_text", notes.add_note(CHAT, "empty", "   ", path=_TMP)["error"] == "empty_text")
check("add: ข้อความยาวเกิน -> too_long",
      notes.add_note(CHAT, "big", "x" * (notes.MAX_TEXT_LEN + 1), path=_TMP)["error"] == "too_long")

# ---------- namespace แยกตามกลุ่ม ----------
notes.add_note(CHAT2, "welcome", "ยินดีต้อนรับกลุ่มสอง", path=_TMP)
check("namespace: กลุ่มอื่นไม่เห็น note กลุ่มนี้", notes.get_note(CHAT2, "rules", path=_TMP) is None)
check("namespace: กลุ่มสองมี note ของตัวเอง", notes.get_note(CHAT2, "welcome", path=_TMP)["text"].startswith("ยินดี"))

# ---------- list / count ----------
notes.add_note(CHAT, "link", "https://example.com", path=_TMP)
lst = notes.list_notes(CHAT, path=_TMP)
check("list: เรียง key ถูก (rules/link/...)", "rules" in lst and "link" in lst and lst == sorted(lst))
check("count: นับถูก", notes.note_count(CHAT, path=_TMP) == len(lst))

# ---------- del ----------
check("del: ลบสำเร็จ", notes.del_note(CHAT, "link", path=_TMP) is True)
check("del: ลบซ้ำ -> False", notes.del_note(CHAT, "link", path=_TMP) is False)
check("del: หายจริง", notes.get_note(CHAT, "link", path=_TMP) is None)

# ---------- persistence (อ่านไฟล์ใหม่) ----------
raw = json.load(open(_TMP, encoding="utf-8"))
check("persist: เขียนลงไฟล์จริง แยก chat", str(CHAT) in raw and str(CHAT2) in raw and "rules" in raw[str(CHAT)])

# ---------- limit ----------
_LIM = os.path.join(tempfile.mkdtemp(), "n.json")
orig = notes.MAX_NOTES_PER_CHAT
notes.MAX_NOTES_PER_CHAT = 3
try:
    for i in range(3):
        notes.add_note(777, f"k{i}", "v", path=_LIM)
    over = notes.add_note(777, "k3", "v", path=_LIM)
    check("limit: เกินเพดาน -> error limit", over["error"] == "limit")
    check("limit: ทับ key เดิมได้แม้เต็ม", notes.add_note(777, "k0", "v2", path=_LIM)["ok"] is True)
finally:
    notes.MAX_NOTES_PER_CHAT = orig

# ---------- formatting ----------
fn = notes.format_note("rules", {"text": "กติกาใหม่", "uses": 5})
check("format_note: มี 📌 + #rules + จำนวนครั้ง", "📌" in fn and "#rules" in fn and "5 ครั้ง" in fn)
fl = notes.format_list(CHAT, notes.list_notes(CHAT, path=_TMP))
check("format_list: มีหัวข้อ + key", "คลังบันทึกกลุ่ม" in fl and "#rules" in fl)
check("format_list: ว่าง -> ข้อความแนะนำ", "ยังว่าง" in notes.format_list(999, []))

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
