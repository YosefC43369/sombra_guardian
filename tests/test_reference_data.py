"""เทส reference_data (Google Drive storage layer) — ครบทั้ง 5 สถานการณ์ที่โจทย์ระบุ
โดยจำลอง Drive ด้วย monkeypatch (ไม่ต้องมี credential/เครือข่ายจริง)

Test 1: ไม่มี cache -> ดาวน์โหลด -> cache -> โหลด
Test 2: เรียกซ้ำใน TTL -> ใช้ cache ไม่ดาวน์โหลดซ้ำ (ไม่แม้แต่ถาม Drive)
Test 3: ไฟล์บน Drive เปลี่ยน -> ตรวจเจอ -> ดาวน์โหลดใหม่
Test 4: Drive ล่มแต่มี cache -> ใช้ cache ต่อได้
Test 5: ไฟล์นอก whitelist -> เพิกเฉย (ไม่ดาวน์โหลด/ไม่ index)
"""
import sys, os, json, hashlib, tempfile, pathlib, logging
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)
logging.basicConfig(level=logging.ERROR)

import reference_data.cache_manager as cache
import reference_data.drive_client as drive
import reference_data.dataset_manager as dm

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

def _md5(b): return hashlib.md5(b).hexdigest()

# cache ไปที่ temp dir (ไม่แตะ ./cache จริง)
cache.CACHE_DIR = pathlib.Path(tempfile.mkdtemp())

V1 = json.dumps({"airports": [{"code": "BKK", "name": "Suvarnabhumi", "city": "Bangkok", "country": "TH"}]}).encode()
V2 = json.dumps({"airports": [
    {"code": "BKK", "name": "Suvarnabhumi", "city": "Bangkok", "country": "TH"},
    {"code": "HND", "name": "Haneda", "city": "Tokyo", "country": "JP"}]}).encode()

state = {"content": V1, "find": 0, "dl": 0, "available": True, "md5_override": None}

def fake_is_configured():
    return True
def fake_find_file(name, allowed=None):
    state["find"] += 1
    if not state["available"]:
        return None
    if allowed is not None and name not in allowed:
        return None
    return {"file_id": "FID1", "name": name, "modified_time": "2026-01-01T00:00:00Z",
            "md5": state["md5_override"] or _md5(state["content"]), "size": len(state["content"])}
def fake_download(file_id, dest):
    state["dl"] += 1
    with open(dest, "wb") as f:
        f.write(state["content"])
    return True

drive.is_configured = fake_is_configured
drive.find_file = fake_find_file
drive.download = fake_download

# ---------- Test 1: cold -> download -> cache -> load ----------
state.update(find=0, dl=0)
p1 = dm.get_dataset_path("airports.json")
check("T1: ได้ path จาก cache", p1 and os.path.isfile(p1) and str(cache.cache_dir()) in p1, p1)
check("T1: ดาวน์โหลด 1 ครั้ง", state["dl"] == 1, state["dl"])
check("T1: เนื้อไฟล์ = V1", open(p1, "rb").read() == V1)
obj = dm.get_json("airports.json")
check("T1: parse JSON ได้ (1 สนามบิน)", obj and len(obj["airports"]) == 1, obj)

# ---------- Test 2: within TTL -> cache, no drive call ----------
state.update(find=0, dl=0)
p2 = dm.get_dataset_path("airports.json")
check("T2: ใช้ cache (ไม่ดาวน์โหลดซ้ำ)", state["dl"] == 0, state["dl"])
check("T2: ไม่แม้แต่ถาม Drive (TTL ยังไม่หมด)", state["find"] == 0, state["find"])
check("T2: get_json มาจาก RAM (path เดิม)", dm.get_json("airports.json") is obj)

# ---------- Test 3: drive file changed -> re-download ----------
cache.CACHE_TTL = 0            # บังคับให้แวะถาม Drive ทุกครั้ง
state.update(content=V2, find=0, dl=0)
p3 = dm.get_dataset_path("airports.json")
check("T3: ตรวจเจอเวอร์ชันใหม่แล้วดาวน์โหลด", state["dl"] == 1, state["dl"])
check("T3: เนื้อไฟล์อัปเดตเป็น V2", open(p3, "rb").read() == V2)
check("T3: get_json เห็นข้อมูลใหม่ (2 สนามบิน)", len(dm.get_json("airports.json")["airports"]) == 2)

# ---------- Test 4: drive unavailable but cache exists ----------
state.update(available=False, find=0, dl=0)
p4 = dm.get_dataset_path("airports.json")
check("T4: Drive ล่ม -> ยังคืน cache", p4 and os.path.isfile(p4), p4)
check("T4: ไม่ดาวน์โหลด (ใช้ cache)", state["dl"] == 0, state["dl"])
check("T4: get_json ยังทำงาน (2 สนามบิน)", len(dm.get_json("airports.json")["airports"]) == 2)
state["available"] = True

# ---------- Test 5: unrelated file ignored ----------
state.update(find=0, dl=0)
check("T5: ไฟล์นอก whitelist -> None", dm.get_dataset_path("passwords.json") is None)
check("T5: ไม่ถาม/ดาวน์โหลดไฟล์นอก whitelist", state["find"] == 0 and state["dl"] == 0)
check("T5: whitelist มีแค่ 2 ไฟล์อ้างอิง",
      dm.ALLOWED_DATASETS == {"airports.json", "programming-languages.json"})

# ---------- integrity: md5 ไม่ตรง -> ปฏิเสธ (ไม่ทำ cache เสีย) ----------
cache.clear_disk("airports.json")
state.update(content=V1, md5_override="deadbeef" * 4, find=0, dl=0)
p6 = dm.get_dataset_path("airports.json")
# md5 ไม่ตรง = ไม่รับไฟล์เข้า cache (ไม่ทำ cache เสีย) แล้วถอยไปใช้ไฟล์ในเครื่อง
check("integrity: ไม่สร้าง cache จากไฟล์ที่ md5 ไม่ตรง", not cache.cache_exists("airports.json"))
check("integrity: ถอยไปใช้ไฟล์ในเครื่อง (resource/)",
      p6 is not None and p6.endswith("resource/airports.json"), p6)
state["md5_override"] = None

# ---------- cache_manager unit ----------
tmpf = cache.cache_dir() / "x.json"
cache._ensure_dir(); tmpf.write_bytes(b'{"a":1}')
check("cache: file_md5 ตรง", cache.file_md5(tmpf) == _md5(b'{"a":1}'))
cache.save_meta("x.json", {"md5": _md5(b'{"a":1}'), "file_id": "F"})
check("cache: meta round-trip", cache.load_meta("x.json")["file_id"] == "F")
check("cache: verify_integrity ผ่านเมื่อ md5 ตรง", cache.verify_integrity("x.json", _md5(b'{"a":1}')))
check("cache: verify_integrity ล้มเมื่อ md5 ผิด", not cache.verify_integrity("x.json", "zzzz"))
check("cache: is_current True เมื่อ md5 ตรง",
      cache.is_current("x.json", {"md5": _md5(b'{"a":1}'), "file_id": "F"}))
check("cache: is_current False เมื่อ md5 ต่าง",
      not cache.is_current("x.json", {"md5": "other", "file_id": "F"}))

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
