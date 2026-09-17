"""เทส reference_data.schema — คัดแยกบทบาทฟิลด์อัตโนมัติ (auto field classification)
และการต่อ fast_index แบบ text_fields="auto" (ไม่ต้องกำหนดฟิลด์ในโค้ด)
"""
import sys, os, logging
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)
logging.basicConfig(level=logging.ERROR)

from reference_data import schema as sch
from reference_data import fast_index as fi

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

RECS = [
    {"iata": "BKK", "icao": "VTBS", "name": "Suvarnabhumi Airport", "city": "Bangkok",
     "country": "TH", "lat": 13.68, "active": True, "note": ""},
    {"iata": "CNX", "icao": "VTCC", "name": "Chiang Mai International", "city": "Chiang Mai",
     "country": "TH", "lat": 18.77, "active": True, "note": ""},
    {"iata": "HKT", "icao": "VTSP", "name": "Phuket International", "city": "Phuket",
     "country": "TH", "lat": 8.11, "active": False, "note": ""},
]

# ---------- classify_fields: เดาบทบาทถูกต้อง ----------
roles = sch.classify_fields(RECS)["roles"]
check("classify: iata/icao เป็น code", roles["iata"] == "code" and roles["icao"] == "code")
check("classify: name/city เป็น text (ค้นได้)", roles["name"] == "text" and roles["city"] == "text")
check("classify: lat เป็น number", roles["lat"] == "number")
check("classify: active เป็น bool", roles["active"] == "bool")
check("classify: note (ว่างล้วน) เป็น ignore", roles["note"] == "ignore")

# ---------- detect_*: รายการฟิลด์ตามบทบาท ----------
tf = sch.detect_text_fields(RECS)
check("detect_text_fields: รวม text+code, ไม่รวม number/bool/ignore",
      "name" in tf and "iata" in tf and "lat" not in tf and "active" not in tf and "note" not in tf, tf)
check("detect_code_fields: มีเฉพาะ code", set(sch.detect_code_fields(RECS)) >= {"iata", "icao"}
      and "name" not in sch.detect_code_fields(RECS))

# ---------- ไม่ต้องกำหนดฟิลด์: ค้นผ่านฟิลด์ที่ตรวจได้อัตโนมัติ ----------
auto_idx = fi.FastIndex(text_fields=sch.detect_text_fields(RECS)).build(RECS)
r = auto_idx.search("Phuket", 3)
check("auto: ค้น 'Phuket' เจอ HKT", bool(r) and r[0]["iata"] == "HKT", [x["iata"] for x in r])
r2 = auto_idx.search("BKK", 1)
check("auto: ค้นรหัส 'BKK' เจอ", bool(r2) and r2[0]["icao"] == "VTBS")

# ---------- for_dataset(text_fields="auto") บนไฟล์จริง (ถ้ามี) ----------
if sch.dataset_manager.get_dataset_path("airports.json"):
    fi.invalidate("airports.json")
    di = fi.for_dataset("airports.json", text_fields="auto")
    check("for_dataset(auto): สร้าง index จากไฟล์จริงได้ (ฟิลด์อัตโนมัติ)",
          di is not None and len(di) > 0)
    if di:
        check("for_dataset(auto): ค้น BKK เจอ", bool(di.search("BKK", 1)))
    fi.invalidate("airports.json")
else:
    check("for_dataset(auto): ข้าม (ไม่มีไฟล์ airports ในเครื่อง)", True)

# ---------- classify_dataset: whitelist gating ----------
check("classify_dataset: นอก whitelist -> None", sch.classify_dataset("passwords.json") is None)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
