"""เทส reference_data.fast_index — trigram inverted index + LRU cache (ค้นในไฟล์เร็ว offline)
ยึด whitelist เดิม (airports, programming-languages) — ไม่ใช่ engine ค้นทั่วไป
"""
import sys, os, logging, time
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)
logging.basicConfig(level=logging.ERROR)

from reference_data import fast_index as fi

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

# ---------- trigram helper ----------
tg = fi.trigrams("BKK")
check("trigram: pad หัวท้ายจับขอบคำ", " bk" in tg and "bkk" in tg and "kk " in tg, tg)
check("trigram: โทเคนสั้น <3 เก็บทั้งชิ้น", fi.trigrams("hi") == ["hi"])
check("trigram: ตัด accent + lowercase", fi.trigrams("Suárez") == fi.trigrams("suarez"))

# ---------- build + search พื้นฐาน ----------
RECS = [
    {"code": "BKK", "name": "Suvarnabhumi Airport", "city": "Bangkok"},
    {"code": "DMK", "name": "Don Mueang", "city": "Bangkok"},
    {"code": "CNX", "name": "Chiang Mai", "city": "Chiang Mai"},
    {"code": "HKT", "name": "Phuket", "city": "Phuket"},
    {"code": "LAX", "name": "Los Angeles", "city": "Los Angeles"},
]
idx = fi.FastIndex().build(RECS)
check("build: index มีครบทุก record", len(idx) == 5)

r = idx.search("bangkok")
check("search: เมือง 'bangkok' คืน 2 สนามบิน (BKK+DMK)",
      {x["code"] for x in r} == {"BKK", "DMK"}, [x["code"] for x in r])

r = idx.search("los ang", limit=3)
check("search: prefix หลายโทเคน 'los ang' -> LAX", r and r[0]["code"] == "LAX", r)

r = idx.search("Suvarnabumi")   # สะกดผิด (ตก h)
check("search: fuzzy สะกดผิด 'Suvarnabumi' -> BKK", r and r[0]["code"] == "BKK", r)

r = idx.search("chiang")
check("search: 'chiang' -> CNX", r and r[0]["code"] == "CNX", r)

check("search: คำค้นว่าง -> []", idx.search("   ") == [])
check("search: ไม่พบ -> []", idx.search("zzzznowhere") == [])

# ---------- ค้นภาษาไทย (฀-๿) ----------
check("thai: _deaccent ไม่ทำลายวรรณยุกต์/สระไทย", fi._deaccent("เชียงใหม่") == "เชียงใหม่")
check("thai: trigrams เก็บอักษรไทย", any("฀" <= ch <= "๿"
      for tri in fi.trigrams("กรุงเทพ") for ch in tri))
TH = [
    {"code": "BKK", "name": "ท่าอากาศยานสุวรรณภูมิ", "city": "กรุงเทพ"},
    {"code": "CNX", "name": "ท่าอากาศยานเชียงใหม่", "city": "เชียงใหม่"},
    {"code": "HKT", "name": "ท่าอากาศยานภูเก็ต", "city": "ภูเก็ต"},
]
tidx = fi.FastIndex().build(TH)
check("thai: ค้นเมืองภาษาไทย 'เชียงใหม่' -> CNX",
      (lambda r: bool(r) and r[0]["code"] == "CNX")(tidx.search("เชียงใหม่")))
check("thai: ค้นเมืองภาษาไทย 'กรุงเทพ' -> BKK",
      (lambda r: bool(r) and r[0]["code"] == "BKK")(tidx.search("กรุงเทพ")))
check("thai: ค้นบางส่วน 'ภูเก็ต' -> HKT",
      (lambda r: bool(r) and r[0]["code"] == "HKT")(tidx.search("ภูเก็ต")))

# ---------- candidate pre-filter: ไม่สแกนทุก doc ----------
# สร้างชุดใหญ่ แล้วยืนยันว่าค้นเร็ว (ผ่านได้แปลว่าไม่ scan เชิงเส้นทั้งหมดต่อคำค้น)
BIG = [{"code": f"C{i:05d}", "name": f"Placeholder Station {i}", "city": f"Town{i%97}"}
       for i in range(20000)]
BIG.append({"code": "ZZZ", "name": "Suvarnabhumi Airport", "city": "Bangkok"})
big_idx = fi.FastIndex().build(BIG)
t0 = time.time()
for _ in range(50):
    res = big_idx.search("suvarnabhumi", limit=3)
dt = time.time() - t0
check("scale: fuzzy บน 20k records ยังเจอ ZZZ", res and res[0]["code"] == "ZZZ", res)
check("scale: 50 คำค้นเร็ว (<1.5s) เพราะ pre-filter", dt < 1.5, f"{dt:.3f}s")

# ---------- LRU cache ----------
idx2 = fi.FastIndex(cache_size=2)
a = idx2.search("bangkok")
b = idx2.search("bangkok")
check("cache: ผลซ้ำเท่ากัน (hit)", [x["code"] for x in a] == [x["code"] for x in b])
check("cache: คืน copy (แก้ผลลัพธ์ไม่กระทบแคช)", (a.append("x"), idx2.search("bangkok") != a)[1])
idx2.search("chiang"); idx2.search("phuket")   # ดันเกิน cache_size=2
check("cache: ขนาดไม่เกินเพดาน", len(idx2._cache) <= 2)

# ---------- whitelist gating ----------
check("for_dataset: นอก whitelist -> None", fi.for_dataset("passwords.json") is None)
check("search(dataset): นอก whitelist -> []", fi.search("leaks.sql", "x") == [])

# dataset จริงใน whitelist (airports.json มีไฟล์ในเครื่อง) — สร้าง index + ค้นได้จริง
di = fi.for_dataset("airports.json")
if di is not None and len(di) > 0:
    check("for_dataset(airports): สร้าง index จากไฟล์จริงได้", len(di) > 0)
    check("for_dataset: แคช index (คืนอ็อบเจกต์เดิม)", fi.for_dataset("airports.json") is di)
    fi.invalidate("airports.json")
    check("invalidate: ล้างแล้วสร้างใหม่ (คนละอ็อบเจกต์)", fi.for_dataset("airports.json") is not di)
else:
    check("for_dataset(airports): ข้าม (ไม่มีไฟล์ในเครื่อง)", True)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
