"""เทสตัวช่วยดึงเนื้อหาเว็บกันบอทใน scrape.py (reader-proxy fallback)
นำเข้า scrape (ต้องมี requests/bs4 ตาม requirements) — ทดสอบเฉพาะตรรกะ ไม่แตะเครือข่าย
"""
import sys, os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)

import scrape

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

# _looks_blocked: หน้า challenge / สั้นเกิน = ถือว่ายังไม่ได้เนื้อจริง
check("blocked: หน้า Cloudflare challenge", scrape._looks_blocked("Just a moment... Checking your browser") is True)
check("blocked: enable JavaScript", scrape._looks_blocked("Please enable JavaScript to continue") is True)
check("blocked: เนื้อหาจริง (แม้สั้น) = ไม่บล็อก", scrape._looks_blocked("นพ. สมชาย ใจดี") is False)
check("blocked: เนื้อหาจริงยาว = ไม่บล็อก", scrape._looks_blocked("A" * 400) is False)
check("blocked: ว่าง/None", scrape._looks_blocked("") is True and scrape._looks_blocked(None) is True)

# ค่าคอนฟิก reader มีจริงและเปิดโดยดีฟอลต์
check("config: reader เปิดโดยดีฟอลต์", scrape.SCRAPE_READER_FALLBACK is True)
check("config: reader prefix เป็น r.jina.ai", scrape.SCRAPE_READER_PROXY == "https://r.jina.ai/",
      scrape.SCRAPE_READER_PROXY)

# ปิด fallback แล้ว _fetch_via_reader ต้องคืน None ทันที (ไม่ยิงเครือข่าย)
_orig = scrape.SCRAPE_READER_FALLBACK
scrape.SCRAPE_READER_FALLBACK = False
try:
    check("reader: ปิดแล้วคืน None", scrape._fetch_via_reader("https://example.com") is None)
finally:
    scrape.SCRAPE_READER_FALLBACK = _orig

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
