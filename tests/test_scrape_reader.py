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

# ---------------- extract_content_and_files: เนื้อหาจริง ไม่เอาข้อความที่เป็นลิงก์ ----------------
_HTML = """
<html><head><title>Doc</title></head><body>
<nav><a href="/home">Home</a><a href="/about">About</a></nav>
<header>SiteName</header>
<article>
  <h1>Dr. Somchai Jaidee</h1>
  <p>Cardiologist at Bangkok Hospital with 20 years experience.</p>
  <p>Contact via <a href="/contact">this anchor text</a> for appointments.</p>
  <ul><li>Published research in 2021</li></ul>
  <a href="/files/cv.pdf">Download CV</a>
  <img src="/img/photo.jpg">
  <a href="/page.html">Related page</a>
</article>
<footer><a href="/privacy">Privacy Policy</a></footer>
</body></html>
"""
_text, _files = scrape.extract_content_and_files(_HTML, "https://example.com/doc")
check("extract: keeps real content", "Somchai" in _text and "Cardiologist" in _text, _text)
check("extract: drops nav link text", "Home" not in _text and "About" not in _text, _text)
check("extract: drops anchor text inside content", "this anchor text" not in _text, _text)
check("extract: drops footer link text", "Privacy" not in _text, _text)
check("extract: file link (pdf) detected", any(u.endswith("/files/cv.pdf") for u in _files), _files)
check("extract: image file detected", any(u.endswith("/img/photo.jpg") for u in _files), _files)
check("extract: non-file link (.html) NOT counted as file",
      not any(u.endswith("/page.html") for u in _files), _files)
check("extract: relative file url resolved against base",
      all(u.startswith("https://example.com/") for u in _files), _files)
check("extract: empty html safe",
      scrape.extract_content_and_files("", "") == ("", []))
check("extract: page without content tags falls back to text",
      "hello world" in scrape.extract_content_and_files("<div>hello world</div>", "")[0])

# ค่าคอนฟิก /search content-fetch เชื่อมกับ constants ที่มีจริง
check("scrape: MAX_EXTRACTED_TEXT_CHARS is int", isinstance(scrape.MAX_EXTRACTED_TEXT_CHARS, int))

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
