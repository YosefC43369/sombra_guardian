# tests/ — ชุดทดสอบ OSINT / search / scrape

เทสสำหรับส่วนที่เพิ่ม/แก้ในสาย `/search`, `/identity`, `/corporate`:
`search.py`, `scrape.py`, `osint.py`, `coordinator.py`, `nethealth.py`,
`username_osint.py`, `config.py` และ handler ใน `app.py`

## รันทั้งหมด

```bash
python tests/run_all.py
```

หรือรันทีละไฟล์ (แต่ละไฟล์ตั้ง exit code 0/1 เอง ไม่ต้องใช้ pytest):

```bash
python tests/test_darkweb_accuracy.py
```

## สิ่งที่ต้องมี

- `requests`, `beautifulsoup4` (อยู่ใน `requirements.txt` แล้ว)
- ไม่ต้องต่ออินเทอร์เน็ตหรือ Tor — ทุกเทสจำลอง engine/เว็บด้วย HTTP server
  ในเครื่อง (`http.server`) และ stub เฉพาะขอบนอก (เครือข่าย + AI)
- ทุกไฟล์คำนวณ repo root จากตำแหน่งตัวเอง จึงรันจาก cwd ไหนก็ได้

## ไฟล์

| ไฟล์ | ครอบคลุม |
|---|---|
| `test_integration.py` | ดึงลิงก์ onion, gateway/Tor routing, budget, cache |
| `test_tor_and_env.py` | ลำดับ Tor→gateway, PySocks หาย, อ่าน .env จริง |
| `test_osint.py` | selector/plan/rank/IOC/corroboration/defang/dossier/preset |
| `test_identity.py` | ชื่อบุคคล, โปรไฟล์โซเชียล, เชื่อมโยงตัวตนข้ามเว็บ, pivot |
| `test_darkweb_accuracy.py` | snippet, กรองข้ามเอนจิน, Ahmia web index, ranking/dedupe |
| `test_clearnet_fix.py` | แกะ redirect ของ engine เว็บเปิด, กรอง chrome/subdomain |
| `test_username.py` | ค้นบัญชีข้ามเว็บจากฐานข้อมูล resource/data.json |
| `test_pipeline.py` | ท่อเต็ม app.py → coordinator → osint → search/scrape → gemini |
| `test_efficiency.py` | circuit breaker, cache, early-stop, scrape สองจังหวะ, pivot |
| `test_degraded.py` | fallback เมื่อไฟล์บนเครื่องอัปเดตไม่ครบ |
| `test_startup.py` | main() บูตครบ, ตรวจความครบของโมดูล, สถานะ Tor |
