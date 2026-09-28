# Changelog

## v0.7.0 — Blue Team Suite

เพิ่มชุดโมดูลป้องกันเชิงรับ (passive) 3 ตัว ในแพ็กเกจ `blueteam/` ต่อเข้าแพลตฟอร์มเดิม
(Event Bus + Workflow Engine + Plugins) แบบ additive โดยไม่แก้ flow มอเดอเรตเดิม

### Added

- **Link Guard** (`blueteam/linkguard.py`, `urlkit.py`, `reputation.py`, `netprobe.py`)
  - ดึง URL จากข้อความ + Telegram entities รองรับการพราง (hxxp, `[.]`, zero-width,
    IDN/punycode, mixed-script, user@host, IP เลขฐานสิบ/สิบหก/แปด, scheme แปลก,
    t.me) และตรวจ `text_link` ที่ข้อความกับ href คนละโดเมน
  - canonicalize + คีย์ SHA-256, eTLD+1 มี fallback ในตัว (ไม่พึ่ง dependency)
  - ชั้นออฟไลน์: lexical, เลียนแบบแบรนด์ (skeleton + Damerau-Levenshtein), TLD เสี่ยง,
    ตัวย่อลิงก์, free hosting — เร็วพอรันใน handler (p95 ~1–2 ms/ข้อความจริง)
  - reputation: allow/deny ต่อกลุ่ม + ฟีด URLhaus/OpenPhish
  - active probe แบบ opt-in: SSRF guard ครบ (ปฏิเสธ private/loopback/link-local/CGNAT/
    metadata, ตรวจทุก hop, ปักหมุด IP กัน DNS rebinding, จำกัด hop/ขนาด/เวลา, ไม่ส่ง
    cookie, parse ด้วย html.parser)
  - คำสั่ง `/linkguard`, `/linkcheck`
- **Scam & Impersonation** (`blueteam/scamguard.py`, `impersonation.py`, `textkit.py`)
  - rule pack ไทย/อังกฤษ (JSON + version + checksum, ReDoS-linted, คอมไพล์ล่วงหน้า)
  - campaign clustering ด้วย SimHash (ring buffer + LRU, memory-bounded)
  - สัญญาณพฤติกรรม + 3 preset ความไว + allow-list วลี + ยกเว้นแอดมิน
  - ตรวจปลอมเป็นแอดมิน/VIP (skeleton + Jaro-Winkler/Damerau-Levenshtein; dHash ถ้ามี Pillow)
  - คิวตรวจสอบสำหรับแอดมิน; คำสั่ง `/scamguard`
- **Join Guard / Anti-Raid** (`blueteam/joinguard.py`, `challenge.py`)
  - อัตราเข้ากลุ่มปรับตัว (EWMA + z-score, cold-start), time-bucket ring buffer O(1)
  - state machine NORMAL→ELEVATED→RAID→COOLDOWN พร้อม hysteresis
  - ด่านยืนยันตัวตน callback แบบ HMAC (≤64 ไบต์, กัน tamper/replay/คนอื่นกด)
  - ล็อกดาวน์ผ่าน setChatPermissions + snapshot สิทธิ์เดิม, กู้คืน idempotent,
    คงสถานะหลังรีสตาร์ท + dead-man switch; คำสั่ง `/joinguard`
- **correlator** เชื่อมสัญญาณข้ามโมดูลในหน้าต่างเวลา (memory-bounded)
- **workflows** เพิ่ม trigger/playbook: `link.flagged`, `scam.detected`, `raid.detected`,
  `blueteam.correlated` → incident + integrity anchor + admin alert; ทุก detection
  แนบ ATT&CK tag
- **dashboard** `/blueteam` สรุป 24h/7d + วิซาร์ด `/blueteam setup`
- **schema** `migrations/m0003_blueteam.py` (12 ตาราง `bt_*`, non-destructive, reversible)
- **feature flags** ต่อโมดูล + kill switch หลัก (แยกขายเป็น tier)
- เอกสาร `docs/blueteam/*`, README (ไทย), `.env.example`, `config.py` ENV_REGISTRY

### Tests

- ชุดทดสอบใหม่แบบ offline: `test_blueteam_foundation` (43), `test_blueteam_linkguard`
  (26, รวม SSRF/rebinding), `test_blueteam_scamguard` (17, recall/FP), 
  `test_blueteam_joinguard` (19, HMAC/state machine), `test_blueteam_integration`
  (15, event→workflow→incident) + `bench_blueteam.py`
- ชุดทดสอบเดิมทั้งหมดยังผ่าน (ไม่แก้ไฟล์เดิมนอกจากจุดเชื่อม additive)

### Security & privacy

- passive เท่านั้น; ไม่รันไฟล์/JavaScript; แบนถาวรต้องมีมนุษย์ยืนยัน
- ทุก query parameterized; ข้อมูล chat-scoped; ตอบเป็น plain text + defang URL
- external services + active probe เป็น opt-in และปิดค่าเริ่มต้น; retention ตั้งค่าได้
