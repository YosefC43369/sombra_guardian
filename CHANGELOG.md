# Changelog

## v0.8.0 — Blue Team Intelligence & Governance

เพิ่มโมดูลป้องกันเชิงรับ (passive) อีก 3 ตัวบนแพลตฟอร์มร่วม (`blueteam/platform/`)
ต่อเข้าระบบเดิมแบบ additive ด้วยปลั๊กอินเดียว (`plugins/builtin/blueteam_v08.py`)
สถาปัตยกรรมแบบชั้น (domain บริสุทธิ์ → services → adapters → handlers) พร้อม
architecture fitness tests ห้าม cycle/ห้าม domain นำเข้า telegram/sqlite

### Added

- **Threat Intel & IOC platform** (`blueteam/intel/`)
  - โมเดล IOC กลาง (url/domain/ip/cidr/hash/email/t.me/wallet/advisory) +
    canonicalization ร่วมกับ Link Guard, โมเดลความมั่นใจอธิบายได้ (noisy-OR ×
    freshness decay), ส่งออก STIX 2.1-lite แบบ deterministic (UUIDv5)
  - เอนจินค้นหาสมรรถนะสูง: exact set + reverse-label trie (จับ subdomain) +
    ช่วง CIDR เรียง + bisect + Bloom filter เขียนเอง + LRU + สลับ snapshot แบบ
    double-buffer (อ่านไม่ต้องล็อก) — พิสูจน์ถูกต้องเทียบ brute force
  - เฟรมเวิร์กฟีด (URLhaus/ThreatFox/MalwareBazaar/CISA-KEV/OpenPhish): SSRF guard,
    conditional GET, กันระเบิดบีบอัด, ingest แบบ staged/atomic, กัน feed poisoning
    (whitelist + growth quarantine), เช็กเงื่อนไข license (ไม่ชัวร์ = ปิดเป็นค่าเริ่ม)
  - คำสั่ง `/intel status|feeds|sync|lookup|add|del|whitelist|sightings|export|stats|health`
- **Detection-as-Code engine** (`blueteam/dac/`)
  - กฎ Sigma-lite JSON คอมไพล์เป็น closure — **ไม่มี eval/exec/compile** เด็ดขาด
    (lexer → recursive-descent parser → AST → optimizer → closure), มี field
    modifiers, ReDoS lint, งบจำนวนโหนด AST
  - Aho-Corasick prefilter, aggregation แบบ stateful (count/distinct บน ring buffer
    ตามเวลา), วงจร lifecycle (shadow→canary→enabled + rollback + version hash-chain),
    circuit breaker ต่อกฎ, ชุดกฎเริ่มต้น 37 กฎ (ไทย/อังกฤษ)
  - คำสั่ง `/rule list|show|import|enable|disable|shadow|canary|rollback|lint|backtest|history|stats|pack`
- **Security Posture Score & Client Report** (`blueteam/posture/`)
  - คะแนนโปร่งใส `Σ(w·s·c)/Σ(w·c)` (UNKNOWN ไม่นับในตัวหาร), deterministic +
    monotonic + gating, อธิบายได้ (`explain`/`whatif`), rollup รายชั่วโมง (ไม่สแกน
    เหตุการณ์ดิบ), พอร์ตโฟลิโอหลายกลุ่ม
  - รายงาน HTML แบบ self-contained (CSS inline + SVG วาดเอง, ไม่มี JS, CSP, `@page`
    สำหรับ PDF, ฟอนต์ไทย) + MD/JSON/CSV, โปรไฟล์ client (ปกปิด)/internal, ผนึก
    SHA-256 ลง integrity ledger + `/posture verify`, white-label branding
  - คำสั่ง `/posture status|score|explain|whatif|trend|report|brand|portfolio|verify|export`
- **Shared platform** (`blueteam/platform/`): event contracts มีเวอร์ชัน, metrics
  registry, write-behind batcher, scheduler (lease/jitter/catch-up-once),
  circuit breaker, tenancy (isolation ระดับ repository), typed config, DI container
- Migration `m0004` (15 ตาราง `bt_*`, ย้อนกลับได้), เอกสาร `docs/blueteam/` + ADR
  `docs/adr/`, benchmark `tests/bench_intel_dac_posture.py`

### Changed (additive, จุดเชื่อมเท่านั้น)

- `blueteam/reputation.py`: hook `IntelProvider` (ออปชัน; ค่าเริ่ม None = พฤติกรรมเดิม)
- `purpleteam_report.py`: ส่วนสรุป DAC rule coverage (รับข้อมูลเข้า, ไม่ผูกพันเพิ่ม)
- `config.py` + `.env.example`: ตัวแปร env ของ v0.8, `__version__` → 0.8.0

### Security

- ไม่มี eval/exec/compile กับกฎ · SSRF guard บนทุกฟีด · กันระเบิดบีบอัด · ReDoS lint ·
  กัน XSS/CSV/CSS injection ในรายงาน · defang IOC ทุกครั้งใน event/ข้อความ · SQL
  พารามิเตอร์ล้วน · แยก tenant ต่อกลุ่ม · detection แบบ fail-open, สิทธิ์แบบ fail-closed ·
  ไม่ส่งเนื้อหาข้อความออกนอกระบบ (egress opt-in, ปิดค่าเริ่ม)

### Tests

175 เคสใหม่ (offline, stdlib, deterministic): arch 5, platform 24, intel 55, dac 48,
posture 33, wiring 10 — ผ่านทั้งหมด; ไม่กระทบของเดิม (reputation 38, linkguard 26)

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
