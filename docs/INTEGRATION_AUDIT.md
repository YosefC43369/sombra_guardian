# Integration, Architecture & Security Audit — Sombra Guardian Red Team Platform

รายงาน audit ทั้งโปรเจกต์ (เน้นโมดูลออฟเฟนซ์/ความปลอดภัยที่เพิ่มเข้ามา + การเชื่อมต่อกับแกนเดิม)
ทุกข้อสรุปมาจากการตรวจจริง (import/registration/test รันจริง) ไม่ใช่การอนุมานจากชื่อไฟล์

สถานะรวม: **ผ่าน — เป็นแพลตฟอร์มเดียวที่เชื่อมกันจริง** · แก้ 1 รายการ (ยุบ Notifier ซ้ำ) · ไม่มี regression

---

## 1. Module inventory

**แกนเดิม (ไม่แตะ):** `app.py` (entry point, dispatcher, event handlers), `config.py`/`envutil.py`
(config), `security.py`+`scope_policy.py`+`integrity_ledger.py` (DB `bot.db` + audit + authorization),
`gemini.py` (AI client เดียว), `sg_platform.py`+`workflows/`+`plugins/` (workflow/plugin engine),
`osint/`+`osint.py`+`search.py`+`scrape.py` (recon/HTTP backbone), `security_testing.py`+`bb_scan.py`
(passive checks), `redteam.py`/`purpleteam.py` (governance), `member_*`/`detection.py` (moderation).

**โมดูลที่เพิ่ม (9):**
| โมดูล | บทบาท | คำสั่ง | ลงทะเบียน |
|---|---|---|---|
| `urlkit` | eTLD+1/URL utils (stdlib) | — | import โดยหลายโมดูล |
| `autolink` | โพสต์ลิงก์ตามรอบในห้องตัวเอง | `/autolink` | direct handler + loop |
| `broadcast` | ยิงลิงก์เดียวออกหลายปลายทาง | `/broadcast` | direct handler + loop |
| `group_security_intelligence` | เฝ้าระวังความปลอดภัยกลุ่ม | `/group_security` +9 | `register_commands` + loop + hooks |
| `passive_recon` | passive recon (`/recon`) | `/recon` | `register_commands` |
| `active_scan` | port/service/AXFR (gated) | `/ascan` | `register_commands` |
| `vuln_probe` | safe-validation DAST | `/vprobe` | `register_commands` |
| `web_vulnerability_assessment` | web vuln assessment | `/vulnscan` +6, `/allowscan` | `register_commands` |
| `api_security_assessment` | API security assessment | `/api_assess` +4 | `register_commands` |

Payload management: **ชุดเดียว** = `web_vulnerability_assessment/payload_engine.py` + `payloads/`
(api reuse, ไม่มี manager ที่สอง). AI: **client เดียว** = `gemini.ask_gemini` (ทุกโมดูล reuse).

---

## 2. Integration verification (ตรวจจริง)

- **Import:** ทั้ง 9 โมดูล import สำเร็จหมด (`coordinator` เดิม import ไม่ได้ใน env ทดสอบนี้เพราะไม่มี
  `httpx` — ไม่เกี่ยวกับโมดูลใหม่; deploy มี httpx).
- **Registration:** `register_commands` ถูกเรียกครบใน `main()` สำหรับ gsi/passive_recon/active_scan/
  vuln_probe/wva/api_sec; autolink/broadcast ลงทะเบียนตรง (`CommandHandler(...)`). Background loops
  (news/github_sweep/autolink/broadcast/gsi) เริ่มใน `post_init` และถูก cancel ครบใน `post_shutdown`.
- **Boot validation:** `_REQUIRED_MODULE_API` ครอบทั้ง 6 โมดูลใหม่ที่ expose API — attribute ที่ประกาศ
  **resolve ครบทุกตัว** (ตรวจด้วย `hasattr`), กัน stale-deploy พังกลางคำสั่ง.
- **Async:** ทุก handler async, งานยาวไม่บล็อก event loop (loops เป็น task, disk ops ห่อ `to_thread`,
  message scan schedule เป็น task). hook ใน `handle_message`/`on_chat_member_update` กลืน error เอง.
- **Orphan:** ไม่พบโมดูลใหม่ที่ไม่ถูกต่อสาย — ทุกตัวมี handler/loop/hook ที่ถูกเรียกจริง.

**Commands: 106 ชื่อ, ชนกัน 0** (ตรวจทั้ง direct + ที่อยู่ใน register_commands).

---

## 3. Duplicate functionality

| สิ่งที่ตรวจ | ผล | การจัดการ |
|---|---|---|
| Authorization/scope | **ชุดเดียว** `scope_policy.evaluate_target` — ทุกโมดูล active ผ่านด่านนี้ | ✓ ไม่ซ้ำ |
| Payload manager | **ชุดเดียว** (WVA payload_engine) | ✓ ไม่ซ้ำ |
| SSRF/IP guard | **ชุดเดียว** `security_testing._forbidden_ip_reason`/`resolve_and_validate` | ✓ reuse ทุกที่ |
| Evidence sanitize + risk classify | **ชุดเดียว** `wva.classify` (api reuse) | ✓ ไม่ซ้ำ |
| AI client | **ชุดเดียว** `gemini.ask_gemini` | ✓ ไม่ซ้ำ |
| HTTP fetch | หลายชั้น **ตามจุดประสงค์ต่างกัน** (osint AsyncHTTPClient = trusted API; security_testing/vuln_probe = gated passive; api `_api_fetch` = gated + method/header) | ยอมรับได้ — ทุกตัวแตะเป้าหมายผ่านด่านเดียวกัน |
| Reporting render | per-domain (เนื้อหาต่างกัน) + ใช้ `classify.sanitize` ร่วม | ยอมรับได้ |
| **Notification handler** | **ซ้ำ** (WVA `Notifier` ≈ api `Notifier`) | **แก้แล้ว** → ยุบเป็น `BaseNotifier` ใน WVA, api subclass |

---

## 4. Centralized orchestration

ไม่จำเป็นต้องมี abstraction กลางบังคับทุกโมดูล (ตามคำเตือนในสเปค). โมดูล assessment
(vuln_probe/wva/api) ใช้ "สัญญาร่วม" โดยพฤตินัยอยู่แล้ว: gate เดียว (scope_policy) → gated fetch
(security_testing) → classify/sanitize เดียว (wva) → notify ฐานเดียว (BaseNotifier) → report 3 รูปแบบ.
การ cancel/progress/status เป็นแพตเทิร์นเดียวกัน (store cancel flag + progress callback).

---

## 5. Unified finding schema

- `web_vulnerability_assessment` และ `api_security_assessment` ใช้ finding schema **เดียวกัน**
  (api เป็น superset — เพิ่ม `method`): `id, category, rule, test_case_id, severity, state,
  confidence, target, endpoint, [method], param, detail, evidence, request, response_status,
  response_excerpt, recommendation, timestamp, ai_explanation`.
- `vuln_probe` ใช้ "indicator" ที่เบากว่า (`category, severity, confidence, detail, evidence`)
  โดยเจตนา — เป็น input เข้า review ไม่ใช่ finding เต็ม. **ไม่ migrate** (เสี่ยง + ไม่จำเป็นตามสเปค).
- states สอดคล้อง: CONFIRMED/POTENTIAL/INFORMATIONAL (+NOT_REPRODUCIBLE ใน api). severity แยกจาก
  confidence ทุกโมดูล.

---

## 6. Scope & permission enforcement

ยืนยันว่า **ไม่มีโมดูล active ไหน bypass ด่านได้**:
- `active_scan` → `guard.authorize_and_resolve` (scope_policy + public-IP) ก่อนเปิด socket, ตรวจ IP ซ้ำก่อน connect.
- `vuln_probe` → `evaluate_target` + `_validate_destination` ทุกคำขอ.
- `web_vulnerability_assessment` → `evaluate_target` + reuse vuln_probe gated fetch.
- `api_security_assessment` → `evaluate_target` + `_validate_destination` ทุกคำขอ (รวม redirect).
- `passive_recon` → SSRF guard (public-IP) + passive เท่านั้น (คนละ permission จาก active — ถูกต้องตามสเปค).
- `/allowscan` (`simple_scope`) **ขับ** scope_policy ให้ครบขั้น (program+authorization+review+INCLUDE
  DOMAIN+URL+activate) — ไม่ได้สร้าง authorization ระบบที่สอง และไม่ลด invariant เดิม (พิสูจน์ด้วยเทสต์
  allow→gate ผ่านในสโคป/ปฏิเสธนอกสโคปกับ DB จริง).
- active ↔ passive แยก permission: passive ไม่ต้องมี program; active ต้องผ่าน `evaluate_target`.

---

## 7. Reporting & notification

- **ปลายทางแยกกันได้จริง:** WVA → `SECURITY_REPORT_CHAT_ID`, api → `API_SECURITY_REPORT_CHAT_ID`
  (fallback เข้าแชตที่สั่ง), gsi/broadcast มี throttle/dedupe ของตัวเอง.
- รูปแบบ finding alert + summary ตามสเปค; export JSON/TXT/MD ครบ; กันแจ้งซ้ำภายใน run.
- redaction: evidence ทุกชิ้นผ่าน `classify.sanitize` (redact cookie/authorization/token/JWT/email/PAN)
  ก่อนเก็บ/ส่ง/เข้า AI. ไม่ส่ง credential/cookie/token ออก Telegram.
- **แก้ duplicate:** notification handler เหลือ logic ชุดเดียว (`BaseNotifier`).

---

## 8. Database & configuration

- **ไม่มี secret hardcode** — ค่าความลับทั้งหมดผ่าน `os.getenv` (ตรวจทั้ง 9 โมดูล). chat id/token เป็น env ล้วน.
- **Env namespace สะอาด** — prefix ต่อโมดูล (`AUTOLINK_*`, `BROADCAST_*`, `GSI_*`, `ASCAN_*`, `VPROBE_*`,
  `WVA_*`, `API_*`, `*_REPORT_CHAT_ID`) ไม่ชนกัน.
- **DB:** แกนเดิมใช้ SQLite `bot.db` (security/scope_policy/integrity_ledger ฯลฯ). โมดูลใหม่ใช้ atomic JSON
  แยกไฟล์ (`resource/*.json`) — runtime data ทั้งหมด **อยู่ใน `.gitignore`** แล้ว, ไม่เพิ่ม migration ให้ DB เดิม,
  ไม่มี model ซ้ำ.
- **Dependencies:** ไม่มี hard dependency ใหม่ — reuse `httpx` (ผ่าน osint), `PyYAML` (ออปชันใน api),
  ที่เหลือ stdlib. DNS ใช้ DoH แทน dnspython, WHOIS ใช้ RDAP แทน python-whois.

---

## 9/10. Testing & fixes

- **เทสต์รันจริง:** โมดูลใหม่รวม **174 เทสต์ ผ่านหมด** (autolink 21, broadcast 24, gsi 35,
  passive_recon 22, active_scan 17, vuln_probe 15, wva 22, api 18). รวมทั้ง repo **992 เทสต์**;
  error 37 ตัวเป็น `telegram`/`pytest` ไม่ได้ติดตั้งใน env ทดสอบนี้ (pre-existing, ไม่เกี่ยวกับโมดูลใหม่
  — ยืนยันว่าไม่มีไฟล์ใหม่ไหนถูก import โดยเทสต์ที่ error).
- **แก้ในรอบนี้ (ปลอดภัย, ไม่ลดฟีเจอร์):** ยุบ `Notifier` ที่ซ้ำ (WVA/api) → `BaseNotifier` ฐานเดียว
  ใน WVA, api subclass. public API เดิม (`Notifier(bot, fallback)`, `.finding_alert`, `.summary`)
  คงเดิม → คำสั่ง/เทสต์เดิมผ่านครบ.
- **ไม่แก้ (โดยเจตนา):** ไม่ยุบ HTTP fetch หลายชั้น (จุดประสงค์ต่างกัน), ไม่ migrate vuln_probe indicator
  (เสี่ยง + ไม่จำเป็น), ไม่ rewrite scope_policy (เป็นแกน gate).

---

## 11. Deliverables summary

- **Module inventory / integration status:** ครบ 9 โมดูลเชื่อมจริง, 106 คำสั่ง 0 ชน, boot-validation ครบ.
- **Broken components:** ไม่มี (ยกเว้น `coordinator` ที่ import ไม่ได้เพราะ httpx หายใน env ทดสอบ — pre-existing).
- **Duplicate findings:** notification handler (แก้แล้ว); HTTP fetch หลายชั้น (justified, คงไว้).
- **Missing dependencies:** ไม่มี (httpx/PyYAML มี/ออปชัน).
- **Architecture problems:** ไม่พบที่ต้องแก้; โครงเชื่อมผ่าน scope_policy + classify + BaseNotifier ร่วม.
- **Files modified:** `web_vulnerability_assessment/notify.py`, `api_security_assessment/notify.py`,
  `app.py` (รอบก่อน ๆ). **Files created:** โมดูล 9 ชุด + เอกสารนี้.
- **Tests:** 992 รัน; โมดูลใหม่ 174 ผ่าน; ไม่มี regression ใหม่.
- **Remaining limitations:** โมดูล assessment เป็น safe-validation (detection ไม่ exploit); ต้องมี httpx
  ตอนรันจริง; vuln_probe ยังใช้ indicator schema ที่เบากว่า (โดยเจตนา); การทดสอบ Telegram/network เต็มรูป
  ต้องทำใน env ที่มี telegram + เป้าหมายที่ authorize.

**สรุป:** โมดูลทั้งหมดทำงานเป็นแพลตฟอร์มเดียวที่เชื่อมกัน ผ่านแกนร่วม (authorization, SSRF guard,
sanitize/classify, AI client, notification base) — ไม่ใช่สคริปต์แยกส่วน. ฟีเจอร์เดิมคงอยู่ครบ.
