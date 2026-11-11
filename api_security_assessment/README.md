# API Security Assessment (`api_security_assessment`)

ประเมินความปลอดภัย **REST / GraphQL / JSON API** แบบ authorized + safe-validation
(detection — ไม่ bypass auth, ไม่ forge token, ไม่ brute, ไม่ DoS, ไม่เข้าถึงข้อมูลบุคคลที่สาม)
บนเป้าหมายที่ authorize ผ่าน `scope_policy` เท่านั้น

> เสริมบน passive_recon / vuln_probe / web_vulnerability_assessment เดิม — ไม่ทำซ้ำ ไม่สร้างบอตใหม่

---

## Input ที่รองรับ

- Base URL ของ API
- OpenAPI/Swagger (v2/v3) **JSON หรือ YAML**
- Swagger/OpenAPI จาก URL (ที่อนุญาตแล้ว)
- Postman Collection (JSON)
- รายการ endpoint จากโมดูล recon เดิม (list)

ไม่ brute-force endpoint ที่ไม่มีในสเปค — แปลงจากที่ให้มาเท่านั้น

---

## คำสั่ง

```
/allowscan <url>                       อนุญาตโดเมน (ใช้ร่วมกับ WVA — scope เดียวกัน)
/api_import <url | แนบไฟล์ .json/.yaml> นำเข้า OpenAPI/Swagger/Postman
/api_assess <base_url> [categories…] [key=value…]
/api_status [id]   /api_report <id>   /api_stop <id>
```
categories: `authentication authorization input_validation sqli xss graphql cors info_disclosure misconfiguration`
options (ทำใน DM): `token=<jwt>` `token_a= token_b= object=/path/{id} id=<synthetic>`
ในกลุ่ม = แอดมิน · ใน DM = เปิด · ส่งผลไปที่ `API_SECURITY_REPORT_CHAT_ID`

---

## หมวดที่ประเมิน

| หมวด | ตรวจ | วิธี |
|---|---|---|
| Endpoint analysis | path/method/param/schema/auth/version, sensitive/admin/deprecated/object-id | static จากสเปค |
| Authentication | missing-auth, JWT config (alg=none/ไม่มี exp/aud/iss — อ่านอย่างเดียว) | GET no-token + decode header/claims |
| Authorization | **BOLA/BFLA** (เทียบ 2 test account + synthetic id), tenant isolation | compare — detection เท่านั้น |
| Input validation | SQLi/XSS marker, **mass assignment (static schema)**, excessive data | reuse vuln_probe/WVA |
| GraphQL | introspection เปิด, error disclosure | bounded introspection query |
| CORS / misconfig | Origin ปลอม → ACAO/ACAC, security headers, verbose error, server banner | non-invasive |
| Rate limiting | rate-limit/Retry-After headers | อ่าน header (ไม่ stress) |

---

## ความปลอดภัย (ตามสเปค)

- **gate ทุกคำขอ**: `scope_policy.evaluate_target()` + `security_testing._validate_destination()`
  (scope + public-IP + port, บล็อก localhost/private/metadata) — reuse ด่านเดิม 100%
- **ไม่ทำ**: signature bypass, token forgery, credential theft, password/token brute,
  high-volume/nested query, resource exhaustion, data extraction, การเข้าถึงข้อมูลจริงของผู้อื่น
- **authz** ใช้เฉพาะ test account + synthetic resource ที่ operator ให้ · หยุดเมื่อข้ามขอบเขต
- **PUT/PATCH/DELETE ปิดโดยดีฟอลต์** (เปิดเฉพาะ staging + disposable ผ่าน policy `allow_state_changing`)
- evidence **sanitize** (redact cookie/auth/token/JWT/email) ก่อนเก็บ/ส่ง/ส่งเข้า AI

---

## Finding states + รายงาน + แจ้งเตือน

- states: **CONFIRMED / POTENTIAL / INFORMATIONAL / NOT_REPRODUCIBLE** (severity แยกจาก confidence)
- รายงาน **JSON / TXT / Markdown** + รูปแบบ `[API SECURITY ALERT]` / `[...COMPLETE]` ตามสเปค
- แจ้งเตือน high-severity ทันที + สรุปจบ + แนบไฟล์ → `API_SECURITY_REPORT_CHAT_ID`
  (แยกจาก WVA; fallback เข้าแชตที่สั่ง), กันซ้ำภายใน run, ไม่ส่ง credential
- AI ออปชัน reuse `gemini.ask_gemini` (sanitize ก่อนส่ง, ไม่อ้าง exploit สำเร็จถ้าเป็น indicator)

---

## ไฟล์ (ใหม่ 8) + reuse

```
api_security_assessment/
├── spec.py        parse OpenAPI(v2/v3 JSON/YAML)/Postman/recon-list → endpoints (pure)
├── analyzers.py   JWT/auth/authz/graphql/cors/rate-limit/mass-assign/excessive (pure)
├── store.py       assessment + imported specs (atomic JSON) + cancel
├── engine.py      orchestration + API gated fetch (method/header/json ผ่าน _validate_destination)
├── report.py      JSON/TXT/MD + alert/summary
├── notify.py      → API_SECURITY_REPORT_CHAT_ID
├── commands.py    /api_assess /api_import /api_status /api_report /api_stop
└── __init__.py
```
reuse: `scope_policy`+`security_testing` (gate/SSRF) · `web_vulnerability_assessment`
(classify/sanitize/simple_scope/detectors) · `vuln_probe.probes` (ผ่าน WVA) · `gemini` · `urlkit` ·
bot instance เดิม — **ไม่สร้าง payload manager ใหม่** (ใช้ของ WVA/vuln_probe)

## Dependencies

ไม่เพิ่ม hard dependency — `httpx` (มีอยู่), `PyYAML` (ออปชัน: ถ้าไม่มี YAML จะ parse เฉพาะ JSON)

## ผลทดสอบ (รันจริง)

`python -m unittest test_api_security_assessment` → **18/18 ผ่าน**: spec (OpenAPI3 JSON,
Swagger YAML, Postman, dedupe/classify, bad spec), analyzers (JWT alg=none, auth enforcement,
BOLA compare, GraphQL introspection, mass-assignment, excessive-data, rate-limit, server banner),
engine (denied/completed+detect/**cancellation**/disabled). รวม repo ไม่มี regression.

## ข้อจำกัด

- detection เท่านั้น — "ไม่พบ" ≠ ปลอดภัย; ตรวจเฉพาะ endpoint ในสเปค/ที่ให้ (ไม่ค้นเอง/ไม่ brute)
- authz ต้องมี 2 test token + object endpoint + synthetic id จาก operator จึงรัน
- localhost/private ถูกบล็อกเสมอ (ไม่รองรับ local test env ในเวอร์ชันนี้ — ตามด่าน security_testing)
- ต้อง `/allowscan` โดเมนก่อน และต้องมี httpx ตอนรันจริง
