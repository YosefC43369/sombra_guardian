# Vuln Probe (`vuln_probe`) — module 2/8

ยืนยันช่องโหว่แบบ **safe-validation** (DAST detection) — ตรวจ *การมีอยู่ของ indicator*
ด้วย marker ที่ไม่ทำลายข้อมูล ไม่ exploit ไม่ extract ข้อมูล — แล้วป้อนเข้าโมเดล
"observation → review gate" ของ redteam เดิม

ครอบคลุม: reflected XSS · error-based SQLi · SSTI · open-redirect · CORS misconfig · subdomain takeover

---

## ด่านความปลอดภัย (reuse ของ security_testing ทั้งหมด)

ทุกคำขอ **ยิงผ่าน `security_testing` ที่มีอยู่**:
- `scope_policy.evaluate_target()` — gate ก่อนแตะเน็ต (authorization + scope)
- `security_testing._validate_destination()` — ตรวจ port/scheme/IP(สาธารณะ)/scope ซ้ำ **ทุกคำขอ**
- `resolve_and_validate()` / `_endpoint_from_target()` — resolver + SSRF guard เดียวกับทั้งโปรเจกต์

engine มีเพียง fetch บาง ๆ ที่รับ custom query/header (reflection/CORS ต้องใช้) แต่เรียก
`_validate_destination` ก่อนยิงเสมอ · ไม่ follow redirect · จำกัดจำนวนคำขอต่อ run

---

## หลัก safe-validation (ไม่ใช่ exploit)

| ตรวจ | วิธี (non-destructive) |
|---|---|
| reflected XSS | ส่ง marker สุ่ม ดูการสะท้อนแบบดิบในบริบท HTML (ไม่รัน payload) |
| error-based SQLi | ส่ง quote เดี่ยว เทียบ error signature ที่ "โผล่ใหม่" — ไม่มี UNION/boolean/time extraction |
| SSTI | ส่ง `{{7*7}}` ดูว่าได้ `49` (template ถูกประเมิน) |
| open-redirect | ใส่ host marker ภายนอก ดู `Location` (ไม่ follow) |
| CORS | ส่ง `Origin` ปลอม ดู `ACAO`/`ACAC` ว่าสะท้อน+allow-credentials ไหม |
| takeover | จับ fingerprint ของบริการที่ชี้ค้าง (GitHub Pages/S3/Heroku/…) |

ผลทุกชิ้นเป็น **informational_indicator** + confidence — ไม่ใช่ข้อสรุปว่า exploit ได้
ยกเป็น Finding จริงผ่าน review gate ของ redteam เมื่อผู้ดูแลยืนยัน

---

## คำสั่ง

```
/vprobe <program_id> <url> [reflection sqli ssti open_redirect cors takeover]
/vprobe list [program_id]
/vprobe get <run_id>
```
ในกลุ่ม = แอดมิน · ใน DM = เปิด · เป้าหมายต้องผ่าน scope_policy · ผลแนบเป็น Markdown + JSON

---

## ไฟล์

```
vuln_probe/
├── probes.py    ตัววิเคราะห์ pure (reflection/sqli/ssti/redirect/cors/takeover) — เทสต์ได้ 100%
├── store.py     ผล run (atomic JSON) + policy
├── engine.py    ยิง probe ผ่านด่าน scope+SSRF ของ security_testing
└── commands.py  /vprobe
```

policy ปรับได้: `param_name`, `redirect_params`, `injected_host`, `max_requests`, `checks` (ไม่ hardcode)

---

## ทดสอบ (รันจริง)

`python -m unittest test_vuln_probe` → **15/15 ผ่าน**: ตัววิเคราะห์ทั้ง 6 (รวมกรณี
encoded=ปลอดภัย, signature ที่มีอยู่เดิมไม่ถูก flag, redirect ภายในไม่ใช่ open-redirect),
store lifecycle, engine เส้นทาง denied(scope)/disabled/completed(stub fetch)

ไม่เพิ่ม dependency · reuse scope_policy + security_testing (gate/SSRF/fetch primitives)

## ข้อจำกัด

- detection เท่านั้น — "ไม่พบ indicator" ไม่ได้แปลว่าปลอดภัย (ตรวจจำกัด, ไม่ครอบคลุม blind/stored)
- probe ยิงบน URL ที่ให้มา + พารามิเตอร์ทดสอบที่ตั้งไว้ (ไม่ crawl/ไม่ค้นพารามิเตอร์เอง)
- ต้องตั้ง program+authorization+scope ใน scope_policy ก่อน ไม่งั้นถูกปฏิเสธ (by design)
- ต้องมี httpx (มีใน requirements เดิม) จึงยิงได้; session ทดสอบนี้ไม่มีจึง stub fetch
