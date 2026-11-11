# Active Scan (`active_scan`) — module 1/8

สแกน **active** จริง: TCP connect port scan + banner grab + service identification +
DNS zone-transfer (AXFR) attempt — **ยิงได้เฉพาะเป้าหมายที่ผ่าน `scope_policy` แล้ว**

ต่อยอด `security_testing` (passive web checks) ไปเป็น active enumeration โดยใช้
ด่านความปลอดภัยชุดเดิมของโปรเจกต์ ไม่สร้างเกณฑ์ใหม่

---

## สองด่านบังคับ (reuse 100%)

1. **`scope_policy.evaluate_target(program_id, target)`** — เป้าหมายต้องอยู่ใน program
   ที่ ACTIVE + มี authorization ภายนอกที่ผ่าน review + ตรง INCLUDE และไม่ตรง EXCLUDE
   (EXCLUDE ชนะ). นี่คือด่านที่ `redteam.py` จงใจบังคับ
2. **`security_testing._forbidden_ip_reason(ip)`** — ทุก IP ที่ resolve/expand ได้ต้องเป็น
   สาธารณะล้วน; loopback/private/link-local/**cloud-metadata (169.254.169.254)**/
   IPv4-mapped/6to4/Teredo ถูกปฏิเสธแบบ fail-closed และตรวจซ้ำอีกครั้งก่อน connect ทุกครั้ง

ป้องกัน DNS-rebinding: host ถูกปฏิเสธถ้ามี IP ที่ไม่สาธารณะแม้ตัวเดียว ·
ขยาย CIDR มีเพดาน · จำนวน connect รวม (hosts × ports) มีเพดาน

---

## คำสั่ง

```
/ascan <program_id> <target> [quick|top100|web|db]
/ascan list [program_id]
/ascan get <scan_id>
/ascan profiles
```
ในกลุ่ม = แอดมิน · ใน DM = เปิด · **ต้องมี program ที่ authorize แล้ว** (ตั้งผ่านระบบ scope_policy เดิม)
ผลลัพธ์: สรุปในแชต + แนบรายงาน Markdown + JSON

โปรไฟล์: `quick` (14 พอร์ต) · `top100` · `web` · `db`

---

## สิ่งที่ทำ / ไม่ทำ

**ทำ:** TCP connect scan (ไม่ต้อง root, ตรวจสอบง่าย), banner grab (ส่ง probe เบาเฉพาะ HTTP),
service id จากพอร์ต+banner, AXFR attempt (RFC 1035 wire format — ปกติ server ปฏิเสธ = ปลอดภัย)
**ไม่ทำ:** SYN/raw-socket scan, exploit, brute-force, การแตะเป้าหมายก่อน gate ผ่าน

---

## ไฟล์

```
active_scan/
├── store.py    ผลสแกน (atomic JSON) + policy
├── guard.py    ด่าน scope + public-IP (reuse evaluate_target + _forbidden_ip_reason)
├── scanner.py  async TCP connect + banner + service + AXFR parser (RFC 1035)
├── engine.py   ประสานหนึ่งสแกน (gate→resolve→scan→AXFR→summary)
└── commands.py /ascan
```

ปรับ policy ได้: `concurrency`, `rate_per_sec`, `connect_timeout`, `max_ports_per_host`,
`max_hosts_per_scan`, `max_total_connects`, `dns_axfr` (ไม่ hardcode)

---

## ทดสอบ (รันจริง)

`python -m unittest test_active_scan` → **17/17 ผ่าน** รวม:
- **การสแกน TCP จริงบน localhost** (open/closed/scan_host)
- AXFR parser (compression pointer + REFUSED rcode + extract names)
- guard: บล็อก private/metadata, อนุญาต public, CIDR cap
- engine: เส้นทาง denied (scope block) / completed (stub) / disabled

ไม่เพิ่ม dependency · reuse scope_policy + security_testing + osint RateLimiter + passive_recon DoH

## ข้อจำกัด

- TCP connect scan เห็นเฉพาะพอร์ตที่ "ตอบรับ connect" (ไม่แยก closed/filtered ละเอียดเท่า SYN)
- AXFR ต้องค้น NS ได้ก่อน (ผ่าน DoH; ถ้า httpx/osint ไม่พร้อม จะข้าม)
- ต้องตั้ง program + authorization + scope rule ใน `scope_policy` ก่อน ไม่งั้นถูกปฏิเสธทุกครั้ง (by design)
