# Passive Reconnaissance & Intelligence (`passive_recon`)

โมดูลเก็บข่าวกรองแบบ **passive** จาก URL/โดเมน — ไม่สแกน ไม่ brute-force ไม่ exploit
ส่งเป้าหมายผ่านคำสั่ง `/recon` แล้วบอตทำงานอัตโนมัติ: normalize → เก็บข้อมูลหลายหมวด
แบบขนาน → correlate → ตัดซ้ำ → คิด confidence → ออกรายงาน JSON/TXT/Markdown

> เสริมบน OSINT framework เดิมของโปรเจกต์ ไม่สร้างบอตใหม่ ไม่แตะคำสั่งเดิม

---

## ของเดิมที่ reuse (ไม่ทำซ้ำ)

| ใช้ของเดิม | เพื่อ |
|---|---|
| `osint.utils.async_http.AsyncHTTPClient` | HTTP client (per-host rate-limit + retry/backoff) สำหรับ API สาธารณะ |
| `osint.utils.validators.is_public_ip` | เกณฑ์ IP สาธารณะเดียวกับทั้งโปรเจกต์ (SSRF) |
| `osint.sources.crtsh.fetch_subdomains` | Certificate Transparency (subdomains + SSL CT) |
| `osint.sources.bgpview.BGPViewIPSource` | ASN / prefix (infrastructure) |
| `urlkit.etld1` | หา registered domain |

**ใหม่** เฉพาะส่วนที่ของเดิมไม่มี: RDAP/WHOIS, DNS (DoH), tech fingerprint, HTTP metadata,
TLS cert, geolocation, security-exposure, SSRF-guarded target fetch, และ /recon + รายงาน

---

## คำสั่ง

```
/recon <url|domain>              เป้าหมายเดียว เช่น /recon https://example.com
/recon  + แนบไฟล์ .txt           หลายเป้าหมาย (URL บรรทัดละ 1 อัน, สูงสุด 20)
/recon <target> --json|--txt|--md  เลือกรูปแบบรายงาน (ดีฟอลต์ markdown + json)
```

- **ในกลุ่ม:** เฉพาะแอดมิน (กันใช้บอตยิง outbound มั่ว) · **ใน DM:** ใช้ได้เลย
- ผลลัพธ์: สรุปสั้นในแชต + แนบไฟล์รายงาน (Markdown + JSON เสมอ, มี source/timestamp ครบ)

---

## หมวดข้อมูลที่เก็บ

| หมวด | รายละเอียด | แหล่ง |
|---|---|---|
| Domain / WHOIS-RDAP | registrar, created/expires, status, nameservers | rdap.org (RDAP) |
| DNS | A/AAAA/MX/NS/SOA/TXT/CAA + SPF/DKIM/DMARC | DoH (dns.google/cloudflare) |
| Subdomains | passive จาก CT log + DNS validation (ชี้ตัวที่อาจถูกทิ้งร้าง) | crt.sh |
| Technology | web server/framework/CMS/JS/CDN/WAF — แยก **ยืนยัน** (header) vs **อนุมาน** (HTML/cookie) | HTTP headers/HTML |
| TLS | issuer, validity, SAN, วันหมดอายุ, TLS version, cipher | handshake :443 |
| HTTP | status, headers, security headers, redirects, title, canonical, robots.txt, sitemap.xml | GET/HEAD เป้าหมาย |
| Infrastructure | IPv4/IPv6, ASN, ISP/org, geo (approx) | DNS + BGPView + ipwho.is |
| Security exposure | ตัวชี้วัด**เชิงข้อมูล**: version ที่เปิดเผย, security header หาย, SPF/DMARC อ่อน, cert ใกล้/หมดอายุ | derived |

ทุกรายการแนบ **source + timestamp** · ข้อมูล security เป็น *informational indicator* ไม่ใช่ช่องโหว่ยืนยัน

---

## ความปลอดภัย (passive-only + SSRF guard)

**ทำ:** DNS/RDAP/CT/metadata สาธารณะ, HTTP GET/HEAD แบบ non-invasive มี rate limit
**ไม่ทำ:** port scan, directory/subdomain brute-force, exploit, SQLi/XSS, auth attack, DoS

SSRF guard (`safehttp.py`):
- resolve เป้าหมายก่อนทุกครั้ง แล้ว **บล็อก** localhost/private/link-local/cloud-metadata (169.254.169.254)
- ปิด auto-redirect — ตาม redirect เองทีละ hop พร้อม **revalidate host ทุก hop**
- จำกัดเฉพาะ **GET/HEAD**, timeout + เพดานขนาด body (512KB), จำกัดจำนวน redirect
- เป้าหมายที่ไม่ถูกต้อง/มี credentials ในURL/ชี้ IP ภายใน → ปฏิเสธ

---

## ไฟล์ (6)

```
passive_recon/
├── parse.py       ตรรกะวิเคราะห์ล้วน (normalize/DoH/SPF-DMARC/fingerprint/cert/exposure/render) — เทสต์ได้ 100%
├── safehttp.py    SSRF-guarded fetch + DoH + TLS cert
├── collectors.py  ตัวเก็บข้อมูลรายหมวด (async; reuse crtsh/bgpview/AsyncHTTPClient)
├── recon.py       เวิร์กโฟลว์หลัก + render JSON/TXT/Markdown
├── commands.py    /recon (เดี่ยว + ไฟล์ .txt)
└── __init__.py    register_commands(app, is_admin)
```

---

## การผูกกับ app.py (ต่อสายไว้ให้แล้ว)

```python
import passive_recon
passive_recon.register_commands(app, is_admin)   # main(): ลง /recon
```
เพิ่มใน `_REQUIRED_MODULE_API` เพื่อ validate ตอนบูต · ไม่มี background loop/entry point ใหม่

---

## Dependencies

ไม่เพิ่ม dependency ใหม่ — ใช้ `httpx` (มีใน requirements เดิม ผ่าน osint framework) + stdlib (`ssl`, `socket`, `ipaddress`)
DNS ใช้ DoH จึงไม่ต้องมี `dnspython`; WHOIS ใช้ RDAP จึงไม่ต้องมี `python-whois`

---

## ผลการทดสอบ (รันจริง)

`python -m unittest test_passive_recon -v` → **22/22 ผ่าน**
ครอบคลุม: normalize (รวมปฏิเสธ credentials/scheme แปลก), DoH/SPF/DMARC, tech fingerprint
(confirmed vs inferred), cert, http metadata, security exposure, dedupe/scope, confidence,
render 3 รูปแบบ, **SSRF guard** (บล็อก private/metadata/::1, ปฏิเสธ non-GET), และ
**workflow end-to-end ด้วย stub client** (ไม่ต่อเน็ต)

รวมทั้ง repo: 883 ผ่าน · error 37 ตัวเป็น `telegram`/`pytest` ไม่ได้ติดตั้งใน env ทดสอบ (ไม่เกี่ยวกับโมดูลนี้ ไม่มี regression)

---

## ข้อจำกัดที่รู้

- **passive เท่านั้น** — ไม่ยืนยัน exploitability; security findings เป็นตัวชี้วัดเชิงข้อมูล
- subdomains มาจาก CT log (passive) — ไม่ครอบคลุมโดเมนที่ไม่เคยออก cert และไม่ brute-force
- RDAP ขึ้นกับ registry ที่รองรับ; บาง TLD ให้ข้อมูลน้อย/ไม่มี
- geolocation เป็นระดับประมาณ (เมือง/ประเทศ) ไม่ใช่พิกัดจริง
- การดึง HTTP/TLS ต้องให้ container มี outbound ถึงเป้าหมาย (ที่ deploy ปกติมี; session ทดสอบนี้ไม่มี httpx จึง mock)
- TLS handshake เป็น passive read (เหมือน browser เปิดเว็บ) — ยังตรวจ SSRF ก่อนเสมอ
