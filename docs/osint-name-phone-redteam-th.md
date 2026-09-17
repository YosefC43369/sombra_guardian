# คู่มือ OSINT ระดับสูง: ชื่อบุคคล + หมายเลขโทรศัพท์ บน Kali Linux (WSL) — แนวทาง Red Team / Purple Team

> **ภาคต่อลำดับที่ 3** — ต่อจาก
> [`spiderfoot-email-osint-th.md`](./spiderfoot-email-osint-th.md) (พื้นฐาน WSL/Kali/SpiderFoot) และ
> [`spiderfoot-email-osint-advanced-th.md`](./spiderfoot-email-osint-advanced-th.md) (คำสั่งอีเมลขั้นสูง)
>
> รอบนี้เพิ่ม **การค้นด้วยชื่อบุคคล (name)** และ **หมายเลขโทรศัพท์ (phone number)**
> ในกรอบงาน **Red Team / Purple Team ที่ได้รับอนุญาต** — คือทำเพื่อ *ทดสอบและยกระดับการป้องกัน*
> ขององค์กร ไม่ใช่ Black Hat ทุกเทคนิคจับคู่กับ **MITRE ATT&CK** และมี **มุมมองฝ่ายป้องกัน (Blue)**
>
> **การทดสอบคำสั่ง:** เครื่องมือทุกตัวในไฟล์นี้ผ่านการรันจริง — `phoneinfoga`, `ignorant`,
> `phonenumbers`, `sherlock`, `maigret`, `socialscan`, ตัวสร้าง username/dork และ one-liner
> คำสั่งที่ต้องมี API key หรือติดตั้งแบบเฉพาะจะระบุไว้ชัดเจน

---

## ⚠️ Authorization Gate — อ่านและยืนยันก่อนเริ่ม

การค้นหาชื่อและเบอร์โทรของ **บุคคลจริง** คือการเก็บข้อมูลส่วนบุคคล (PII) การทำโดยไม่ได้รับอนุญาต
เข้าข่ายผิดกฎหมาย (PDPA/GDPR/พ.ร.บ.คอมพิวเตอร์ฯ) และอาจเป็นการคุกคาม ก่อนเริ่มทุกครั้ง ต้องมี:

```
[ ] เอกสารอนุญาตเป็นลายลักษณ์อักษร (SOW / Rules of Engagement) ที่ระบุขอบเขตชัดเจน
[ ] ขอบเขต (scope): โดเมน/บุคคล/หมายเลข ที่อนุญาต และรายการที่ "ห้ามแตะ"
[ ] ช่องทาง deconfliction + ผู้ประสานงานฝ่าย Blue/SOC
[ ] ขั้นตอน abort/stop และแผน rollback
[ ] ใช้เฉพาะแหล่งเปิดสาธารณะ (passive) เว้นแต่ได้รับอนุญาตให้ทำ active
[ ] ไม่ exfiltrate ข้อมูลผู้ใช้จริง — ใช้บัญชี/ข้อมูลทดสอบเมื่อเป็นไปได้
```

> ถ้ายืนยันข้างต้นไม่ได้ → จำกัดขอบเขตไว้ที่ **การวางแผน, การวิเคราะห์ coverage, และ tabletop**
> เท่านั้น ห้ามรันคำสั่งกับบุคคลจริง คู่มือนี้ใช้ตัวอย่าง `John Doe` และหมายเลขทดสอบเสมอ

---

## สารบัญ

1. [กรอบงาน: Red Team / Purple Team และ ATT&CK Reconnaissance](#1-กรอบงาน-red-team--purple-team-และ-attck-reconnaissance)
2. [เตรียมเครื่องมือ (ต่อยอดจากไฟล์ 1–2)](#2-เตรียมเครื่องมือ-ต่อยอดจากไฟล์-1-2)
3. [ส่วน A — OSINT หมายเลขโทรศัพท์](#3-ส่วน-a--osint-หมายเลขโทรศัพท์)
   - [3.1 phonenumbers — parse/validate/carrier/geo](#31-phonenumbers--parsevalidatecarriergeo)
   - [3.2 PhoneInfoga — สแกนเบอร์แบบครบวงจร](#32-phoneinfoga--สแกนเบอร์แบบครบวงจร)
   - [3.3 ignorant — เบอร์นี้ผูกกับบัญชีใด](#33-ignorant--เบอร์นี้ผูกกับบัญชีใด)
   - [3.4 Google dork สำหรับเบอร์โทร](#34-google-dork-สำหรับเบอร์โทร)
4. [ส่วน B — OSINT ชื่อบุคคล](#4-ส่วน-b--osint-ชื่อบุคคล)
   - [4.1 สร้าง username candidates จากชื่อ](#41-สร้าง-username-candidates-จากชื่อ)
   - [4.2 sherlock — ค้น username ข้ามเครือข่าย](#42-sherlock--ค้น-username-ข้ามเครือข่าย)
   - [4.3 maigret — โปรไฟล์เชิงลึก 3000+ ไซต์](#43-maigret--โปรไฟล์เชิงลึก-3000-ไซต์)
   - [4.4 socialscan + Google/LinkedIn dork สำหรับชื่อ](#44-socialscan--googlelinkedin-dork-สำหรับชื่อ)
   - [4.5 theHarvester — ชื่อพนักงานจากโดเมนองค์กร](#45-theharvester--ชื่อพนักงานจากโดเมนองค์กร)
5. [ส่วน C — Correlation & Pivoting เชิงลึก](#5-ส่วน-c--correlation--pivoting-เชิงลึก)
6. [ส่วน D — สคริปต์อัตโนมัติแบบครบวงจร](#6-ส่วน-d--สคริปต์อัตโนมัติแบบครบวงจร)
7. [ส่วน E — มุมมอง Purple Team: ตรวจจับและป้องกัน](#7-ส่วน-e--มุมมอง-purple-team-ตรวจจับและป้องกัน)
8. [ส่วน F — OPSEC สำหรับผู้ทดสอบ](#8-ส่วน-f--opsec-สำหรับผู้ทดสอบ)
9. [ส่วน G — เทมเพลตรายงาน (Red + Purple)](#9-ส่วน-g--เทมเพลตรายงาน-red--purple)
10. [Cheat Sheet — สรุปคำสั่งทั้งหมด](#10-cheat-sheet--สรุปคำสั่งทั้งหมด)
11. [ความเสี่ยงที่ยังเหลืออยู่ (Residual Risks)](#11-ความเสี่ยงที่ยังเหลืออยู่-residual-risks)

---

## 1. กรอบงาน: Red Team / Purple Team และ ATT&CK Reconnaissance

การค้นหาชื่อ/เบอร์อยู่ในเฟส **Reconnaissance (TA0043)** ของ MITRE ATT&CK ซึ่งเป็นการเก็บข้อมูล
*ก่อน* โจมตี ในงาน Red Team คือจำลองว่าศัตรูรู้อะไรเกี่ยวกับองค์กรได้บ้าง ส่วน Purple Team คือ
เอาผลนั้นมา *ยกระดับการป้องกัน* ร่วมกับฝ่าย Blue

| ATT&CK ID | เทคนิค | เกี่ยวกับชื่อ/เบอร์อย่างไร |
|---|---|---|
| **T1589** | Gather Victim Identity Information | .002 อีเมล, .003 ชื่อพนักงาน, และหมายเลขโทรศัพท์ |
| **T1589.003** | Employee Names | รวบรวมชื่อพนักงานเพื่อคาดเดา username/อีเมล |
| **T1591** | Gather Victim Org Information | .004 ระบุบทบาท/ตำแหน่งของบุคคล |
| **T1593** | Search Open Websites/Domains | .001 โซเชียลมีเดีย, .002 เสิร์ชเอนจิน |
| **T1593.001** | Social Media | หาโปรไฟล์จากชื่อ/username |
| **T1596** | Search Open Technical Databases | ฐานข้อมูลสาธารณะ (WHOIS, cert, ฯลฯ) |
| **T1598** | Phishing for Information | ใช้ข้อมูลที่ได้ไปทำ phishing (เฟสถัดไป) |

**หลักการ Red→Purple:** ทุกคำสั่งในคู่มือนี้ควรบันทึกเป็น *attack log* (เวลา, เทคนิค, ATT&CK ID,
ผลที่คาดว่า Blue จะเห็น) เพื่อใช้ในการ debrief และแปลงเป็น *การป้องกัน* (ส่วน E)

```
   RED (จำลองศัตรู)              PURPLE (ทำงานร่วม)              BLUE (ป้องกัน)
   เก็บชื่อ/เบอร์/username   ──▶   วัด: footprint เปิดแค่ไหน   ──▶   ลด PII สาธารณะ
   ปะติดปะต่อ identity      ──▶   ทดสอบ: detect ได้ไหม       ──▶   canary/honeypot
   เตรียม phishing target   ──▶   ประเมิน: พนักงานเสี่ยง      ──▶   awareness training
```

---

## 2. เตรียมเครื่องมือ (ต่อยอดจากไฟล์ 1–2)

สมมติว่าติดตั้งพื้นฐาน (pipx, jq, dnsutils, Go) จากไฟล์ที่ 2 แล้ว รอบนี้เพิ่มเครื่องมือชื่อ/เบอร์:

```bash
# --- เครื่องมือ Python (pipx) ---
pipx install sherlock-project           # ค้น username ข้ามเครือข่าย
pipx install ignorant                   # เบอร์โทร → บัญชีที่ผูก
pipx install maigret                    # (ถ้ายังไม่มีจากไฟล์ 2)
pipx install socialscan                 # (ถ้ายังไม่มีจากไฟล์ 2)

# --- ไลบรารี phonenumbers (ใช้ใน venv/สคริปต์) ---
python3 -m venv ~/osint && source ~/osint/bin/activate
pip install phonenumbers requests
```

### ติดตั้ง PhoneInfoga (สำคัญ: `go install` ใช้ไม่ได้ ให้ดาวน์โหลด release binary)

```bash
# ดาวน์โหลด binary สำเร็จรูป (สถาปัตย์ x86_64)
cd /tmp
curl -sSL -o phoneinfoga.tgz \
  "https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Linux_x86_64.tar.gz"
tar xzf phoneinfoga.tgz
sudo install -m 0755 phoneinfoga /usr/local/bin/phoneinfoga
phoneinfoga version
```

> **ทำไมไม่ใช้ `go install`:** PhoneInfoga ฝัง web client ไว้ตอน build release — การ `go install`
> จะ error `pattern client/dist/*: no matching files found` ให้ใช้ release binary หรือ Docker แทน

ตรวจว่าติดตั้งครบ:

```bash
for t in phoneinfoga sherlock ignorant maigret socialscan; do
  command -v "$t" >/dev/null && echo "[OK]  $t" || echo "[MISS] $t"
done
python3 -c "import phonenumbers; print('[OK] phonenumbers', phonenumbers.__name__)"
```

---

## 3. ส่วน A — OSINT หมายเลขโทรศัพท์

> **ATT&CK:** T1589 (Gather Victim Identity Information)
> เริ่มเสมอด้วยการ **normalize เบอร์เป็นรูปแบบ E.164** (เช่น `+66818765432`) เพื่อให้ทุกเครื่องมือเข้าใจตรงกัน

### 3.1 phonenumbers — parse/validate/carrier/geo

ไลบรารี `phonenumbers` (พอร์ตจาก libphonenumber ของ Google) ให้ข้อมูล **offline ล้วน** — ไม่แตะเป้าหมาย
ปลอดภัยที่สุด และเป็นขั้นแรกเสมอ

**สคริปต์ตรวจเบอร์พื้นฐาน (บันทึกเป็น `phone_info.py`):**

```python
#!/usr/bin/env python3
# phone_info.py — offline phone intel (ATT&CK T1589)
import sys, phonenumbers
from phonenumbers import geocoder, carrier, timezone, number_type, PhoneNumberType

raw = sys.argv[1] if len(sys.argv) > 1 else "+66818765432"
region = sys.argv[2] if len(sys.argv) > 2 else None
n = phonenumbers.parse(raw, region)

types = {getattr(PhoneNumberType, a): a for a in dir(PhoneNumberType) if a.isupper()}
print(f"input      : {raw}")
print(f"valid      : {phonenumbers.is_valid_number(n)}")
print(f"possible   : {phonenumbers.is_possible_number(n)}")
print(f"E164       : {phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164)}")
print(f"intl       : {phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}")
print(f"national   : {phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.NATIONAL)}")
print(f"country    : +{n.country_code}")
print(f"region     : {geocoder.description_for_number(n, 'en')}")
print(f"carrier    : {carrier.name_for_number(n, 'en') or '(n/a)'}")
print(f"timezone   : {timezone.time_zones_for_number(n)}")
print(f"line type  : {types.get(number_type(n), 'UNKNOWN')}")
```

**รันคำสั่ง:**

```bash
source ~/osint/bin/activate
python3 phone_info.py "+66818765432"          # เบอร์ไทย → region=Thailand, carrier=AIS
python3 phone_info.py "+14155552671"          # เบอร์ US → San Francisco, CA
python3 phone_info.py "0818765432" TH         # เบอร์ในประเทศ + region hint
```

**one-liner ตรวจแบบเร็ว:**

```bash
python3 -c "import phonenumbers as p,sys; n=p.parse(sys.argv[1],None); \
from phonenumbers import geocoder,carrier; \
print('valid=',p.is_valid_number(n),'|',geocoder.description_for_number(n,'en'),'|',carrier.name_for_number(n,'en'))" "+66818765432"
```

**ตรวจหลายเบอร์จากไฟล์ (numbers.txt: หนึ่งเบอร์ต่อบรรทัด):**

```bash
while read -r NUM; do
  echo "==== $NUM ===="
  python3 phone_info.py "$NUM"
done < numbers.txt
```

**สร้างรูปแบบเบอร์ทุกแบบเพื่อใช้ค้นต่อ (E164 / national / ไม่มี +):**

```bash
python3 - "+66818765432" <<'PY'
import sys, phonenumbers as p
n = p.parse(sys.argv[1], None)
e164 = p.format_number(n, p.PhoneNumberFormat.E164)
natl = p.format_number(n, p.PhoneNumberFormat.NATIONAL)
print(e164)                    # +66818765432
print(e164.lstrip('+'))        # 66818765432
print(natl)                    # 081 876 5432
print(natl.replace(' ', ''))   # 0818765432
PY
```

> **การอ่านผล (Red):** `line type` = MOBILE/FIXED_LINE/VOIP ช่วยประเมินว่าเป็นมือถือส่วนตัว
> หรือเบอร์องค์กร; `carrier` + `region` ช่วยระบุพื้นที่/ผู้ให้บริการ
> **มุม Purple:** ขั้นนี้ passive ล้วน ตรวจจับฝั่งเป้าหมายไม่ได้ → การป้องกันคือ *ลดการเปิดเผยเบอร์*

**ฟีเจอร์ขั้นสูงของ phonenumbers (ตรวจตามภูมิภาค / เบอร์ตัวอย่าง / ประเภทเลข):**

```bash
python3 - <<'PY'
import phonenumbers as p
from phonenumbers import is_valid_number_for_region, region_code_for_number, example_number_for_type, PhoneNumberType
n = p.parse("+66818765432", None)
print("valid_for_region(TH):", is_valid_number_for_region(n, "TH"))
print("region_code         :", region_code_for_number(n))
# เบอร์ตัวอย่างของภูมิภาค (ใช้ทดสอบรูปแบบ/สร้าง test data)
ex = example_number_for_type("TH", PhoneNumberType.MOBILE)
print("TH mobile example   :", p.format_number(ex, p.PhoneNumberFormat.E164))
PY
```

**สกัดเบอร์โทรจากข้อความ/หน้าเว็บ (PhoneNumberMatcher) — มีประโยชน์มากตอนวิเคราะห์เพจ:**

```bash
python3 - <<'PY'
import phonenumbers as p
from phonenumbers import PhoneNumberMatcher
text = "ติดต่อ 081-876-5432 หรือ +66 2 123 4567 ครับ"   # ใส่เนื้อหาเพจ/ไฟล์ที่ scrape มา
for m in PhoneNumberMatcher(text, "TH"):
    print(p.format_number(m.number, p.PhoneNumberFormat.E164))
PY
```

**สกัดเบอร์จากไฟล์ที่ดาวน์โหลด (เช่น หน้าเว็บที่ curl มา):**

```bash
curl -s "https://example.com/contact" -o page.html
python3 - page.html <<'PY'
import sys, phonenumbers as p
from phonenumbers import PhoneNumberMatcher
html = open(sys.argv[1], encoding="utf-8", errors="ignore").read()
found = sorted({p.format_number(m.number, p.PhoneNumberFormat.E164) for m in PhoneNumberMatcher(html, "TH")})
print("\n".join(found) or "(ไม่พบเบอร์)")
PY
```

### 3.2 PhoneInfoga — สแกนเบอร์แบบครบวงจร

PhoneInfoga รวมหลาย scanner: `local` (offline), `numverify` (API), `googlesearch` (สร้าง dork), `ovh`, `googlecse`

**ดู scanner ที่โหลดอยู่:**

```bash
phoneinfoga scanners
```

**สแกนเต็มรูปแบบ (ทุก scanner):**

```bash
phoneinfoga scan -n "+66818765432"
```

**รันเฉพาะ local scanner (offline — ปิด scanner อื่น):**

```bash
phoneinfoga scan -n "+66818765432" -D numverify -D googlesearch -D ovh -D googlecse
```

**รันเฉพาะ googlesearch (สร้าง Google dork URLs พร้อมใช้ — ไม่ยิงเป้าหมาย):**

```bash
phoneinfoga scan -n "+66818765432" -D local -D numverify -D ovh -D googlecse
```

**เปิด Numverify scanner (ต้องมี API key ฟรีจาก numverify.com):**

```bash
export NUMVERIFY_API_KEY="YOUR_NUMVERIFY_KEY"
phoneinfoga scan -n "+66818765432" -D googlesearch -D ovh -D googlecse
```

**ใช้ไฟล์ `.env` เก็บ key แทน export:**

```bash
cat > .env <<'ENV'
NUMVERIFY_API_KEY=YOUR_NUMVERIFY_KEY
ENV
phoneinfoga scan -n "+66818765432" --env-file .env
```

**เปิด Web UI (สแกนผ่านเบราว์เซอร์ — bind localhost เท่านั้น):**

```bash
phoneinfoga serve -p 5000
# เปิด http://127.0.0.1:5000
```

**บันทึกผล dork URLs ลงไฟล์ (grep เอา URL):**

```bash
phoneinfoga scan -n "+66818765432" 2>/dev/null | grep -oE 'https?://[^ ]+' > phone_dorks.txt
wc -l phone_dorks.txt
```

> **การอ่านผล (Red):** `local` ให้ country/รูปแบบ; `googlesearch` ให้ dork ค้นโซเชียล/เว็บรับ SMS ชั่วคราว
> (บ่งชี้ว่าเบอร์อาจเป็น disposable); `numverify` ให้ carrier/line type ที่แม่นขึ้น
> **มุม Purple:** dork ที่ชี้ไปเว็บรับ SMS ชั่วคราว = สัญญาณว่าเบอร์อาจถูกใช้สมัครบัญชีปลอม

### 3.3 ignorant — เบอร์นี้ผูกกับบัญชีใด

`ignorant` (จากผู้สร้าง holehe) เช็กว่าเบอร์ถูกใช้ลงทะเบียนบน Instagram/Amazon/Snapchat หรือไม่
**โดยไม่ส่ง SMS/ไม่แจ้งเจ้าของ** — ใช้ฟีเจอร์ "ลืมรหัสผ่าน"

**รูปแบบคำสั่ง: `ignorant <country code> <number ไม่มีรหัสประเทศ>`**

```bash
ignorant 66 818765432          # เบอร์ไทย (country=66)
ignorant 1 4155552671          # เบอร์ US (country=1)
```

**แสดงเฉพาะที่ "ใช้แล้ว" + ไม่ล้างจอ/ไม่ใส่สี:**

```bash
ignorant --only-used --no-clear --no-color 66 818765432
```

**ตั้ง timeout:**

```bash
ignorant --only-used -T 15 66 818765432
```

**วนตรวจหลายเบอร์ (numbers_local.txt: "66 818765432" ต่อบรรทัด):**

```bash
while read -r CC NUM; do
  echo "==== +$CC $NUM ===="
  ignorant --only-used --no-clear --no-color "$CC" "$NUM"
done < numbers_local.txt
```

> **การอ่านผล:** `[+]` = เบอร์ถูกใช้บนเว็บนั้น, `[-]` = ไม่ถูกใช้, `[x]` = rate limit
> **มุม Purple:** ถ้าเบอร์พนักงานผูกกับบัญชีโซเชียลส่วนตัว = พื้นผิวโจมตี social engineering เพิ่ม

### 3.4 Google dork สำหรับเบอร์โทร

Dork คือ query เสิร์ชขั้นสูง — สร้าง URL แล้วเปิดในเบราว์เซอร์ (ไม่ใช่การยิงเป้าหมายโดยตรง)

**สคริปต์สร้าง dork เบอร์ (บันทึกเป็น `phone_dorks.py`):**

```python
#!/usr/bin/env python3
# phone_dorks.py — generate search dorks for a phone number (ATT&CK T1593.002)
import sys, urllib.parse, phonenumbers as p
n = p.parse(sys.argv[1], None)
e164 = p.format_number(n, p.PhoneNumberFormat.E164)
natl = p.format_number(n, p.PhoneNumberFormat.NATIONAL).replace(' ', '')
nums = {e164, e164.lstrip('+'), natl, natl.lstrip('0')}
variants = " OR ".join(f'"{x}"' for x in sorted(nums))
dorks = [
    f'({variants})',
    f'({variants}) site:facebook.com',
    f'({variants}) site:linkedin.com',
    f'({variants}) site:twitter.com OR site:x.com',
    f'({variants}) (contact OR line OR whatsapp OR telegram)',
    f'({variants}) filetype:pdf OR filetype:xlsx',
    f'({variants}) (resume OR cv OR vcard)',
]
for d in dorks:
    print("https://www.google.com/search?q=" + urllib.parse.quote(d))
```

**รัน:**

```bash
python3 phone_dorks.py "+66818765432"
# เปิดทีละ URL ในเบราว์เซอร์ WSL (หรือ copy ไป Windows browser)
```

**เปิด dork ตัวแรกในเบราว์เซอร์ Windows จาก WSL:**

```bash
python3 phone_dorks.py "+66818765432" | head -1 | xargs -I{} cmd.exe /c start "{}" 2>/dev/null
```

> **มุม Purple:** dork เหล่านี้เผยว่าเบอร์รั่วในไฟล์ PDF/Excel สาธารณะหรือไม่ →
> การป้องกันคือสแกนเว็บ/ไฟล์ขององค์กรเองด้วย dork ชุดเดียวกัน แล้วลบ/จำกัดการเข้าถึง

### 3.5 สกัด PII (เบอร์ + อีเมล) จากเพจที่เก็บมา

เมื่อได้หน้าเว็บ/ไฟล์สาธารณะมา ให้สกัด **ทั้งอีเมลและเบอร์** ในครั้งเดียว (T1589)

**สคริปต์รวม (บันทึกเป็น `extract_pii.py`):**

```python
#!/usr/bin/env python3
# extract_pii.py — pull emails + phone numbers from text/HTML (ATT&CK T1589)
import sys, re, phonenumbers as p
from phonenumbers import PhoneNumberMatcher
region = sys.argv[2] if len(sys.argv) > 2 else "TH"
data = open(sys.argv[1], encoding="utf-8", errors="ignore").read()
emails = sorted(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', data)))
phones = sorted({p.format_number(m.number, p.PhoneNumberFormat.E164)
                 for m in PhoneNumberMatcher(data, region)})
print("=== EMAILS ==="); print("\n".join(emails) or "(ไม่พบ)")
print("=== PHONES ==="); print("\n".join(phones) or "(ไม่พบ)")
```

**รัน:**

```bash
source ~/osint/bin/activate
curl -s "https://example.com/about" -o page.html
python3 extract_pii.py page.html TH
```

**ดึงหลายเพจจากรายการ URL แล้วรวมผล:**

```bash
# urls.txt: หนึ่ง URL ต่อบรรทัด
while read -r U; do
  curl -s "$U" -o /tmp/p.html 2>/dev/null
  echo "==== $U ===="
  python3 extract_pii.py /tmp/p.html TH
done < urls.txt
```

**one-liner สกัดอีเมลอย่างเดียวจากหลายเพจ:**

```bash
while read -r U; do curl -s "$U"; done < urls.txt \
  | grep -oiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' | sort -u
```

> **มุม Purple:** รันสคริปต์นี้กับหน้าเว็บ *ขององค์กรตัวเอง* (about/team/contact) เพื่อดูว่าเปิดเผย
> อีเมล/เบอร์อะไรบ้าง แล้วพิจารณาปกปิด (เช่น ใช้ฟอร์มติดต่อแทนอีเมลตรง)

---

## 4. ส่วน B — OSINT ชื่อบุคคล

> **ATT&CK:** T1589.003 (Employee Names), T1593.001 (Social Media)
> ชื่อบุคคลค้นตรง ๆ ได้ผลน้อย — เทคนิคคือ **แปลงชื่อ → username candidates → ค้นข้ามแพลตฟอร์ม**
> ควบคู่กับ **dork เสิร์ชเอนจิน/LinkedIn**

### 4.1 สร้าง username candidates จากชื่อ

**สคริปต์สร้าง username (บันทึกเป็น `name2user.py`):**

```python
#!/usr/bin/env python3
# name2user.py — generate username candidates from a full name (ATT&CK T1589.003)
import sys
first = sys.argv[1].lower()
last  = sys.argv[2].lower() if len(sys.argv) > 2 else ""
seps = ["", ".", "_", "-"]
c = set()
if last:
    for s in seps:
        c.add(f"{first}{s}{last}")
        c.add(f"{last}{s}{first}")
        c.add(f"{first[0]}{s}{last}")
        c.add(f"{first}{s}{last[0]}")
    c.add(first + last[0]); c.add(first[0] + last)
    c.add(last + first[0]); c.add(f"{first}{last}")
else:
    c.add(first)
for u in sorted(c):
    print(u)
```

**รัน:**

```bash
python3 name2user.py John Doe > usernames.txt
cat usernames.txt
```

**one-liner (bash ล้วน):**

```bash
F=john; L=doe
for s in "" "." "_" "-"; do echo "${F}${s}${L}"; echo "${L}${s}${F}"; echo "${F:0:1}${s}${L}"; done | sort -u
```

**เพิ่มปีเกิด/ตัวเลขท้าย (เพิ่ม candidate ที่คนนิยมใช้):**

```bash
while read -r U; do
  echo "$U"
  for y in 1 7 88 99 2000 2543; do echo "${U}${y}"; done
done < usernames.txt | sort -u > usernames_ext.txt
wc -l usernames_ext.txt
```

### 4.2 sherlock — ค้น username ข้ามเครือข่าย

sherlock ตรวจ username บนเว็บ 400+ แห่งอย่างรวดเร็ว

**ค้น username เดียว (แสดงเฉพาะที่พบ):**

```bash
sherlock --print-found johndoe
```

**ค้นหลาย username (จากที่สร้างในข้อ 4.1):**

```bash
sherlock --print-found $(cat usernames.txt | tr '\n' ' ')
```

**จำกัดบางไซต์ (เร็วขึ้น) + ตั้ง timeout:**

```bash
sherlock --timeout 10 --print-found --site GitHub --site Reddit --site Twitter --site Instagram johndoe
```

**บันทึกผลเป็นไฟล์/CSV/JSON:**

```bash
sherlock --print-found --csv johndoe                 # johndoe.csv
sherlock --print-found --output johndoe.txt johndoe  # ข้อความ
sherlock --print-found --json johndoe.json johndoe   # JSON
```

**เก็บผลหลาย username ลงโฟลเดอร์เดียว:**

```bash
sherlock --print-found --folderoutput ./sherlock_out $(cat usernames.txt | tr '\n' ' ')
ls -1 ./sherlock_out
```

**วนตรวจทีละ username พร้อมหน่วงเวลา (กัน rate limit):**

```bash
while read -r U; do
  echo "==== $U ===="
  sherlock --timeout 10 --print-found "$U"
  sleep 3
done < usernames.txt
```

> **การอ่านผล:** `[+] <ไซต์>: <URL>` = พบบัญชี — **ต้อง verify** เพราะ username ซ้ำได้
> **มุม Purple:** ถ้าพบว่า username แบบเดียวกับอีเมลองค์กรถูกใช้ทั่วเว็บ → เสี่ยง credential stuffing

### 4.3 maigret — โปรไฟล์เชิงลึก 3000+ ไซต์

maigret ครอบคลุมกว่า sherlock และดึงข้อมูลเสริม (ชื่อจริง, รูป, วันสร้างบัญชี)

```bash
maigret johndoe --top-sites 100 --timeout 10        # จำกัดไซต์ยอดนิยม
maigret johndoe --html                              # รายงาน HTML (มีรูป/ลิงก์)
maigret johndoe --pdf                               # รายงาน PDF
maigret johndoe -J simple                           # JSON
maigret johndoe --tags social,photo --top-sites 150 # เฉพาะโซเชียล/รูป
maigret johndoe --folderoutput ./maigret_out        # กำหนดโฟลเดอร์
```

**ตรวจหลาย username + permute (สลับหาความเป็นเจ้าของเดียวกัน):**

```bash
maigret johndoe john.doe jdoe --permute --top-sites 100
```

**ดึงเฉพาะบัญชีที่ยืนยัน (Claimed) จาก JSON:**

```bash
maigret johndoe --top-sites 100 -J simple --no-color
# อ่านไฟล์ JSON ที่สร้างในโฟลเดอร์ reports/
jq -r 'to_entries[] | select(.value.status.status=="Claimed") | "\(.key): \(.value.url_user)"' \
   reports/report_johndoe_simple.json 2>/dev/null
```

### 4.4 socialscan + Google/LinkedIn dork สำหรับชื่อ

**socialscan — เช็ก username ว่าง/ถูกใช้ (ยืนยันข้าม sherlock):**

```bash
socialscan johndoe john.doe jdoe --show-urls
socialscan johndoe --available-only
```

**สคริปต์สร้าง dork ชื่อ (บันทึกเป็น `name_dorks.py`):**

```python
#!/usr/bin/env python3
# name_dorks.py — generate people-search dorks (ATT&CK T1593)
import sys, urllib.parse
name = sys.argv[1]
org  = sys.argv[2] if len(sys.argv) > 2 else ""
q = f'"{name}"'
o = f' "{org}"' if org else ""
dorks = [
    f'{q}{o} site:linkedin.com/in',
    f'{q} site:facebook.com',
    f'{q} site:twitter.com OR site:x.com',
    f'{q} site:instagram.com',
    f'{q}{o} (email OR contact OR phone OR mobile)',
    f'{q} filetype:pdf (cv OR resume OR profile)',
    f'{q}{o} (intitle:profile OR intitle:team OR intitle:staff)',
    f'{q} site:github.com',
]
for d in dorks:
    print("https://www.google.com/search?q=" + urllib.parse.quote(d))
```

**รัน:**

```bash
python3 name_dorks.py "John Doe" "Example Corp"
python3 name_dorks.py "John Doe" "Example Corp" | head -1 | xargs -I{} cmd.exe /c start "{}" 2>/dev/null
```

> **มุม Purple:** dork `site:linkedin.com/in` + ชื่อองค์กร = วิธีที่ศัตรูสร้างรายชื่อพนักงาน (org chart)
> การป้องกัน: จำกัดข้อมูลตำแหน่ง/ทีมในหน้าเว็บสาธารณะ, ฝึกพนักงานเรื่อง privacy setting

### 4.5 theHarvester — ชื่อพนักงานจากโดเมนองค์กร

theHarvester เก็บอีเมล/ชื่อที่ผูกกับโดเมน — ใช้สร้างรายชื่อพนักงาน (T1589.003)

```bash
theHarvester -d example.com -b bing,duckduckgo,crtsh -l 500 -f staff_report
# อ่านอีเมลที่พบ → อนุมาน pattern ชื่อ (firstname.lastname@)
jq -r '.emails[]?' staff_report.json 2>/dev/null | sort -u
```

**อนุมานชื่อจาก pattern อีเมล (firstname.lastname):**

```bash
jq -r '.emails[]?' staff_report.json 2>/dev/null \
  | sed 's/@.*//' | tr '.' ' ' | sort -u
```

### 4.6 recon-ng — เฟรมเวิร์กเก็บ contact/profile (Kali apt)

recon-ng เป็นเฟรมเวิร์ก OSINT แบบ modular บน Kali (ติดตั้ง `sudo apt install recon-ng`)
เหมาะกับการเก็บ contacts/profiles อย่างเป็นระบบและบันทึกลงฐานข้อมูล workspace

```bash
# เปิด recon-ng
recon-ng

# ---- คำสั่งภายใน recon-ng (interactive) ----
# สร้าง workspace แยกต่อเป้าหมาย
workspaces create example_engagement

# ค้นและติดตั้งโมดูลจาก marketplace
marketplace search profiler
marketplace install recon/profiles-profiles/profiler
marketplace install recon/contacts-contacts/mangle

# ตั้งค่า input แล้วรัน
modules load recon/profiles-profiles/profiler
options set SOURCE johndoe
run

# ดูผลที่เก็บในตาราง
show profiles
show contacts
```

**รัน recon-ng แบบไม่โต้ตอบ (resource script):**

```bash
cat > recon.rc <<'RC'
workspaces create example_engagement
modules load recon/profiles-profiles/profiler
options set SOURCE johndoe
run
show profiles
exit
RC
recon-ng -r recon.rc
```

> โมดูลจำนวนมากใน recon-ng ต้องตั้ง API key ก่อน (`keys add <name> <value>`, `keys list`)
> เริ่มจากโมดูลที่ไม่ต้องมี key ก่อน แล้วค่อยเพิ่ม

### 4.7 SpiderFoot สำหรับชื่อ/เบอร์ (เชื่อมโยงกับไฟล์ที่ 1)

SpiderFoot (จากไฟล์ที่ 1) รับเป้าหมายได้หลายชนิด รวมถึง **ชื่อบุคคล (HUMAN_NAME)** และ
**เบอร์โทร (PHONE_NUMBER)** — ตรวจจับชนิดอัตโนมัติจากรูปแบบ input

```bash
# (สมมติติดตั้ง SpiderFoot จากไฟล์ที่ 1 แล้ว: ~/spiderfoot)
cd ~/spiderfoot && source venv/bin/activate

# สแกนชื่อบุคคล (ใส่ในเครื่องหมายคำพูด) — passive
python3 sf.py -s "John Doe" -u passive -o csv > name_sf.csv

# สแกนเบอร์โทร (E164) — passive
python3 sf.py -s "+66818765432" -u passive -o csv > phone_sf.csv

# เลือกเฉพาะโมดูลที่เกี่ยวกับชื่อ/โซเชียล
python3 sf.py -s "John Doe" -m sfp_names,sfp_social,sfp_accounts -o csv > name_focus.csv

# กรองผลเฉพาะชนิดข้อมูลที่สนใจ
python3 sf.py -s "+66818765432" -u passive -t PHONE_NUMBER,HUMAN_NAME,SOCIAL_MEDIA
```

> ใช้ SpiderFoot เป็น "ตัวรวมศูนย์" แล้ว cross-check กับผลจาก sherlock/maigret/phoneinfoga
> ที่รันแยก เพื่อยืนยันข้อมูลข้ามเครื่องมือ

---

## 5. ส่วน C — Correlation & Pivoting เชิงลึก

หัวใจของ OSINT เชิงลึกคือการ **ปะติดปะต่อ identity** จากจุดเริ่มต่างกัน (ชื่อ/เบอร์/อีเมล/username)
ให้บรรจบเป็นบุคคลเดียว โดย **ยืนยันข้ามอย่างน้อย 2 แหล่ง** ก่อนสรุป

```
        ชื่อ ────▶ username candidates ────▶ sherlock/maigret ─┐
                                                              ├─▶ โปรไฟล์โซเชียล ─▶ ยืนยันตัวตน
        เบอร์ ───▶ phoneinfoga/ignorant ───▶ บัญชีที่ผูก ──────┘        │
                        │                                              ▼
                        └─▶ dork ─▶ เบอร์ปรากฏในเว็บ/ไฟล์ ─────────▶ อีเมล/ที่อยู่/องค์กร
        อีเมล ──▶ (ไฟล์ที่ 2: holehe/h8mail/crt.sh) ──────────────────┘
```

**ลูกโซ่คำสั่งจากเบอร์ → ตัวตน:**

```bash
NUM="+66818765432"; CC=66; LOCAL=818765432
source ~/osint/bin/activate

# 1) offline intel
python3 phone_info.py "$NUM"

# 2) เบอร์ผูกกับบัญชีใด
ignorant --only-used --no-clear --no-color "$CC" "$LOCAL"

# 3) dork หาเบอร์ในเว็บ/ไฟล์
python3 phone_dorks.py "$NUM" > phone_dorks.txt

# 4) ถ้า dork พบชื่อ → แปลงเป็น username → ค้นต่อ
python3 name2user.py John Doe > usernames.txt
sherlock --print-found $(cat usernames.txt | tr '\n' ' ')
```

**ลูกโซ่คำสั่งจากชื่อ → ตัวตน → อีเมลองค์กร:**

```bash
# 1) ชื่อ → username → โปรไฟล์
python3 name2user.py John Doe > usernames.txt
maigret $(cat usernames.txt | tr '\n' ' ') --top-sites 100 --html

# 2) ชื่อ + องค์กร → dork
python3 name_dorks.py "John Doe" "Example Corp" > name_dorks.txt

# 3) โดเมนองค์กร → รายชื่อพนักงาน/อีเมล
theHarvester -d example.com -b bing,crtsh -l 300 -f staff
jq -r '.emails[]?' staff.json 2>/dev/null | sort -u

# 4) อีเมลที่คาดเดา → ตรวจต่อ (เครื่องมือไฟล์ที่ 2)
echo "john.doe@example.com" | while read -r E; do holehe --only-used "$E"; done
```

> **กติกา verify:** ทุก pivot มี false positive (ชื่อ/username/เบอร์ซ้ำ) — บันทึกระดับความมั่นใจ
> (confirmed / probable / candidate) และแหล่งที่มาต่อ finding เสมอ

### 5.1 ตารางเมทริกซ์ pivot (จากอะไร ไปอะไรได้)

| มีข้อมูล ↓ / อยากได้ → | ชื่อ | username | อีเมล | เบอร์ | โซเชียล |
|---|---|---|---|---|---|
| **ชื่อ** | — | name2user.py | theHarvester (pattern) | dork/เพจ | sherlock/maigret |
| **username** | maigret (fullname) | — | เดา pattern @domain | ignorant (ถ้าเบอร์=user) | sherlock/maigret |
| **อีเมล** | pattern → ชื่อ | local-part | — | เพจ/breach | holehe (ไฟล์ 2) |
| **เบอร์** | dork/เพจ | — | เพจ/breach | — | ignorant |
| **โซเชียล** | โปรไฟล์ | @handle | โปรไฟล์ | โปรไฟล์ | — |

### 5.2 สคริปต์รวมศูนย์ identity resolution (multi-input)

สคริปต์นี้รับได้ทั้งชื่อ/อีเมล/เบอร์ แล้วแตกเป็นทุกเส้นทางในครั้งเดียว เก็บลงโฟลเดอร์เดียว
พร้อมสรุปเป็น `summary.md`

```bash
#!/usr/bin/env bash
# identity_recon.sh — multi-input OSINT correlation (ATT&CK T1589/T1593)
# ใช้: ./identity_recon.sh --name "John Doe" --email john.doe@example.com --phone "+66818765432" --org "Example Corp"
set -euo pipefail
NAME=""; EMAIL=""; PHONE=""; ORG=""
while [ $# -gt 0 ]; do case "$1" in
  --name)  NAME="$2"; shift 2;;
  --email) EMAIL="$2"; shift 2;;
  --phone) PHONE="$2"; shift 2;;
  --org)   ORG="$2"; shift 2;;
  *) echo "unknown: $1"; exit 1;;
esac; done
OUT="identity_$(date +%Y%m%d_%H%M%S)"; mkdir -p "$OUT"
echo "# Identity Recon Summary ($(date -u))" > "$OUT/summary.md"
echo "target: name=$NAME email=$EMAIL phone=$PHONE org=$ORG" | tee -a "$OUT/summary.md"

# --- จากชื่อ ---
if [ -n "$NAME" ]; then
  set -- $NAME; FIRST="$1"; LAST="${2:-}"
  python3 name2user.py "$FIRST" "$LAST" > "$OUT/usernames.txt"
  echo "[name] usernames -> $OUT/usernames.txt"
  sherlock --timeout 10 --print-found $(tr '\n' ' ' < "$OUT/usernames.txt") \
    > "$OUT/sherlock.txt" 2>&1 || true
  python3 name_dorks.py "$NAME" "$ORG" > "$OUT/name_dorks.txt" || true
  echo "## Sherlock" >> "$OUT/summary.md"
  grep '\[+\]' "$OUT/sherlock.txt" 2>/dev/null >> "$OUT/summary.md" || echo "(none)" >> "$OUT/summary.md"
fi

# --- จากอีเมล (เครื่องมือไฟล์ที่ 2) ---
if [ -n "$EMAIL" ]; then
  holehe --no-clear --no-color --only-used "$EMAIL" > "$OUT/holehe.txt" 2>&1 || true
  echo "## holehe (email accounts)" >> "$OUT/summary.md"
  grep '\[+\]' "$OUT/holehe.txt" 2>/dev/null >> "$OUT/summary.md" || echo "(none)" >> "$OUT/summary.md"
fi

# --- จากเบอร์ ---
if [ -n "$PHONE" ]; then
  python3 phone_info.py "$PHONE" > "$OUT/phone.txt" 2>&1 || true
  CC=$(python3 -c "import phonenumbers as p,sys;n=p.parse(sys.argv[1],None);print(n.country_code)" "$PHONE")
  NAT=$(python3 -c "import phonenumbers as p,sys;n=p.parse(sys.argv[1],None);print(n.national_number)" "$PHONE")
  ignorant --only-used --no-clear --no-color "$CC" "$NAT" > "$OUT/ignorant.txt" 2>&1 || true
  python3 phone_dorks.py "$PHONE" > "$OUT/phone_dorks.txt" || true
  echo "## phone (offline + accounts)" >> "$OUT/summary.md"
  cat "$OUT/phone.txt" >> "$OUT/summary.md"
fi

# --- จากองค์กร ---
if [ -n "$ORG" ] && [ -n "$EMAIL" ]; then
  DOM="${EMAIL#*@}"
  theHarvester -d "$DOM" -b bing,crtsh -l 200 -f "$OUT/org" >/dev/null 2>&1 || true
fi

echo "[✓] เสร็จ — ดู $OUT/summary.md"; ls -1 "$OUT"
```

**ใช้งาน:**

```bash
source ~/osint/bin/activate
chmod +x identity_recon.sh
./identity_recon.sh --name "John Doe" --email john.doe@example.com --phone "+66818765432" --org "Example Corp"
cat identity_*/summary.md
```

---

## 6. ส่วน D — สคริปต์อัตโนมัติแบบครบวงจร

### 6.1 สคริปต์สแกนเบอร์โทร (passive-first)

```bash
#!/usr/bin/env bash
# phone_recon.sh — passive phone OSINT chain (ATT&CK T1589)
# ใช้: ./phone_recon.sh "+66818765432" 66 818765432
set -euo pipefail
NUM="${1:?ใส่เบอร์ E164 เช่น +66818765432}"
CC="${2:?ใส่ country code เช่น 66}"
LOCAL="${3:?ใส่เบอร์ในประเทศ เช่น 818765432}"
OUT="phone_$(echo "$NUM" | tr -cd '0-9')_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"; echo "[*] target=$NUM  out=$OUT/"

echo "[1/4] phonenumbers (offline)..."
python3 phone_info.py "$NUM" > "$OUT/local.txt" 2>&1 || true

echo "[2/4] phoneinfoga (local + googlesearch)..."
phoneinfoga scan -n "$NUM" -D numverify -D ovh -D googlecse > "$OUT/phoneinfoga.txt" 2>&1 || true

echo "[3/4] ignorant (บัญชีที่ผูก)..."
ignorant --only-used --no-clear --no-color "$CC" "$LOCAL" > "$OUT/ignorant.txt" 2>&1 || true

echo "[4/4] dork URLs..."
python3 phone_dorks.py "$NUM" > "$OUT/dorks.txt" 2>&1 || true

echo "[✓] เสร็จ — ดูผลที่ $OUT/"; ls -1 "$OUT"
```

**ใช้งาน:**

```bash
source ~/osint/bin/activate
chmod +x phone_recon.sh
./phone_recon.sh "+66818765432" 66 818765432
```

### 6.2 สคริปต์สแกนชื่อบุคคล

```bash
#!/usr/bin/env bash
# name_recon.sh — passive name OSINT chain (ATT&CK T1589.003 / T1593)
# ใช้: ./name_recon.sh John Doe "Example Corp"
set -euo pipefail
FIRST="${1:?ใส่ชื่อ}"; LAST="${2:?ใส่นามสกุล}"; ORG="${3:-}"
OUT="name_${FIRST}_${LAST}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"; echo "[*] target=$FIRST $LAST ($ORG)  out=$OUT/"

echo "[1/4] username candidates..."
python3 name2user.py "$FIRST" "$LAST" > "$OUT/usernames.txt"

echo "[2/4] sherlock..."
sherlock --timeout 10 --print-found --folderoutput "$OUT/sherlock" \
  $(cat "$OUT/usernames.txt" | tr '\n' ' ') > "$OUT/sherlock.txt" 2>&1 || true

echo "[3/4] socialscan..."
socialscan $(cat "$OUT/usernames.txt" | tr '\n' ' ') --show-urls > "$OUT/socialscan.txt" 2>&1 || true

echo "[4/4] dork URLs..."
python3 name_dorks.py "$FIRST $LAST" "$ORG" > "$OUT/dorks.txt" 2>&1 || true

echo "[✓] เสร็จ — ดูผลที่ $OUT/"; ls -1 "$OUT"
```

**ใช้งาน:**

```bash
chmod +x name_recon.sh
./name_recon.sh John Doe "Example Corp"
```

### 6.3 สร้าง attack log สำหรับ Purple Team debrief

ทุกการรันควรบันทึกเป็น log ที่ map กับ ATT&CK เพื่อส่งต่อฝ่าย Blue:

```bash
log_action() {
  # log_action <ATT&CK_ID> <technique> <target> <expected_telemetry>
  printf '%s | %s | %s | target=%s | expected=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" "$3" "$4" >> attack_log.csv
}

log_action T1589.003 "Employee name enumeration" "John Doe" "none (passive)"
log_action T1589      "Phone number OSINT"        "+66818765432" "none (passive)"
log_action T1593.001  "Social media search"       "johndoe" "possible login anomaly if active"
cat attack_log.csv
```

---

## 7. ส่วน E — มุมมอง Purple Team: ตรวจจับและป้องกัน

นี่คือส่วนที่แยก **Purple Team ออกจาก Black Hat** — เอาผล recon มา *ยกระดับการป้องกัน*
recon ส่วนใหญ่เป็น passive (ไม่แตะระบบเป้าหมาย) จึง **ตรวจจับตรง ๆ ยาก** ทางแก้คือลดพื้นผิวและวางกับดัก

### 7.1 ตารางแมป: เทคนิค → การตรวจจับ → การป้องกัน

| ATT&CK | สิ่งที่ Red ทำ | Blue ตรวจจับได้ไหม | การป้องกัน (Harden) |
|---|---|---|---|
| T1589.003 | เก็บชื่อพนักงานจากเว็บ/LinkedIn | ❌ (external) | ลดข้อมูลทีม/ตำแหน่งในหน้าสาธารณะ; นโยบาย privacy |
| T1589 (phone) | รวบรวมเบอร์จากไฟล์รั่ว | ❌ (external) | สแกนไฟล์สาธารณะขององค์กรด้วย dork เดียวกัน; ลบ PII |
| T1593.001 | ค้นโปรไฟล์โซเชียล | ⚠️ บางส่วน (ถ้ามี API เข้าถึง) | awareness training; ตั้ง privacy setting |
| T1593.002 | dork เสิร์ชเอนจิน | ❌ | robots.txt เฉพาะจุด; ลบไฟล์ที่ index ไม่ควร |
| ignorant/holehe (active) | password-recovery probing | ⚠️ (ถ้าเฝ้า auth log) | ตรวจ pattern reset ผิดปกติ; rate-limit; alert |
| T1598 (ถัดไป) | phishing จากข้อมูลที่ได้ | ✅ (email gateway) | DMARC/SPF/DKIM; anti-phishing; report button |

### 7.2 คำสั่งฝั่ง Blue: สแกน footprint ขององค์กรตัวเอง

ใช้ "เครื่องมือชุดเดียวกับ Red" ยิงใส่ **สินทรัพย์ของตัวเอง** เพื่อดูว่าเปิดเผยอะไรบ้าง

```bash
# 1) เบอร์/อีเมลองค์กรรั่วในเว็บสาธารณะไหม (dork ตัวเอง)
python3 phone_dorks.py "+6621234567" > our_phone_exposure.txt
python3 name_dorks.py "CEO Name" "Our Company" > our_name_exposure.txt

# 2) ชื่อ/อีเมลพนักงานที่ค้นเจอจากโดเมนตัวเอง
theHarvester -d ourcompany.com -b bing,crtsh,duckduckgo -l 500 -f self_audit
jq -r '.emails[]?' self_audit.json 2>/dev/null | sort -u | tee exposed_emails.txt | wc -l

# 3) ซับโดเมน/cert ที่เปิดเผย (จากไฟล์ที่ 2)
curl -s "https://crt.sh/?q=%25.ourcompany.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

### 7.3 การวางกับดัก (Detection Engineering)

การ recon แบบ passive ตรวจไม่ได้ แต่ "ขั้นถัดไป" ตรวจได้ — วาง canary/honeypot:

```bash
# แนวคิด (ตัวอย่างการจัดการ canary token ที่สร้างจาก canarytokens.org):
# - สร้างอีเมล/เอกสาร "ล่อ" ที่ฝัง canary token
# - ถ้ามีคนเปิด/ใช้ → ได้ alert ทันที = จับสัญญาณ recon→phishing ได้

# ตัวอย่าง: ตรวจ log การพยายาม reset password ผิดปกติ (สัญญาณ holehe/ignorant)
# (รันบน mail/auth server ขององค์กร ปรับ path ตามระบบจริง)
grep -iE "password.reset|forgot.password" /var/log/auth.log 2>/dev/null \
  | awk '{print $1,$2,$3}' | sort | uniq -c | sort -rn | head
```

### 7.4 Sigma rule (แนวคิด) — จับ enumeration ที่ผิดปกติ

```yaml
title: Suspicious Password-Reset Enumeration (possible OSINT probing)
status: experimental
description: จับ pattern การขอ reset password จำนวนมากในเวลาสั้น (สัญญาณ holehe/ignorant)
logsource:
  category: application
  product: web
detection:
  selection:
    uri|contains:
      - '/password/reset'
      - '/forgot'
  timeframe: 5m
  condition: selection | count() by src_ip > 20
level: medium
tags:
  - attack.reconnaissance
  - attack.t1589
```

> **หลัก Purple:** วัดผลเป็น "coverage" — เทคนิคไหน *ไม่มี telemetry* (recon passive) ให้ยอมรับ
> และย้ายไปลงทุนที่ "ลด footprint" แทน; เทคนิคที่ *มี telemetry* (active probing) ให้เขียน detection

### 7.5 Sigma rule เพิ่มเติม — จับ enumeration ผ่าน user-agent เครื่องมือ

```yaml
title: OSINT Tool User-Agent Detected (recon probing)
status: experimental
description: จับ user-agent ที่บ่งชี้เครื่องมือ OSINT อัตโนมัติยิงเข้าเว็บองค์กร
logsource:
  category: webserver
detection:
  selection:
    c-useragent|contains:
      - 'python-requests'
      - 'holehe'
      - 'sherlock'
      - 'phoneinfoga'
      - 'theHarvester'
  condition: selection
level: low
tags:
  - attack.reconnaissance
  - attack.t1593
falsepositives:
  - สคริปต์/บ็อตภายในที่ใช้ python-requests โดยชอบธรรม
```

> เครื่องมือจริงมักปลอม user-agent ได้ กติกานี้จึงเป็น *low fidelity* — ใช้เป็นสัญญาณเสริม
> ไม่ใช่ตัวชี้ขาด และควรจับคู่กับ rate-based detection (7.4)

### 7.6 คำสั่ง Blue: วิเคราะห์ log หา recon pattern

```bash
# หา IP ที่ยิง endpoint สมัคร/reset/login บ่อยผิดปกติ (top 10)
awk '$7 ~ /(reset|forgot|login|register)/ {print $1}' /var/log/nginx/access.log 2>/dev/null \
  | sort | uniq -c | sort -rn | head

# หา user-agent ของเครื่องมืออัตโนมัติ
grep -iE "python-requests|sherlock|holehe|phoneinfoga|curl" /var/log/nginx/access.log 2>/dev/null \
  | awk '{print $1}' | sort -u

# นับจำนวน request ต่อ IP ต่อนาที (จับ burst)
awk '{print $1, substr($4,2,17)}' /var/log/nginx/access.log 2>/dev/null \
  | sort | uniq -c | sort -rn | head
```

### 7.7 การวัด Coverage แบบ ATT&CK Navigator (แนวคิด)

สร้าง layer JSON เพื่อระบายสีเทคนิคตามระดับการป้องกัน (none/telemetry/detection/prevention)
แล้วอัปโหลดที่ <https://mitre-attack.github.io/attack-navigator/> เพื่อทำ heatmap แชร์ทีม

```bash
cat > navigator_recon.json <<'JSON'
{
  "name": "Recon Coverage - Name/Phone OSINT",
  "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
  "domain": "enterprise-attack",
  "techniques": [
    {"techniqueID": "T1589", "score": 25, "comment": "phone/identity - no telemetry, reduce footprint"},
    {"techniqueID": "T1589.003", "score": 25, "comment": "employee names - external, awareness"},
    {"techniqueID": "T1593", "score": 25, "comment": "search open sites - external"},
    {"techniqueID": "T1593.001", "score": 50, "comment": "social media - partial monitoring"},
    {"techniqueID": "T1598", "score": 75, "comment": "phishing-for-info - email GW detects"}
  ],
  "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 100}
}
JSON
echo "อัปโหลด navigator_recon.json ที่ ATT&CK Navigator เพื่อดู heatmap"
```

---

## 8. ส่วน F — OPSEC สำหรับผู้ทดสอบ

ในงาน Red Team ที่ได้รับอนุญาต การปกปิดร่องรอย *ของผู้ทดสอบเอง* คือส่วนหนึ่งของการจำลองศัตรูจริง
(และเพื่อไม่ให้ผลทดสอบปนเปื้อน)

```bash
# 1) ตรวจ IP ที่จะปรากฏต่อเป้าหมาย (ควรเป็น VPN/exit ที่ตกลงไว้ ไม่ใช่ IP บ้าน)
curl -s https://ifconfig.co/json | jq '{ip, country, org}'

# 2) route ผ่าน Tor (ถ้าตกลงใน RoE) — ตรวจว่าออกทาง Tor จริง
#    ต้องมี tor + torsocks: sudo apt install tor torsocks
sudo service tor start
torsocks curl -s https://check.torproject.org/api/ip | jq

# 3) แยกโปรไฟล์: อย่าใช้บัญชี/เบราว์เซอร์ส่วนตัวปนกับงานทดสอบ
#    ใช้ container/VM แยก และ user-agent ที่ตกลงไว้

# 4) หน่วงเวลา/สุ่ม delay กัน rate-limit และลดสัญญาณ automated
for U in $(cat usernames.txt); do
  sherlock --timeout 10 --print-found "$U"
  sleep $((RANDOM % 5 + 2))     # หน่วง 2–6 วินาทีแบบสุ่ม
done
```

**OPSEC checklist (สรุป):**

```
[ ] IP/exit ที่ใช้ตรงกับที่ระบุใน RoE (ไม่ใช่ IP ส่วนตัว)
[ ] แยกสภาพแวดล้อม (VM/container) ออกจากงานส่วนตัว
[ ] บันทึก attack log ครบ (เวลา, เทคนิค, ATT&CK, เป้าหมาย)
[ ] ไม่เก็บ PII เกินจำเป็น; เข้ารหัสไฟล์ผลลัพธ์
[ ] deconflict กับ SOC ก่อนทำ active probing
[ ] มีสัญญาณ abort และหยุดทันทีเมื่อได้รับแจ้ง
```

---

## 9. ส่วน G — เทมเพลตรายงาน (Red + Purple)

### 9.1 Red Team — สรุปผล recon บุคคล/เบอร์

```markdown
# Reconnaissance Findings — [Engagement]
**Authorization:** [SOW/RoE ref]  |  **Date:** [YYYY-MM-DD]  |  **Operator:** [name]

## Executive Summary
[2–3 ประโยค: เก็บชื่อ/เบอร์/บัญชีได้กี่รายการ, พื้นผิว social engineering ที่สำคัญ]

## Identity Findings
| # | ประเภท | ค่า | แหล่งที่มา | ความมั่นใจ | ATT&CK |
|---|--------|-----|-----------|-----------|--------|
| 1 | Employee name | John Doe | LinkedIn dork | confirmed | T1589.003 |
| 2 | Phone (mobile) | +66-81-xxx (AIS) | phoneinfoga local | confirmed | T1589 |
| 3 | Social account | github.com/jdoe | sherlock | probable | T1593.001 |

## Attack Surface / Phishing Pretext Potential
[ข้อมูลที่พบเอื้อต่อ T1598 phishing อย่างไร — เพื่อ "ทดสอบ" ไม่ใช่โจมตีจริง]

## Recommended Defensive Actions → ส่งต่อ Purple/Blue
```

### 9.2 Purple Team — Coverage & Remediation

```markdown
# Purple Team Debrief — Recon Phase
**Emulated behavior:** OSINT identity gathering (T1589 / T1593)

## Coverage Scorecard
| เทคนิค | telemetry? | detection? | prevention? | Gap/Action |
|--------|-----------|-----------|-------------|------------|
| T1589.003 name enum | none | none | partial | ลดข้อมูลทีมในเว็บสาธารณะ |
| T1589 phone OSINT | none | none | none | สแกน/ลบ PII ในไฟล์สาธารณะ |
| password-reset probing | yes | no | rate-limit | เขียน Sigma + alert |

## Prioritized Backlog
| Priority | Gap | Action | Owner |
|----------|-----|--------|-------|
| High | เบอร์/ชื่อผู้บริหารรั่วใน PDF สาธารณะ | ลบไฟล์ + de-index | IT/Web |
| Med | ไม่มี alert ต่อ reset enumeration | deploy Sigma rule | Detection Eng |
| Low | พนักงาน privacy setting หลวม | awareness training | Security |
```

---

## 10. Cheat Sheet — สรุปคำสั่งทั้งหมด

```bash
# ===== ติดตั้ง (ต่อจากไฟล์ 2) =====
pipx install sherlock-project ignorant maigret socialscan
python3 -m venv ~/osint && source ~/osint/bin/activate && pip install phonenumbers requests
curl -sSL -o /tmp/pi.tgz "https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Linux_x86_64.tar.gz"
tar -C /tmp -xzf /tmp/pi.tgz && sudo install -m0755 /tmp/phoneinfoga /usr/local/bin/phoneinfoga

# ===== เบอร์โทร =====
python3 phone_info.py "+66818765432"                         # offline: carrier/geo/tz/type
phoneinfoga scan -n "+66818765432"                           # ทุก scanner
phoneinfoga scan -n "+66818765432" -D numverify -D ovh -D googlecse  # local+dork
phoneinfoga serve -p 5000                                    # Web UI (localhost)
ignorant --only-used --no-clear --no-color 66 818765432      # เบอร์ → บัญชีที่ผูก
python3 phone_dorks.py "+66818765432"                        # dork URLs

# ===== ชื่อบุคคล =====
python3 name2user.py John Doe > usernames.txt                # ชื่อ → username candidates
sherlock --print-found $(cat usernames.txt | tr '\n' ' ')    # ค้น username
maigret johndoe --top-sites 100 --html                       # โปรไฟล์เชิงลึก + รายงาน
socialscan johndoe john.doe --show-urls                      # username ว่าง/ถูกใช้
python3 name_dorks.py "John Doe" "Example Corp"              # dork ชื่อ
theHarvester -d example.com -b bing,crtsh -l 300 -f staff    # ชื่อ/อีเมลจากโดเมน

# ===== automation =====
./phone_recon.sh "+66818765432" 66 818765432                 # สแกนเบอร์ครบวงจร
./name_recon.sh John Doe "Example Corp"                       # สแกนชื่อครบวงจร

# ===== Purple (audit ตัวเอง) =====
theHarvester -d ourcompany.com -b bing,crtsh -l 500 -f self_audit
jq -r '.emails[]?' self_audit.json | sort -u                 # อีเมลพนักงานที่รั่ว
curl -s https://ifconfig.co/json | jq '{ip,country,org}'     # OPSEC: IP ที่จะปรากฏ
```

**ตารางแฟล็กสำคัญ:**

| เครื่องมือ | แฟล็กที่ใช้บ่อย |
|---|---|
| phoneinfoga | `scan -n` `-D <scanner>` `--env-file` `serve -p` `scanners` |
| ignorant | `<cc> <number>` `--only-used` `--no-clear` `--no-color` `-T` |
| phonenumbers | (ไลบรารี) `parse` `is_valid_number` `geocoder` `carrier` `timezone` |
| sherlock | `--print-found` `--site` `--timeout` `--csv` `--json` `--folderoutput` |
| maigret | `--top-sites` `--html` `--pdf` `-J simple` `--tags` `--permute` |
| socialscan | `--show-urls` `--available-only` `-p` `--json` |

---

## 11. ความเสี่ยงที่ยังเหลืออยู่ (Residual Risks)

> ไม่มีเครื่องมือหรือกระบวนการใดปลอดภัยสมบูรณ์ — ต่อไปนี้คือความเสี่ยงที่ยังคงอยู่

1. **กฎหมาย/จริยธรรม (สูงสุด)** — การค้นชื่อ/เบอร์ของบุคคลจริงคือการประมวลผล PII ทำได้เฉพาะ
   เมื่อมี **อำนาจตามกฎหมาย/สัญญา** ที่ชัดเจน ผิดได้ทั้ง PDPA/GDPR/พ.ร.บ.คอมพิวเตอร์ฯ และคดีคุกคาม
2. **False positive สูงมาก** — ชื่อ/username/เบอร์ซ้ำกันได้ทั่วไป การสรุปผิดตัวคือความเสียหายต่อบุคคล
   บริสุทธิ์ — ยืนยันข้าม ≥2 แหล่ง และบันทึกระดับความมั่นใจเสมอ
3. **เส้นแบ่ง passive/active** — `ignorant`/`holehe` แตะบริการจริง (password-recovery) ต้องอยู่ใน scope
   และ deconflict กับ SOC ก่อน
4. **การเปิดเผยตัวผู้ทดสอบ** — IP/บัญชี/เบราว์เซอร์อาจถูกบันทึกฝั่งเป้าหมาย ใช้ OPSEC ตามส่วน F
5. **ข้อมูลเก่า/เปลี่ยนมือ** — เบอร์ถูกรีไซเคิล บัญชีถูกทิ้ง ทำให้เชื่อมโยงผิดคน
6. **ผลลัพธ์คือ PII อ่อนไหว** — ไฟล์รายงานมีชื่อ/เบอร์/บัญชีของคนจริง เข้ารหัส เก็บจำกัดเวลา และลบเมื่อจบงาน
7. **เครื่องมือ/แหล่งข้อมูลเปลี่ยน** — เว็บเปลี่ยน API, scanner บางตัวต้อง key อัปเดตเครื่องมือสม่ำเสมอ
   (`pipx upgrade-all`) และตรวจ syntax ล่าสุดก่อนใช้จริง
8. **Scope creep** — pivot อาจพาออกนอกขอบเขตที่อนุญาต หยุดและตรวจ scope ทุกครั้งที่พบ identity ใหม่

> **บทสรุป:** คู่มือนี้ให้เทคนิคระดับสูงในกรอบ **Red/Purple Team ที่ได้รับอนุญาต** — เป้าหมายคือ
> *ยกระดับการป้องกัน* ขององค์กร ไม่ใช่การล่วงละเมิดบุคคล ใช้เฉพาะกับเป้าหมายที่มีเอกสารอนุญาต
> และเมื่อสงสัยว่าเกินขอบเขต ให้หยุดและตรวจสอบก่อนเสมอ

---

> จบคู่มือชุด OSINT (ไฟล์ที่ 3/3) — ดูภาคก่อนหน้า:
> [ไฟล์ 1: พื้นฐาน SpiderFoot](./spiderfoot-email-osint-th.md) ·
> [ไฟล์ 2: คำสั่งอีเมลขั้นสูง](./spiderfoot-email-osint-advanced-th.md)
