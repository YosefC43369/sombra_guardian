# คู่มือ Email OSINT ขั้นสูงบน Kali Linux (WSL) — เน้นคำสั่งจริง (ภาคต่อ)

> **ภาคต่อจาก** [`spiderfoot-email-osint-th.md`](./spiderfoot-email-osint-th.md)
> ไฟล์แรกปูพื้นฐาน WSL + Kali + SpiderFoot มาแล้ว ไฟล์นี้ **ต่อยอดไปที่การค้นหาขั้นสูง**
> โดย **เน้นคำสั่งที่รันได้จริงบน Kali Linux ผ่าน WSL** และแนะนำ **เครื่องมืออื่นนอกจาก SpiderFoot**
>
> **หมายเหตุการทดสอบ:** คำสั่งในไฟล์นี้ผ่านการรันจริงบน Python 3.11 / Linux แล้ว
> เครื่องมือที่ยืนยันการรันสด: `holehe`, `socialscan`, `maigret`, `h8mail`, `mosint`,
> `dnstwist`, `curl→crt.sh`, `curl→DoH`, และ one-liner ทั้งหมด ส่วน `theHarvester`
> ยืนยัน syntax จากซอร์สโค้ดโดยตรง คำสั่งใดที่ต้องมี API key จะระบุไว้ชัดเจน
>
> ⚠️ **ใช้กับอีเมลของตัวเอง หรือเป้าหมายที่ได้รับอนุญาตเป็นลายลักษณ์อักษรเท่านั้น** (ดูหัวข้อ 1 ของไฟล์แรก)

---

## สารบัญ

1. [เตรียมเครื่อง Kali/WSL สำหรับติดตั้งเครื่องมือ (PEP 668)](#1-เตรียมเครื่อง-kaliwsl-สำหรับติดตั้งเครื่องมือ-pep-668)
2. [ตารางเครื่องมือทั้งหมดในไฟล์นี้](#2-ตารางเครื่องมือทั้งหมดในไฟล์นี้)
3. [holehe — อีเมลถูกใช้สมัครเว็บใดบ้าง](#3-holehe--อีเมลถูกใช้สมัครเว็บใดบ้าง)
4. [h8mail — ตรวจ data breach ของอีเมล](#4-h8mail--ตรวจ-data-breach-ของอีเมล)
5. [socialscan — เช็กการมีอยู่ของอีเมล/username](#5-socialscan--เช็กการมีอยู่ของอีเมลusername)
6. [Mosint — เครื่องมือรวมศูนย์ (Go)](#6-mosint--เครื่องมือรวมศูนย์-go)
7. [theHarvester — เก็บข้อมูลจากโดเมนของอีเมล](#7-theharvester--เก็บข้อมูลจากโดเมนของอีเมล)
8. [maigret — จาก local-part ของอีเมลสู่โปรไฟล์](#8-maigret--จาก-local-part-ของอีเมลสู่โปรไฟล์)
9. [crt.sh + curl — สืบโดเมน/ซับโดเมนของอีเมล](#9-crtsh--curl--สืบโดเมนซับโดเมนของอีเมล)
10. [Gravatar — จากอีเมลสู่รูป/โปรไฟล์](#10-gravatar--จากอีเมลสู่รูปโปรไฟล์)
11. [ตรวจสุขภาพอีเมลของโดเมน (MX/SPF/DMARC/DKIM)](#11-ตรวจสุขภาพอีเมลของโดเมน-mxspfdmarckim)
12. [dnstwist — หาโดเมนปลอม/ฟิชชิงที่เลียนแบบ](#12-dnstwist--หาโดเมนปลอมฟิชชิงที่เลียนแบบ)
13. [เครื่องมือที่ต้องมี API Key (EmailRep / HIBP / Hunter)](#13-เครื่องมือที่ต้องมี-api-key-emailrep--hibp--hunter)
14. [เทคนิค Pivot: อีเมล → username → โดเมน → คน](#14-เทคนิค-pivot-อีเมล--username--โดเมน--คน)
15. [สคริปต์รวมร่าง: สแกนอีเมลเดียวด้วยหลายเครื่องมือ](#15-สคริปต์รวมร่าง-สแกนอีเมลเดียวด้วยหลายเครื่องมือ)
16. [การจัดการผลลัพธ์ด้วย jq (merge/filter/report)](#16-การจัดการผลลัพธ์ด้วย-jq-mergefilterreport)
17. [Cheat Sheet — สรุปคำสั่งทั้งหมด](#17-cheat-sheet--สรุปคำสั่งทั้งหมด)
18. [ความเสี่ยงที่ยังเหลืออยู่ (Residual Risks)](#18-ความเสี่ยงที่ยังเหลืออยู่-residual-risks)

---

## 1. เตรียมเครื่อง Kali/WSL สำหรับติดตั้งเครื่องมือ (PEP 668)

Kali รุ่นใหม่ใช้ "externally-managed environment" — ติดตั้ง pip ตรง ๆ ทั้งระบบไม่ได้
ต้องใช้ **`pipx`** (แนะนำ), **`apt`**, หรือ **venv** วิธีที่สะอาดที่สุดคือ `pipx`

```bash
# 1) อัปเดตระบบ + ติดตั้งเครื่องมือพื้นฐาน
sudo apt update
sudo apt -y install pipx python3-pip python3-venv git curl jq dnsutils whois golang-go

# 2) เปิดใช้งาน pipx (เพิ่ม ~/.local/bin เข้า PATH)
pipx ensurepath

# 3) ปิด-เปิด shell ใหม่ หรือรีโหลด PATH
source ~/.bashrc
```

ตรวจสอบว่าพร้อม:

```bash
pipx --version
jq --version
curl --version | head -1
go version
```

> **ทางเลือก venv:** `python3 -m venv ~/osint && source ~/osint/bin/activate` แล้ว `pip install <tool>` ภายใน venv นั้น

### ติดตั้งเครื่องมือทั้งหมดในไฟล์นี้ (รวดเดียว)

```bash
# เครื่องมือ Python ผ่าน pipx (แยก environment อัตโนมัติ)
pipx install holehe
pipx install h8mail
pipx install socialscan
pipx install maigret
pipx install dnstwist

# theHarvester — ใช้แพ็กเกจของ Kali โดยตรง (เสถียรที่สุด)
sudo apt -y install theharvester

# Mosint — เครื่องมือ Go (ติดตั้งด้วย go install)
go install github.com/alpkeskin/mosint/v3/cmd/mosint@latest
# เพิ่ม GOPATH/bin เข้า PATH (ครั้งเดียว)
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc && source ~/.bashrc
```

> **ทางเลือก apt** (บาง Kali มีให้): `sudo apt install holehe h8mail dnstwist`

ตรวจว่าติดตั้งครบ:

```bash
for t in holehe h8mail socialscan maigret dnstwist theHarvester mosint; do
  command -v "$t" >/dev/null && echo "[OK]  $t" || echo "[MISS] $t"
done
```

---

## 2. ตารางเครื่องมือทั้งหมดในไฟล์นี้

| เครื่องมือ | input หลัก | ให้ผลอะไร | ต้องมี API key |
|---|---|---|---|
| **holehe** | อีเมล | เว็บ/บริการที่อีเมลนี้เคยสมัคร | ไม่ต้อง |
| **h8mail** | อีเมล | ข้อมูล breach/credential leak | ฟรีได้บางส่วน / เพิ่ม key ได้ |
| **socialscan** | อีเมล/username | อีเมล/username ว่างหรือถูกใช้แล้ว | ไม่ต้อง |
| **Mosint** | อีเมล | รวมศูนย์ (breach, social, dns, ...) | ต้องมี config+key |
| **theHarvester** | โดเมน | อีเมล/subdomain/host ของโดเมน | ฟรีได้บางแหล่ง |
| **maigret** | username | โปรไฟล์ข้ามแพลตฟอร์ม 3000+ ไซต์ | ไม่ต้อง |
| **crt.sh (curl)** | โดเมน | ใบรับรอง/ซับโดเมน (CT logs) | ไม่ต้อง |
| **Gravatar (curl)** | อีเมล | รูป/โปรไฟล์ที่ผูกกับ hash | ไม่ต้อง |
| **dig/DoH** | โดเมน | MX/SPF/DMARC/DKIM | ไม่ต้อง |
| **dnstwist** | โดเมน | โดเมนปลอม/ฟิชชิง | ไม่ต้อง |
| **EmailRep / HIBP / Hunter** | อีเมล/โดเมน | reputation/breach/pattern | **ต้องมี key** |

> 🔑 กติกา: เริ่มจากเครื่องมือ "ไม่ต้องมี key" ก่อน แล้วค่อยเสริมด้วยตัวที่ต้องมี key เมื่อจำเป็น

---

## 3. holehe — อีเมลถูกใช้สมัครเว็บใดบ้าง

holehe เช็กว่าอีเมลถูกใช้ลงทะเบียนบนเว็บ ~120 แห่งหรือไม่ (ผ่านฟีเจอร์ลืมรหัสผ่าน) **โดยไม่แจ้งเตือนเจ้าของบัญชี**

```bash
holehe someone@example.com                                    # พื้นฐาน
holehe --only-used someone@example.com                        # แสดงเฉพาะเว็บที่ "ใช้แล้ว"
holehe --no-clear --no-color --only-used someone@example.com  # ไม่ล้างจอ/ไม่ใส่สี (เก็บ log/ไพป์)
holehe --no-clear --no-color -C someone@example.com; ls -1 *.csv  # บันทึกเป็น CSV
holehe --only-used -T 15 someone@example.com                  # ตั้ง timeout ต่อคำขอ 15s
holehe --only-used a@example.com b@example.com c@example.com  # ตรวจหลายอีเมลรวดเดียว
```

**อ่านรายการอีเมลจากไฟล์แล้ววนตรวจ:**

```bash
# emails.txt: หนึ่งอีเมลต่อบรรทัด
while read -r EMAIL; do
  echo "==== $EMAIL ===="
  holehe --no-clear --no-color --only-used "$EMAIL"
done < emails.txt
```

> **การอ่านผล:** `[+]` = อีเมลถูกใช้บนเว็บนั้น, `[-]` = ไม่ถูกใช้, `[x]` = โดน rate limit (ลองใหม่ทีหลัง)

---

## 4. h8mail — ตรวจ data breach ของอีเมล

h8mail ค้นหาว่าอีเมลปรากฏใน data breach ใด (บางแหล่งใช้ฟรีได้ บางแหล่งต้องใส่ key)

**คำสั่งพื้นฐาน (ใช้แหล่งฟรีเริ่มต้น):**

```bash
h8mail -t someone@example.com
```

**ข้ามแหล่งฟรีเริ่มต้น (เมื่ออยากใช้เฉพาะ key ของตัวเอง):**

```bash
h8mail -t someone@example.com --skip-defaults
```

**ตรวจหลายอีเมลจากไฟล์:**

```bash
# targets.txt: หนึ่งอีเมลต่อบรรทัด
h8mail -t targets.txt
```

**บันทึกผลเป็น CSV และ JSON:**

```bash
h8mail -t someone@example.com -o result.csv
h8mail -t someone@example.com -j result.json
cat result.json | jq '.'
```

**สร้างไฟล์ config สำหรับใส่ API key (เพิ่มพลังค้น breach):**

```bash
# สร้างเทมเพลต config
h8mail --gen-config
ls -1 h8mail_config.ini

# แก้ไขไฟล์ ใส่ key ของบริการที่คุณสมัคร (เช่น HIBP, Hunter, Snusbase)
nano h8mail_config.ini

# เรียกใช้พร้อม config
h8mail -t someone@example.com -c h8mail_config.ini
```

**ใส่ API key แบบชั่วคราวผ่าน CLI (ไม่ต้องมีไฟล์ config):**

```bash
h8mail -t someone@example.com -k "hunterio=YOUR_HUNTER_KEY"
```

**โหมด "ไล่ล่า" (chase) — เอาอีเมลที่เจอไปค้นต่อ (ระวังขยายผลกว้าง):**

```bash
h8mail -t someone@example.com --chase 1 --power-chase
```

> **การอ่านผล:** ถ้าพบ `No results founds` แปลว่าแหล่งฟรีที่ใช้ไม่พบข้อมูล — ไม่ได้แปลว่าอีเมลปลอดภัย
> ควรยืนยันซ้ำด้วย HIBP (หัวข้อ 13)

---

## 5. socialscan — เช็กการมีอยู่ของอีเมล/username

socialscan บอกว่าอีเมล/username **ว่าง (available)** หรือ **ถูกใช้แล้ว (taken)** บนแพลตฟอร์มต่าง ๆ
(รวดเร็ว เพราะใช้ API ทางการของแต่ละเว็บ)

```bash
socialscan someone@example.com                       # ตรวจอีเมล (ตรวจจับรูปแบบอัตโนมัติ)
socialscan johndoe                                   # ตรวจ username
socialscan someone@example.com johndoe john.doe      # ตรวจอีเมล+username พร้อมกัน
socialscan someone@example.com -p github twitter instagram   # เฉพาะบางแพลตฟอร์ม
socialscan johndoe --available-only                  # แสดงเฉพาะที่ยังว่าง
socialscan someone@example.com --view-by query --show-urls   # จัดกลุ่มตาม query + แสดง URL
socialscan someone@example.com --cache-tokens        # cache token ลด request (กัน rate limit)
```

**อ่านรายการจากไฟล์ + ส่งออก JSON:**

```bash
# input.txt: อีเมล/username อย่างละบรรทัด
socialscan --input input.txt --json out.json
cat out.json | jq '.'
```

> **การอ่านผล:** `Taken/Reserved` = ถูกใช้แล้ว (มีบัญชี), `Available` = ว่าง, `Error` = โดน rate limit/บล็อก

---

## 6. Mosint — เครื่องมือรวมศูนย์ (Go)

Mosint รวมหลายฟังก์ชันในตัวเดียว (breach, social media, DNS, related emails ฯลฯ) เขียนด้วย Go เร็วมาก
**ต้องมีไฟล์ config พร้อม API key** จึงจะทำงานเต็มรูปแบบ

**ตรวจว่าติดตั้งได้:**

```bash
mosint --version
mosint --help
```

**สร้างไฟล์ config (`~/.mosint.yaml`):**

```bash
cat > ~/.mosint.yaml <<'YAML'
services:
  hunter: "YOUR_HUNTER_API_KEY"
  emailrep: "YOUR_EMAILREP_API_KEY"
  intelx: "YOUR_INTELX_API_KEY"
  ipinfo: "YOUR_IPINFO_TOKEN"
settings:
  scan_email_verification: true
  scan_social_media: true
  scan_related_emails: true
  scan_breach: true
  scan_dns_lookup: true
YAML
```

**รันสแกนอีเมล:**

```bash
mosint someone@example.com
```

**ระบุ config เอง + บันทึกผลเป็น JSON:**

```bash
mosint someone@example.com -c ~/.mosint.yaml -o result.json
cat result.json | jq '.'
```

**โหมดเงียบ (เขียนลงไฟล์อย่างเดียว):**

```bash
mosint someone@example.com -s -o result.json
```

> **หมายเหตุ:** ถ้ารันโดยไม่มี config Mosint จะเตือนให้สร้าง `~/.mosint.yaml` ก่อน
> คีย์ฟรีที่หาได้ง่าย: Hunter.io (free tier), IPinfo (free token)

---

## 7. theHarvester — เก็บข้อมูลจากโดเมนของอีเมล

เมื่อมีอีเมล `someone@example.com` โดเมน `example.com` คือจุดเริ่มที่ดี theHarvester เก็บ
**อีเมล / subdomain / host / IP** ของโดเมนจากเสิร์ชเอนจินและแหล่งสาธารณะ

**ดูวิธีใช้และรายชื่อแหล่ง (sources):**

```bash
theHarvester -h
```

แหล่ง (`-b`) ที่ใช้ได้ (บางส่วนที่ไม่ต้องมี key): `bing`, `duckduckgo`, `crtsh`,
`hackertarget`, `rapiddns`, `certspotter`, `dnsdumpster`, `otx`, `threatminer`, `urlscan`, `yahoo`, `anubis`

**คำสั่งพื้นฐาน — เก็บอีเมล/host ของโดเมนจาก Bing:**

```bash
theHarvester -d example.com -b bing -l 200
```

- `-d` = โดเมนเป้าหมาย, `-b` = แหล่งข้อมูล, `-l` = จำกัดจำนวนผลลัพธ์

**ใช้หลายแหล่งพร้อมกัน (คั่นด้วย comma) หรือทุกแหล่ง:**

```bash
theHarvester -d example.com -b bing,duckduckgo,crtsh,otx -l 500
# หรือทุกแหล่งที่ไม่ต้องใช้ key
theHarvester -d example.com -b all -l 500
```

**เปิด DNS resolution + brute-force ซับโดเมน:**

```bash
theHarvester -d example.com -b crtsh -c -r
```

- `-c` = DNS brute force, `-r` = resolve ซับโดเมนที่พบ

**บันทึกผลเป็นไฟล์ (จะได้ทั้ง XML และ JSON):**

```bash
theHarvester -d example.com -b bing,crtsh -l 300 -f example_report
ls -1 example_report.*        # example_report.json, example_report.xml
cat example_report.json | jq '.emails, .hosts' 2>/dev/null | head
```

**เงียบเสียงเตือน API key ที่ขาด:**

```bash
theHarvester -d example.com -b bing -l 200 -q
```

**ตรวจ subdomain takeover ระหว่างเก็บข้อมูล:**

```bash
theHarvester -d example.com -b crtsh -r -t
```

> **การอ่านผล:** ดูส่วน `[*] Emails found:` และ `[*] Hosts found:` — อีเมลที่พบอาจเป็น
> รูปแบบ (pattern) อีเมลขององค์กร ใช้ประเมิน footprint และตรวจสอบข้ามกับ holehe ได้

---

## 8. maigret — จาก local-part ของอีเมลสู่โปรไฟล์

maigret ค้นหา username ข้าม 3000+ ไซต์ เทคนิคคือ **ดึง local-part (ส่วนหน้า @) มาเป็น username**
แล้วค้นหา (คนจำนวนมากใช้ username เดียวกับส่วนหน้าอีเมล)

**แยก local-part จากอีเมล (bash):**

```bash
EMAIL="john.doe@example.com"
USERNAME="${EMAIL%@*}"       # ได้ john.doe
DOMAIN="${EMAIL#*@}"         # ได้ example.com
echo "username=$USERNAME domain=$DOMAIN"
```

```bash
maigret john.doe                                    # ค้นหาพื้นฐาน (ทุกไซต์)
maigret john.doe --top-sites 50 --timeout 10        # จำกัดไซต์ยอดนิยม (เร็วขึ้นมาก)
maigret john.doe --top-sites 100 --no-color         # ไม่ใส่สี (เก็บ log)
maigret john.doe --html                             # รายงาน HTML
maigret john.doe --pdf                              # รายงาน PDF
maigret john.doe --csv                              # ตาราง CSV
maigret john.doe -J simple                          # JSON แบบเรียบ
maigret john.doe --top-sites 100 --folderoutput ./maigret_reports   # กำหนดโฟลเดอร์เก็บผล
maigret john.doe --tags social,photo --top-sites 100   # เฉพาะไซต์บางแท็ก
maigret john.doe johndoe --permute                  # สลับหลาย username ที่คาดว่าคนเดียว
```

> **การอ่านผล:** บรรทัด `[+] <ไซต์>: <URL>` คือบัญชีที่พบ maigret จะดึงข้อมูลเสริม
> (ชื่อ, วันสร้างบัญชี, รูป) ให้ด้วยเมื่อทำได้ — **ต้อง verify เสมอ** เพราะ username อาจซ้ำกับคนอื่น

---

## 9. crt.sh + curl — สืบโดเมน/ซับโดเมนของอีเมล

Certificate Transparency (CT) logs เผยซับโดเมนทั้งหมดที่เคยออกใบรับรอง — เป็นวิธี **passive** ล้วน
ใช้ `curl` + `jq` ได้เลยโดยไม่ต้องติดตั้งเครื่องมือเพิ่ม

**ดึงรายชื่อ (ดิบ) ของใบรับรองในโดเมน:**

```bash
curl -s "https://crt.sh/?q=example.com&output=json" | jq -r '.[].name_value' | sort -u
```

**ดึงซับโดเมนทั้งหมด (ใช้ wildcard `%`) แล้วทำความสะอาด:**

```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u
```

**นับจำนวนซับโดเมนที่ไม่ซ้ำ:**

```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | wc -l
```

**บันทึกลงไฟล์เพื่อใช้ต่อ:**

```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > subdomains.txt
wc -l subdomains.txt
```

**ดูผู้ออกใบรับรอง (issuer) และวันหมดอายุ:**

```bash
curl -s "https://crt.sh/?q=example.com&output=json" \
  | jq -r '.[] | "\(.name_value)  |  \(.issuer_name)  |  \(.not_after)"' | head -20
```

**ฟังก์ชัน bash สำเร็จรูป (ใส่ใน `~/.bashrc` เพื่อเรียกซ้ำ):**

```bash
crtsub() { curl -s "https://crt.sh/?q=%25.$1&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u; }
# ใช้งาน:
crtsub example.com
```

---

## 10. Gravatar — จากอีเมลสู่รูป/โปรไฟล์

Gravatar ผูกรูปโปรไฟล์กับ **hash ของอีเมล** (ไม่ใช่อีเมลตรง ๆ) ถ้าอีเมลลงทะเบียน Gravatar ไว้
จะดึงรูป/โปรไฟล์สาธารณะได้

**สร้าง MD5 hash ของอีเมล (รูปแบบดั้งเดิม):**

```bash
echo -n "someone@example.com" | tr '[:upper:]' '[:lower:]' | md5sum | awk '{print $1}'
```

**สร้าง SHA256 hash (รูปแบบใหม่ที่ Gravatar แนะนำ):**

```bash
echo -n "someone@example.com" | tr '[:upper:]' '[:lower:]' | sha256sum | awk '{print $1}'
```

**เช็กว่าอีเมลนี้มี Gravatar หรือไม่ (`d=404` → HTTP 200 = มี, 404 = ไม่มี):**

```bash
H=$(echo -n "someone@example.com" | tr '[:upper:]' '[:lower:]' | md5sum | awk '{print $1}')
curl -s -o /dev/null -w "HTTP %{http_code}\n" "https://www.gravatar.com/avatar/$H?d=404"
```

**one-liner ด้วย Python (พิมพ์ URL รูปพร้อมใช้):**

```bash
python3 -c "import hashlib,sys; e=sys.argv[1].strip().lower(); print('https://www.gravatar.com/avatar/'+hashlib.md5(e.encode()).hexdigest()+'?d=404')" someone@example.com
```

**ดึงโปรไฟล์สาธารณะ (ถ้าตั้งเป็น public) เป็น JSON:**

```bash
H=$(echo -n "someone@example.com" | tr '[:upper:]' '[:lower:]' | md5sum | awk '{print $1}')
curl -s "https://www.gravatar.com/$H.json" | jq '.' 2>/dev/null || echo "ไม่มีโปรไฟล์สาธารณะ"
```

**ฟังก์ชัน bash สำเร็จรูป:**

```bash
grav() {
  local h; h=$(echo -n "$1" | tr '[:upper:]' '[:lower:]' | md5sum | awk '{print $1}')
  echo "avatar : https://www.gravatar.com/avatar/$h"
  echo "profile: https://www.gravatar.com/$h.json"
  curl -s -o /dev/null -w "exists : HTTP %{http_code} (200=มี / 404=ไม่มี)\n" "https://www.gravatar.com/avatar/$h?d=404"
}
grav someone@example.com
```

---

## 11. ตรวจสุขภาพอีเมลของโดเมน (MX/SPF/DMARC/DKIM)

จากโดเมนของอีเมล ตรวจ **การตั้งค่าความปลอดภัยอีเมล** ว่าองค์กรป้องกันการปลอมอีเมล (spoofing) ดีแค่ไหน
ต้องมี `dnsutils` (`sudo apt install dnsutils whois`)

**MX record (เซิร์ฟเวอร์รับเมลของโดเมน):**

```bash
dig +short MX example.com
```

**SPF (ใครส่งเมลแทนโดเมนนี้ได้บ้าง) — อยู่ใน TXT:**

```bash
dig +short TXT example.com | grep -i "v=spf1"
```

**DMARC (นโยบายจัดการเมลปลอม):**

```bash
dig +short TXT _dmarc.example.com
```

**DKIM (ตรวจ selector ที่พบบ่อย เช่น `default`, `google`, `selector1`):**

```bash
for s in default google selector1 selector2 k1 mail; do
  echo "== selector: $s =="
  dig +short TXT "$s._domainkey.example.com"
done
```

**WHOIS ของโดเมน (วันจดทะเบียน/ผู้จด/nameserver):**

```bash
whois example.com | grep -iE "Registrar:|Creation Date|Name Server|Registrant"
```

### ทางเลือกที่ทดสอบแล้ว: DNS over HTTPS (DoH) ผ่าน `curl`

ถ้า WSL แก้ DNS ตรง ๆ ไม่ได้ (เช่นบางเครือข่ายบล็อก UDP 53) ใช้ DoH ผ่าน HTTPS แทนได้ — **ทดสอบแล้วใช้ได้จริง**

```bash
# MX ผ่าน Google DoH
curl -s "https://dns.google/resolve?name=example.com&type=MX" | jq -r '.Answer[]?.data'

# SPF (TXT) ผ่าน Cloudflare DoH
curl -s -H 'accept: application/dns-json' \
  "https://cloudflare-dns.com/dns-query?name=example.com&type=TXT" \
  | jq -r '.Answer[]?.data' | grep -i spf1

# DMARC ผ่าน Google DoH
curl -s "https://dns.google/resolve?name=_dmarc.example.com&type=TXT" | jq -r '.Answer[]?.data'
```

> **จุดที่ควรแจ้งเตือน (เชิงป้องกัน):**
> - ไม่มี DMARC หรือ `p=none` → ปลอมอีเมลได้ง่าย
> - SPF ลงท้าย `~all` (softfail) หรือ `?all` (neutral) → อ่อนแอ
> - SPF `+all` → ใครส่งแทนก็ได้ (อันตรายมาก)

---

## 12. dnstwist — หาโดเมนปลอม/ฟิชชิงที่เลียนแบบ

dnstwist สร้างชื่อโดเมนที่ "เพี้ยน" จากโดเมนของอีเมล (typosquatting) เพื่อหาโดเมนฟิชชิงที่อาจปลอมเป็นองค์กร

**สร้างรายชื่อโดเมนที่เป็นไปได้ (generate อย่างเดียว — ทดสอบแล้ว):**

```bash
dnstwist -f list example.com
```

**เลือกอัลกอริทึมการกลายพันธุ์เฉพาะ (เร็วขึ้น):**

```bash
dnstwist -f list --fuzzers homoglyph,omission,insertion example.com
```

**ตรวจว่าโดเมนปลอมตัวไหน "จดทะเบียนแล้ว" (มีคนถือครอง):**

```bash
dnstwist -r example.com
```

**แสดงเฉพาะที่จดแล้ว + ตรวจ MX (โดเมนที่รับเมลได้ = เสี่ยงฟิชชิงเมล):**

```bash
dnstwist -r -m example.com
```

**บันทึกเป็น CSV/JSON:**

```bash
dnstwist -r --format csv example.com > twist.csv
dnstwist -r --format json example.com > twist.json
cat twist.json | jq '.[] | {domain: .domain, dns_a: .dns_a}' 2>/dev/null | head
```

**ปรับจำนวน thread + ใช้ DoH nameserver (กรณี DNS ตรงถูกบล็อก):**

```bash
dnstwist -r -t 4 --nameservers https://dns.google/dns-query example.com
```

> **หมายเหตุ:** โหมด `-r` ต้องใช้ DNS resolution จริง (อาจช้าถ้าเครือข่ายจำกัด) — บน Kali/WSL ปกติทำงานได้ดี
> ส่วน `-f list` ไม่แตะ DNS เลย ใช้ได้ทุกที่

---

## 13. เครื่องมือที่ต้องมี API Key (EmailRep / HIBP / Hunter)

> ⚠️ **ตามจริง (ทดสอบ 2026):** เวอร์ชันฟรีแบบไม่ต้องยืนยันตัวตนของ EmailRep และ HIBP
> **ถูกปิดแล้ว** ต้องสมัคร API key จึงจะใช้ได้ ด้านล่างคือรูปแบบคำสั่งที่ถูกต้องเมื่อมี key

### 13.1 Have I Been Pwned (HIBP) — มาตรฐานตรวจ breach

```bash
# ต้องมี HIBP API key (เสียเงิน) — ใส่ใน header hibp-api-key
HIBP_KEY="YOUR_HIBP_API_KEY"
curl -s -H "hibp-api-key: $HIBP_KEY" -H "user-agent: osint-lab" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/someone@example.com?truncateResponse=false" \
  | jq -r '.[] | "\(.Name)  (\(.BreachDate))  -  \(.Description[0:80])"'
```

**ตรวจว่ารหัสผ่านหลุดหรือไม่ (Pwned Passwords — ฟรี ไม่ต้อง key, ใช้ k-anonymity):**

```bash
# ส่งเฉพาะ 5 ตัวแรกของ SHA1 (ปลอดภัย ไม่เปิดเผยรหัสเต็ม)
PASS="P@ssw0rd"
HASH=$(printf '%s' "$PASS" | sha1sum | awk '{print toupper($1)}')
PREFIX=${HASH:0:5}; SUFFIX=${HASH:5}
curl -s "https://api.pwnedpasswords.com/range/$PREFIX" | grep -i "$SUFFIX" \
  && echo "[!] รหัสนี้เคยหลุด — ห้ามใช้" || echo "[OK] ไม่พบในชุดข้อมูลที่รู้จัก"
```

> คำสั่ง Pwned Passwords ด้านบนใช้ **k-anonymity** — ส่งแค่ 5 ตัวแรกของ hash เท่านั้น จึงปลอดภัยและ**ไม่ต้องมี key**

### 13.2 Hunter.io — หา pattern อีเมลของโดเมน (มี free tier)

```bash
HUNTER_KEY="YOUR_HUNTER_API_KEY"
# หา pattern และอีเมลของโดเมน
curl -s "https://api.hunter.io/v2/domain-search?domain=example.com&api_key=$HUNTER_KEY" \
  | jq '.data.pattern, .data.emails[]?.value'
# ตรวจความถูกต้องของอีเมลรายตัว
curl -s "https://api.hunter.io/v2/email-verifier?email=someone@example.com&api_key=$HUNTER_KEY" \
  | jq '.data | {status, result, score}'
```

### 13.3 EmailRep.io — reputation ของอีเมล (ต้องมี key แล้ว)

```bash
EMAILREP_KEY="YOUR_EMAILREP_API_KEY"
curl -s -H "Key: $EMAILREP_KEY" -H "User-Agent: osint-lab" \
  "https://emailrep.io/someone@example.com" \
  | jq '{email, reputation, suspicious, references, details}'
```

> **เก็บ key อย่างปลอดภัย:** ใช้ตัวแปรสภาพแวดล้อม อย่า hardcode ลงสคริปต์ที่ commit ขึ้น git
> ```bash
> echo 'export HIBP_KEY="xxxx"'    >> ~/.bashrc
> echo 'export HUNTER_KEY="xxxx"'  >> ~/.bashrc
> source ~/.bashrc
> ```

---

## 14. เทคนิค Pivot: อีเมล → username → โดเมน → คน

หัวใจของ OSINT ขั้นสูงคือ **การต่อจุด (pivoting)** — เอาผลจากขั้นหนึ่งไปป้อนขั้นถัดไป
โดยแตกอีเมลออกเป็น 3 เส้นทาง:

- **local-part** (`john.doe`) → `maigret`, `socialscan`, `holehe` → โปรไฟล์โซเชียล → ชื่อ/รูป/เมือง
- **โดเมน** (`example.com`) → `theHarvester`, `crt.sh`, `dig MX/SPF/DMARC`, `dnstwist` → อีเมลอื่น/pattern องค์กร
- **hash อีเมล** (md5/sha256) → `Gravatar` → รูป/โปรไฟล์

**ตัวอย่างลูกโซ่คำสั่ง (pivot ทีละขั้น):**

```bash
EMAIL="john.doe@example.com"
USER="${EMAIL%@*}"
DOM="${EMAIL#*@}"

# ขั้น 1: อีเมล → บัญชีที่ผูก
holehe --only-used "$EMAIL"

# ขั้น 2: local-part → โปรไฟล์โซเชียล
socialscan "$USER" --show-urls
maigret "$USER" --top-sites 50 --timeout 10

# ขั้น 3: โดเมน → footprint องค์กร
theHarvester -d "$DOM" -b bing,crtsh -l 300 -f "${DOM}_report"
crtsub "$DOM"                       # (ฟังก์ชันจากหัวข้อ 9)

# ขั้น 4: hash อีเมล → รูป/โปรไฟล์
grav "$EMAIL"                       # (ฟังก์ชันจากหัวข้อ 10)

# ขั้น 5: ตรวจความปลอดภัยอีเมลของโดเมน
dig +short MX "$DOM"
dig +short TXT "_dmarc.$DOM"
```

> **หลักการ verify:** ทุก pivot มีโอกาส false positive (username ซ้ำ, ข้อมูลเก่า)
> ยืนยันข้อมูลจากอย่างน้อย 2 แหล่งก่อนสรุป และแยก **confirmed** ออกจาก **candidate** เสมอ

---

## 15. สคริปต์รวมร่าง: สแกนอีเมลเดียวด้วยหลายเครื่องมือ

สคริปต์ด้านล่างรัน holehe + socialscan + maigret + Gravatar + crt.sh + DNS ในครั้งเดียว
เก็บผลลงโฟลเดอร์แยกตามอีเมล **(ใช้เฉพาะอีเมลที่คุณมีสิทธิ์ตรวจสอบ)**

```bash
#!/usr/bin/env bash
# email_osint.sh — passive email OSINT chain (Kali/WSL)
# ใช้งาน: ./email_osint.sh someone@example.com
set -euo pipefail

EMAIL="${1:?ใส่อีเมลเป็น argument: ./email_osint.sh someone@example.com}"
USER="${EMAIL%@*}"
DOM="${EMAIL#*@}"
OUT="osint_$(echo "$EMAIL" | tr '@.' '__')_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"
echo "[*] เป้าหมาย: $EMAIL  (user=$USER domain=$DOM)"
echo "[*] เก็บผลที่: $OUT/"

echo "[1/6] holehe (บัญชีที่ผูกกับอีเมล)..."
holehe --no-clear --no-color --only-used "$EMAIL" > "$OUT/holehe.txt" 2>&1 || true

echo "[2/6] socialscan (อีเมล/username)..."
socialscan "$EMAIL" "$USER" --show-urls > "$OUT/socialscan.txt" 2>&1 || true

echo "[3/6] maigret (โปรไฟล์จาก username)..."
maigret "$USER" --top-sites 50 --timeout 10 --no-color > "$OUT/maigret.txt" 2>&1 || true

echo "[4/6] Gravatar (รูป/โปรไฟล์)..."
H=$(echo -n "$EMAIL" | tr '[:upper:]' '[:lower:]' | md5sum | awk '{print $1}')
{
  echo "avatar : https://www.gravatar.com/avatar/$H"
  echo "profile: https://www.gravatar.com/$H.json"
  curl -s -o /dev/null -w "exists : HTTP %{http_code}\n" "https://www.gravatar.com/avatar/$H?d=404"
  curl -s "https://www.gravatar.com/$H.json"
} > "$OUT/gravatar.txt" 2>&1 || true

echo "[5/6] crt.sh (ซับโดเมนของโดเมน)..."
curl -s "https://crt.sh/?q=%25.$DOM&output=json" \
  | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > "$OUT/subdomains.txt" || true

echo "[6/6] DNS/email-security (DoH)..."
{
  echo "== MX =="
  curl -s "https://dns.google/resolve?name=$DOM&type=MX" | jq -r '.Answer[]?.data'
  echo "== SPF/TXT =="
  curl -s "https://dns.google/resolve?name=$DOM&type=TXT" | jq -r '.Answer[]?.data' | grep -i spf1 || echo "ไม่พบ SPF"
  echo "== DMARC =="
  curl -s "https://dns.google/resolve?name=_dmarc.$DOM&type=TXT" | jq -r '.Answer[]?.data' || echo "ไม่พบ DMARC"
} > "$OUT/dns.txt" 2>&1 || true

echo "[✓] เสร็จสิ้น — ดูผลได้ที่โฟลเดอร์ $OUT/"
ls -1 "$OUT"
```

**วิธีใช้:**

```bash
nano email_osint.sh      # วางเนื้อหาด้านบน
chmod +x email_osint.sh
./email_osint.sh someone@example.com
```

> สคริปต์นี้ใช้ **เฉพาะโมดูล passive** ที่ไม่ต้องมี API key ทั้งหมด และมี `|| true`
> เพื่อให้ทำงานต่อแม้บางขั้นล้มเหลว (เช่น rate limit)

---

## 16. การจัดการผลลัพธ์ด้วย jq (merge/filter/report)

**ดึงเฉพาะบัญชีที่ maigret พบ (จาก JSON):**

```bash
maigret john.doe --top-sites 100 -J simple --no-color
# ไฟล์ JSON จะอยู่ในโฟลเดอร์ reports/ — ตัวอย่างการอ่าน:
cat reports/report_john.doe_simple.json | jq -r 'to_entries[] | select(.value.status.status=="Claimed") | .key'
```

**รวมซับโดเมนจากหลายโดเมน + กรอง theHarvester JSON:**

```bash
# รวมซับโดเมนหลายโดเมน ตัดซ้ำ
for d in example.com example.org; do
  curl -s "https://crt.sh/?q=%25.$d&output=json" | jq -r '.[].name_value'
done | sed 's/\*\.//g' | sort -u > all_subdomains.txt

# กรอง theHarvester JSON เอาเฉพาะอีเมลและ host
jq -r '.emails[]?' report.json 2>/dev/null | sort -u
jq -r '.hosts[]?'  report.json 2>/dev/null | sort -u
```

**สร้างรายงาน Markdown สรุปจากไฟล์ผลลัพธ์:**

```bash
{
  echo "# Email OSINT Report — someone@example.com ($(date))"
  echo "## บัญชีที่พบ (holehe)"; echo '```'; grep '\[+\]' holehe.txt 2>/dev/null || echo "(ไม่มี)"; echo '```'
  echo "## ซับโดเมน (crt.sh)"; echo '```'; head -20 subdomains.txt 2>/dev/null; echo '```'
} > report.md
```

---

## 17. Cheat Sheet — สรุปคำสั่งทั้งหมด

```bash
# ===== ติดตั้ง (ครั้งเดียว) =====
sudo apt -y install pipx jq dnsutils whois golang-go theharvester
pipx ensurepath && source ~/.bashrc
pipx install holehe h8mail socialscan maigret dnstwist
go install github.com/alpkeskin/mosint/v3/cmd/mosint@latest

# ===== อีเมล → บัญชี/breach =====
holehe --only-used EMAIL                         # บัญชีที่ผูกกับอีเมล
h8mail -t EMAIL                                  # breach (แหล่งฟรี)
h8mail -t EMAIL -j out.json                      # breach → JSON
socialscan EMAIL USERNAME --show-urls            # อีเมล/username ว่างหรือถูกใช้
mosint EMAIL -o out.json                         # รวมศูนย์ (ต้องมี ~/.mosint.yaml)

# ===== local-part → โปรไฟล์ =====
USER="${EMAIL%@*}"
maigret "$USER" --top-sites 50 --timeout 10      # โปรไฟล์ข้ามแพลตฟอร์ม
maigret "$USER" --html                           # รายงาน HTML

# ===== โดเมน → footprint =====
DOM="${EMAIL#*@}"
theHarvester -d "$DOM" -b bing,crtsh,otx -l 300 -f rep   # อีเมล/host/subdomain
curl -s "https://crt.sh/?q=%25.$DOM&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
dnstwist -f list "$DOM"                           # โดเมนปลอม (generate)
dnstwist -r -m "$DOM"                             # โดเมนปลอมที่จดแล้ว + MX

# ===== hash อีเมล → รูป =====
H=$(echo -n "$EMAIL" | tr '[:upper:]' '[:lower:]' | md5sum | awk '{print $1}')
curl -s -o /dev/null -w "HTTP %{http_code}\n" "https://www.gravatar.com/avatar/$H?d=404"

# ===== ความปลอดภัยอีเมลของโดเมน (DoH — ใช้ได้แม้ DNS ตรงถูกบล็อก) =====
curl -s "https://dns.google/resolve?name=$DOM&type=MX" | jq -r '.Answer[]?.data'
curl -s "https://dns.google/resolve?name=$DOM&type=TXT" | jq -r '.Answer[]?.data' | grep -i spf1
curl -s "https://dns.google/resolve?name=_dmarc.$DOM&type=TXT" | jq -r '.Answer[]?.data'

# ===== ตรวจรหัสผ่านหลุด (ฟรี ไม่ต้อง key, k-anonymity) =====
HASH=$(printf '%s' 'PASSWORD' | sha1sum | awk '{print toupper($1)}')
curl -s "https://api.pwnedpasswords.com/range/${HASH:0:5}" | grep -i "${HASH:5}"
```

**ตารางแฟล็กสำคัญ:**

| เครื่องมือ | แฟล็กที่ใช้บ่อย |
|---|---|
| holehe | `--only-used` `--no-color` `-C` (csv) `-T` (timeout) |
| h8mail | `-t` (target) `-j`/`-o` (output) `-c` (config) `-k` (key) `--chase` |
| socialscan | `-p` (platforms) `-a` (available) `--json` `--show-urls` |
| maigret | `--top-sites` `--timeout` `--html` `--pdf` `--csv` `--tags` `--permute` |
| theHarvester | `-d` (domain) `-b` (source) `-l` (limit) `-f` (file) `-c` `-r` `-t` `-q` |
| dnstwist | `-f list` `-r` `-m` `--fuzzers` `--nameservers` `--format` |

---

## 18. ความเสี่ยงที่ยังเหลืออยู่ (Residual Risks)

> ไม่มีเครื่องมือใดปลอดภัยสมบูรณ์ — ต่อไปนี้คือความเสี่ยงที่ยังคงอยู่แม้ทำตามคู่มือ

1. **กฎหมาย/จริยธรรม** — ใช้กับบุคคลอื่นโดยไม่ได้รับอนุญาตอาจผิด PDPA/GDPR/พ.ร.บ.คอมพิวเตอร์ฯ และเข้าข่ายคุกคาม **ผู้ใช้รับผิดชอบเอง**
2. **False positive สูง** — โดยเฉพาะ maigret/socialscan (username ซ้ำ) และ holehe (ข้อมูลเก่า) ต้อง verify ทุกครั้ง อย่าสรุปจากผลดิบ
3. **การเปิดเผยตัวตนของคุณเอง** — บางคำสั่ง (theHarvester active, dnstwist `-r`, holehe) ติดต่อบริการจริง IP คุณอาจถูกบันทึก
4. **Rate limit / บล็อก** — รันบ่อยเกินไป IP โดนบล็อก ผลขาดหาย (`[x]`, `Error`) ใช้ `--timeout`, ลด parallelism, เว้นช่วง
5. **API key รั่วไหล** — อย่า hardcode key ในสคริปต์ที่ commit ขึ้น git ใช้ env var และใส่ไฟล์ config ลง `.gitignore`
6. **ผลลัพธ์คือ PII** — โฟลเดอร์รายงานมีข้อมูลส่วนบุคคล เก็บปลอดภัยและลบเมื่อจบงาน
7. **เครื่องมือเปลี่ยนตามเวลา** — เว็บเป้าหมายเปลี่ยน API บางโมดูลอาจใช้ไม่ได้ อัปเดตสม่ำเสมอ (`pipx upgrade-all`)

> **บทสรุป:** คู่มือนี้ให้ "วิธีการและคำสั่งที่ใช้ได้จริง" — ส่วนการใช้ **อย่างถูกกฎหมายและมีจริยธรรม**
> เป็นความรับผิดชอบของผู้ใช้ ตรวจเฉพาะอีเมลของตัวเองหรือเป้าหมายที่ได้รับอนุญาตเป็นลายลักษณ์อักษรเท่านั้น

---

### ภาคผนวก: บำรุงรักษาเครื่องมือ

```bash
pipx upgrade-all                                   # อัปเดตเครื่องมือ pipx ทั้งหมด
go install github.com/alpkeskin/mosint/v3/cmd/mosint@latest   # อัปเดต mosint
maigret --self-check                               # ตรวจสุขภาพฐานข้อมูลไซต์ของ maigret
```

> จบคู่มือภาคต่อ — สำหรับพื้นฐาน WSL/Kali/SpiderFoot ดูไฟล์แรก
> [`spiderfoot-email-osint-th.md`](./spiderfoot-email-osint-th.md)
