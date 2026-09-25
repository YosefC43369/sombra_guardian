# Photon Advanced Website Recon Field Manual (ภาษาไทย)

> คู่มือภาคปฏิบัติสำหรับ **Photon** (s0md3v/Photon) — เว็บครอว์เลอร์สาย OSINT/Recon
> ใช้สำหรับ Reconnaissance, Asset Inventory, Bug Bounty, Authorized Pentest, Red/Blue Team และการประเมินระบบของตนเอง
> ทุกคำสั่งในเอกสารนี้อ้างอิงจาก source (`photon.py`) และ wiki ของโปรเจกต์จริง
> เป้าหมาย/ตัวอย่างทั้งหมดใช้ `example.com`, `example.org`, `example.net` และ IP กลุ่ม TEST-NET (RFC 5737): `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`

---

## หมายเหตุความถูกต้อง (อ่านก่อนใช้งาน)

- Photon เป็น Open Source ที่ยังมีการแก้ไข syntax/flag ได้ตามเวอร์ชัน
- **ยืนยัน flag จริงเสมอด้วย** `python photon.py --help` ก่อนเชื่อเอกสารใด ๆ รวมถึงเอกสารนี้
- เมื่อ flag หรือชื่อไฟล์ output ต่างจากที่เขียนไว้ ให้ยึดตามเวอร์ชันที่ติดตั้งจริง — “Syntax หรือ Option อาจแตกต่างกันตามเวอร์ชันของ Photon”
- เอกสารนี้ **ไม่** สอน exploitation, WAF bypass, privilege escalation, หรือการเข้าถึงระบบโดยไม่ได้รับอนุญาต โดยเจตนา — Photon เป็นเครื่องมือเก็บข้อมูล ไม่ใช่เครื่องมือโจมตี

---

## ขอบเขตการใช้งานที่ถูกต้อง (Authorization Scope)

ใช้ Photon กับเป้าหมายต่อไปนี้เท่านั้น:

- โดเมน/แอปที่คุณเป็นเจ้าของ หรือดูแลในนามองค์กร
- โปรแกรม Bug Bounty ที่ระบุ scope ชัดเจนและอนุญาต automated crawling
- งาน Pentest ที่มี **written authorization / Rules of Engagement** เป็นลายลักษณ์อักษร
- ห้องแล็บของตนเอง (self-hosted lab)

ก่อนยิงเครื่องมือใส่เป้าหมายจริง ให้ตรวจสอบ:

```
[ ] มีสิทธิ์เป็นลายลักษณ์อักษร (scope, โดเมน, ช่วงเวลา, ความเข้มข้นที่อนุญาต)
[ ] เป้าหมายอยู่ใน scope (ไม่ครอว์ล subdomain/asset นอก scope)
[ ] เคารพ robots.txt / rate limit ตามข้อตกลง
[ ] มี point of contact กรณีเกิดผลกระทบต่อ production
[ ] เก็บ log การทำงานของตัวเองไว้เพื่อ audit
```

---

# สารบัญ

- Part I — Installation & Environment
- Part II — Installation Methods
- Part III — CLI Complete Reference
- Part IV — Basic Crawling
- Part V — Advanced Crawling
- Part VI — URL Discovery
- Part VII — JavaScript Recon
- Part VIII — API Recon
- Part IX — Web Technology / Asset Recon
- Part X — Hidden Resources Discovery
- Part XI — Output Files
- Part XII — JSON & Text Processing
- Part XIII — Linux Automation
- Part XIV — Docker
- Part XV — Python Integration
- Part XVI — Source Code Structure
- Part XVII — Performance Optimization
- Part XVIII — Large Website Recon
- Part XIX — Bug Bounty Recon Workflows
- Part XX — Corporate Website Recon
- Part XXI — Threat Intelligence Workflow
- Part XXII — Blue Team Workflow
- Part XXIII — Red Team Recon Workflow
- Part XXIV — Integration กับเครื่องมือ OSINT อื่น
- Part XXV — Kali Linux Toolkit
- Part XXVI — Case Studies
- Part XXVII — Troubleshooting
- Part XXVIII — Command Encyclopedia
- Part XXIX — Workflow Encyclopedia
- Part XXX — Quick Reference

---

# Part I — Installation & Environment

## Photon คืออะไร

Photon คือเว็บครอว์เลอร์เขียนด้วย Python ออกแบบมาเพื่อ **recon แบบเร็วและเก็บข้อมูลอย่างเป็นระเบียบ** เมื่อชี้ไปที่โดเมนหนึ่ง Photon จะไล่เก็บ:

- URL ภายใน (internal) และภายนอก (external)
- URL ที่มีพารามิเตอร์ (fuzzable — มี `?key=value`)
- ไฟล์ JavaScript และ endpoint ที่ฝังอยู่ใน JS
- ไฟล์ประเภทเอกสาร/สื่อ (pdf, xml, png ฯลฯ)
- ข้อมูล intel (อีเมล, โซเชียล, S3 bucket ฯลฯ)
- สตริงที่ตรงกับ regex ที่กำหนดเอง
- (ตัวเลือก) secret keys / high-entropy strings
- (ตัวเลือก) subdomain และข้อมูล DNS

จุดเด่นคือ **เบา เร็ว และ output เป็นไฟล์ข้อความที่ต่อท่อ (pipe) เข้ากับเครื่องมืออื่นได้ทันที** จึงเหมาะเป็น “ตัวเก็บ URL/endpoint” ต้นน้ำของ pipeline recon

## Photon Architecture

```
                +------------------------+
   seed URL --> |  Crawler Engine        |
                |  (requests + regex)    |
                +-----------+------------+
                            |
        +-------------------+-------------------+
        |                   |                   |
   URL Extractor      JS Extractor        Intel Extractor
        |                   |                   |
   internal/external   scripts/endpoints   intel (email,...)
        |                   |                   |
        +-------------------+-------------------+
                            |
                     Writer (text files)
                            |
                     Exporter plugin (json/csv)
```

องค์ประกอบหลัก:

- **Crawler Engine** — ดึงหน้าเว็บด้วย `requests`, ใช้ regex ดึงลิงก์/สตริง, จัดคิว URL ตามระดับความลึก (level)
- **Extractors** — แยกผลออกเป็นชุดข้อมูล (dataset) เช่น internal, external, fuzzable, scripts, intel
- **Plugins** — `wayback` (ดึง seed จาก archive.org), `dnsdumpster` (subdomain/DNS), `Exporter` (แปลงเป็น json/csv)
- **Writer** — เขียน dataset ลงไฟล์ `.txt` ในโฟลเดอร์ผลลัพธ์

## Photon Workflow (ภาพรวมการใช้งานจริง)

```
1. เตรียม environment (Python 3, venv, git clone)
2. ยืนยัน flag ด้วย --help
3. รัน crawl แบบเบา ๆ ก่อน (level ต่ำ, thread น้อย) เพื่อดูพฤติกรรมเว็บ
4. ปรับ level/threads/delay/exclude ให้เหมาะกับขนาดเว็บและข้อตกลง
5. เก็บผลเป็นโฟลเดอร์ + export json
6. ประมวลผลด้วย jq/grep/awk แล้วส่งต่อ httpx/katana/gau ฯลฯ
7. สรุปเป็น asset inventory / report
```

## Requirement

- Python 3.x (แนะนำ 3.8+)
- `pip` และ `git`
- แพ็กเกจ Python: `requests`, `tld` และอื่น ๆ ตาม `requirements.txt` ของ repo
- การเชื่อมต่ออินเทอร์เน็ตออกไปยังเป้าหมาย (และ archive.org หากใช้ `--wayback`)

## Python Environment

ตรวจสอบเวอร์ชัน Python:

```bash
python3 --version
pip3 --version
```

**NOTE:** Photon รันด้วย `python photon.py ...` จากภายในโฟลเดอร์ repo เป็นหลัก ไม่ใช่ binary ติดตั้งระบบ

## Kali Linux Preparation

Kali มี Python/git ครบอยู่แล้ว ตรวจ dependency พื้นฐาน:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git
```

**NOTE:** บางรุ่นของ Kali เคยรวมแพ็กเกจ `photon` ไว้ แต่ **อย่าเชื่อว่ามีเสมอ** — ตรวจด้วย `apt-cache search photon` หากไม่มีให้ใช้วิธี git clone (มาตรฐานของโปรเจกต์)

## Virtual Environment

แยก dependency ไม่ให้ชนกับระบบ:

```bash
python3 -m venv ~/venvs/photon
source ~/venvs/photon/bin/activate
```

ออกจาก venv:

```bash
deactivate
```

## Git Installation

```bash
sudo apt install -y git        # Debian/Kali/Ubuntu
sudo dnf install -y git        # Fedora
sudo pacman -S git             # Arch
```

## Update Photon

ภายในโฟลเดอร์ repo:

```bash
git pull
```

หรือใช้ flag ในตัว (ตามเวอร์ชัน):

```bash
python photon.py --update
```

**NOTE:** `--update` ตรวจและดึงอัปเดตจาก repo ต้นทาง หากคุณ clone แบบ shallow หรือแก้ไฟล์เอง อาจ conflict — กรณีนั้นใช้ `git pull` ตรง ๆ

## Verify Version

```bash
python photon.py --help
git -C . log -1 --oneline
```

**NOTE:** Photon ไม่ได้เน้น semantic version — ให้ดู commit ล่าสุด (`git log -1`) เป็นตัวระบุเวอร์ชันที่แม่นที่สุด

---

# Part II — Installation Methods

> ยึดหลัก: **ห้ามสร้างวิธีติดตั้งปลอม** ด้านล่างคือวิธีที่ใช้ได้จริง ส่วนวิธีที่โปรเจกต์ไม่ได้จัดให้อย่างเป็นทางการจะระบุไว้ตรง ๆ

## Git Clone (วิธีหลักที่แนะนำ)

```bash
git clone https://github.com/s0md3v/Photon.git
cd Photon
pip3 install -r requirements.txt
python photon.py --help
```

## Python Pip

**NOTE (สำคัญ):** โปรเจกต์ Photon ตัวนี้ **ไม่ได้เผยแพร่เป็นแพ็กเกจ pip ชื่อ `photon` อย่างเป็นทางการ** ชื่อ `photon` บน PyPI เป็นคนละโปรเจกต์ อย่า `pip install photon` แล้วคาดหวังว่าจะได้ตัวนี้ ให้ใช้ git clone แทน หากต้องการเรียกใช้สะดวก ให้ทำ wrapper เอง (ดู Part XIII)

## Pipx

ด้วยเหตุผลเดียวกับ pip — โปรเจกต์นี้ไม่ได้แพ็กเป็น console entry point ทางการสำหรับ pipx ให้ใช้ git clone เป็นหลัก

## Docker

repo มี `Dockerfile` จริง ใช้ได้ดังนี้:

```bash
git clone https://github.com/s0md3v/Photon.git
cd Photon
docker build -t photon .
docker run -it --rm photon -u example.com
```

**NOTE:** ทางเลือกดึง image สำเร็จรูปจาก registry ก็มีในบางช่วงเวลา แต่ตรวจ tag/ผู้เผยแพร่ให้ชัดก่อนใช้ อย่าเชื่อ image แปลกปลอม

## Kali / Ubuntu / Debian

- Kali/Ubuntu/Debian: ติดตั้ง dependency ระบบแล้ว git clone (เหมือน Part II หัวข้อแรก)
- อย่าใช้ชื่อแพ็กเกจ apt ที่ไม่ได้ตรวจสอบ — ยืนยันด้วย `apt-cache search photon` ก่อน

## Arch Linux

```bash
sudo pacman -S python python-pip git
git clone https://github.com/s0md3v/Photon.git
cd Photon && pip install -r requirements.txt
```

**NOTE:** หากมีใน AUR ให้ตรวจผู้ดูแลแพ็กเกจก่อน; วิธี git clone ปลอดภัยและคาดเดาได้กว่า

## Manual Installation

```bash
# ดาวน์โหลด zip แล้วแตกไฟล์
curl -L -o Photon.zip https://github.com/s0md3v/Photon/archive/refs/heads/master.zip
unzip Photon.zip
cd Photon-master
pip3 install -r requirements.txt
```

## Offline Installation

บนเครื่องที่มีเน็ต — ดาวน์โหลด wheel ล่วงหน้า:

```bash
mkdir photon_offline && cd photon_offline
git clone https://github.com/s0md3v/Photon.git
pip3 download -r Photon/requirements.txt -d ./wheels
```

ย้ายทั้งโฟลเดอร์ไปเครื่อง offline แล้ว:

```bash
pip3 install --no-index --find-links=./wheels -r Photon/requirements.txt
```

## Upgrade

```bash
cd Photon && git pull && pip3 install -r requirements.txt --upgrade
```

## Remove

```bash
# ถ้าใช้ git clone: ลบโฟลเดอร์ก็พอ
rm -rf ~/Photon
# ถ้าใช้ venv: ลบ venv
rm -rf ~/venvs/photon
# ถ้าใช้ docker:
docker rmi photon
```

---

# Part III — CLI Complete Reference

> ตารางอ้างอิงจาก argparse ใน `photon.py` ค่า default บางตัวถูกกำหนดจาก config ภายใน จึงอาจต่างตามเวอร์ชัน — ยืนยันด้วย `--help`

## ภาพรวม flag ทั้งหมด

| Short | Long | Argument | หน้าที่ |
|-------|------|----------|--------|
| `-u` | `--url` | root url | โดเมน/URL เริ่มต้นที่จะครอว์ล |
| `-l` | `--level` | int | ความลึกของการครอว์ล (recursion depth) |
| `-t` | `--threads` | int | จำนวน thread พร้อมกัน |
| `-d` | `--delay` | float | หน่วงเวลา (วินาที) ระหว่างแต่ละ request |
| `-c` | `--cookie` | string | Cookie header ที่แนบไปทุก request |
| `-r` | `--regex` | pattern | ดึงสตริงที่ตรง regex ระหว่างครอว์ล |
| `-s` | `--seeds` | urls | seed URL เพิ่มเติม (หลายค่า) |
| `-e` | `--export` | csv\|json | รูปแบบไฟล์ export |
| `-o` | `--output` | dir | โฟลเดอร์ผลลัพธ์ (default: ชื่อโดเมน) |
| `-v` | `--verbose` | — | แสดงผลละเอียดขณะทำงาน |
| `-p` | `--proxy` | IP:PORT | ส่ง request ผ่าน proxy |
| | `--stdout` | variable | พ่นชุดข้อมูลหนึ่งออก stdout เพื่อ pipe |
| | `--user-agent` | agents | กำหนด User-Agent เอง (หลายค่าได้) |
| | `--exclude` | regex | ไม่ครอว์ล URL ที่ตรง regex นี้ |
| | `--timeout` | float | timeout ต่อ request |
| | `--clone` | — | บันทึกหน้าเว็บลงเครื่อง (mirror) |
| | `--headers` | — | เพิ่ม HTTP headers (แบบกรอกเอง) |
| | `--dns` | — | เก็บ subdomain + DNS data |
| | `--keys` | — | ค้นหา secret keys / high-entropy strings |
| | `--only-urls` | — | ครอว์ลเก็บเฉพาะ URL ไม่ extract อย่างอื่น |
| | `--wayback` | — | ดึง URL จาก archive.org มาเป็น seed |
| | `--ninja` | — | (บางเวอร์ชัน) ส่ง request ผ่านบริการ proxy สาธารณะ |
| | `--update` | — | ตรวจ/ดึงอัปเดต Photon |

**NOTE:** `--ninja` และค่า default ตัวเลข (level/threads/timeout) พบความต่างระหว่างเวอร์ชัน — ยึด `--help` ของเครื่องคุณ

---

### `-u`, `--url`

- **Purpose:** ระบุ URL/โดเมนต้นทาง
- **Syntax:** `python photon.py -u <url>`
- **Example:**
  ```bash
  python photon.py -u https://example.com
  ```
- **Expected Output:** สร้างโฟลเดอร์ `example.com/` พร้อมไฟล์ dataset
- **Common Mistakes:** ลืมใส่ scheme (`http/https`); ใส่ path ลึกทำให้ scope แคบเกินตั้งใจ
- **Notes:** ใส่ scheme ให้ชัดเพื่อลดการเดา redirect

### `-l`, `--level`

- **Purpose:** กำหนดความลึกการครอว์ล (ยิ่งมากยิ่งไปไกลจาก seed)
- **Syntax:** `-l <int>`
- **Example:**
  ```bash
  python photon.py -u https://example.com -l 3
  ```
- **Expected Output:** จำนวน URL ที่เก็บได้เพิ่มตาม level
- **Common Mistakes:** ตั้ง level สูงกับเว็บใหญ่ → ครอว์ลนาน/โหลดหนัก
- **Notes:** เริ่มที่ 2 แล้วค่อยเพิ่ม

### `-t`, `--threads`

- **Purpose:** จำนวน request พร้อมกัน
- **Syntax:** `-t <int>`
- **Example:**
  ```bash
  python photon.py -u https://example.com -t 10
  ```
- **Common Mistakes:** thread สูงเกินทำให้โดน rate-limit/บล็อก หรือกระทบ production
- **Notes:** ปรับคู่กับ `-d` เสมอ

### `-d`, `--delay`

- **Purpose:** หน่วงเวลาระหว่าง request (ลดภาระเป้าหมาย)
- **Syntax:** `-d <float>`
- **Example:**
  ```bash
  python photon.py -u https://example.com -t 5 -d 0.5
  ```
- **Notes:** ใช้ตามข้อตกลง rate limit

### `-c`, `--cookie`

- **Purpose:** แนบ Cookie (เช่น session ที่ได้รับอนุญาตให้ทดสอบพื้นที่ authenticated)
- **Syntax:** `-c "name=value; name2=value2"`
- **Example:**
  ```bash
  python photon.py -u https://example.com -c "session=REDACTED"
  ```
- **Notes:** อย่า commit cookie จริงลง repo/log

### `-r`, `--regex`

- **Purpose:** ดึงสตริงที่ตรง pattern (เช่น รูปแบบ endpoint, id)
- **Syntax:** `-r '<regex>'`
- **Example:**
  ```bash
  python photon.py -u https://example.com -r '/api/v[0-9]+/[a-z]+'
  ```
- **Expected Output:** ผลไปอยู่ใน `custom.txt`
- **Notes:** ครอบ regex ด้วย single quote กัน shell ตีความ

### `-s`, `--seeds`

- **Purpose:** เพิ่ม seed URL นอกเหนือจาก root
- **Syntax:** `-s <url1> <url2>`
- **Example:**
  ```bash
  python photon.py -u https://example.com -s https://example.com/app https://example.com/docs
  ```
- **Notes:** ช่วยเจาะส่วนที่ลิงก์ไม่ถึงจากหน้าแรก

### `-e`, `--export`

- **Purpose:** export ผลรวมเป็น json หรือ csv
- **Syntax:** `-e json` | `-e csv`
- **Example:**
  ```bash
  python photon.py -u https://example.com -e json
  ```
- **Expected Output:** ไฟล์ export (เช่น `exported.json`) ในโฟลเดอร์ผลลัพธ์
- **Notes:** json เหมาะกับ jq pipeline

### `-o`, `--output`

- **Purpose:** กำหนดโฟลเดอร์ผลลัพธ์เอง
- **Syntax:** `-o <dir>`
- **Example:**
  ```bash
  python photon.py -u https://example.com -o recon/example_2025
  ```
- **Notes:** ตั้งชื่อโฟลเดอร์ให้มีวันที่ ช่วยเทียบผลข้ามรอบ

### `-v`, `--verbose`

- **Purpose:** แสดงสิ่งที่พบแบบ realtime
- **Example:**
  ```bash
  python photon.py -u https://example.com -v
  ```
- **Notes:** ใช้ตอน debug; เวลา automate ให้ปิดเพื่อ log สะอาด

### `-p`, `--proxy`

- **Purpose:** ส่ง traffic ผ่าน proxy (เช่น เพื่อ log/inspect ในแล็บของตน)
- **Syntax:** `-p <IP:PORT>`
- **Example:**
  ```bash
  python photon.py -u https://example.com -p 127.0.0.1:8080
  ```
- **Notes:** รองรับ proxy ต่างกันตามเวอร์ชัน — ตรวจ `--help`

### `--stdout`

- **Purpose:** พ่นชุดข้อมูลหนึ่งออก stdout เพื่อ pipe ต่อ
- **Syntax:** `--stdout <dataset>` (เช่น internal, external, fuzzable)
- **Example:**
  ```bash
  python photon.py -u https://example.com --stdout internal | httpx -silent
  ```
- **Notes:** ชื่อ dataset ที่ pipe ได้ขึ้นกับเวอร์ชัน — ยืนยันด้วย `--help`

### `--user-agent`

- **Purpose:** กำหนด UA เอง (เลี่ยง UA เริ่มต้นที่บาง WAF บล็อก — เพื่อการทดสอบที่ได้รับอนุญาต)
- **Syntax:** `--user-agent "<UA string>"`
- **Example:**
  ```bash
  python photon.py -u https://example.com --user-agent "Mozilla/5.0 (Recon; +authorized-test)"
  ```

### `--exclude`

- **Purpose:** ไม่ครอว์ล URL ที่ตรง regex (กัน logout, กัน endpoint ที่เปลี่ยน state)
- **Syntax:** `--exclude '<regex>'`
- **Example:**
  ```bash
  python photon.py -u https://example.com --exclude '(logout|signout|delete)'
  ```
- **Notes:** สำคัญมากใน authorized test — กันไปกดปุ่มทำลาย state

### `--timeout`

- **Purpose:** timeout ต่อ request
- **Syntax:** `--timeout <float>`
- **Example:**
  ```bash
  python photon.py -u https://example.com --timeout 10
  ```

### `--clone`

- **Purpose:** บันทึกหน้าเว็บลงเครื่อง (mirror) เพื่อวิเคราะห์ offline
- **Example:**
  ```bash
  python photon.py -u https://example.com --clone
  ```
- **Notes:** ใช้พื้นที่ดิสก์เพิ่ม; เหมาะกับการเก็บหลักฐาน asset ณ เวลาหนึ่ง

### `--headers`

- **Purpose:** เพิ่ม HTTP headers เอง (แบบกรอก)
- **Example:**
  ```bash
  python photon.py -u https://example.com --headers
  ```
- **Notes:** ใช้แนบ Authorization/custom header ที่ได้รับอนุญาต

### `--dns`

- **Purpose:** เก็บ subdomain และข้อมูล DNS (ผ่าน plugin dnsdumpster)
- **Example:**
  ```bash
  python photon.py -u https://example.com --dns
  ```
- **Expected Output:** `subdomains.txt` และไฟล์ map DNS
- **Notes:** ผลขึ้นกับบริการภายนอก — อาจว่างถ้าบริการเปลี่ยน

### `--keys`

- **Purpose:** ค้นหา high-entropy strings / secret keys ที่หลุดในหน้าเว็บ/JS
- **Example:**
  ```bash
  python photon.py -u https://example.com --keys
  ```
- **Expected Output:** `keys.txt`
- **Notes:** มี false positive สูง — ต้องตรวจด้วยมือ และรายงานอย่างมีความรับผิดชอบหากพบ secret จริง (สำหรับระบบที่คุณมีสิทธิ์)

### `--only-urls`

- **Purpose:** เก็บเฉพาะ URL เร็ว ๆ ไม่ extract อย่างอื่น
- **Example:**
  ```bash
  python photon.py -u https://example.com --only-urls
  ```

### `--wayback`

- **Purpose:** ดึง URL เก่าจาก archive.org มาเป็น seed (เจอ endpoint เก่า/ที่ถูกลบลิงก์)
- **Example:**
  ```bash
  python photon.py -u https://example.com --wayback
  ```

### `--ninja` (เฉพาะบางเวอร์ชัน)

- **Purpose:** กระจาย request ผ่านบริการ proxy สาธารณะ
- **Notes:** อาจไม่มีในทุกเวอร์ชัน และพึ่งบริการภายนอกที่ไม่เสถียร — ตรวจ `--help`

### `--update`

- **Purpose:** ตรวจและดึงอัปเดต
- **Example:**
  ```bash
  python photon.py --update
  ```

---

# Part IV — Basic Crawling

## Crawl Website (คำสั่งพื้นฐานสุด)

```bash
python photon.py -u https://example.com
```

**OUTPUT:** โฟลเดอร์ `example.com/` พร้อม `internal.txt`, `external.txt`, `fuzzable.txt`, `scripts.txt`, `intel.txt` ฯลฯ

## Depth (ความลึก)

```bash
python photon.py -u https://example.com -l 2
python photon.py -u https://example.com -l 4
```

**NOTE:** level เพิ่ม → coverage เพิ่ม แต่เวลาและภาระเพิ่มแบบทวีคูณ

## URL Limit (จำกัดผ่านความลึก/เวลา)

Photon ไม่มี flag “จำนวน URL สูงสุด” ตายตัว การควบคุมปริมาณทำผ่าน `-l` (ลด depth), `--exclude` (ตัดกิ่ง) และเวลา/`-d`

```bash
python photon.py -u https://example.com -l 2 --exclude '(/tag/|/page/|/category/)'
```

## Timeout

```bash
python photon.py -u https://example.com --timeout 8
```

## Threads

```bash
python photon.py -u https://example.com -t 8
```

## Delay

```bash
python photon.py -u https://example.com -t 8 -d 0.3
```

## Cookies

```bash
python photon.py -u https://example.com -c "session=REDACTED; csrftoken=REDACTED"
```

## Headers

```bash
python photon.py -u https://example.com --headers
# จากนั้นกรอก header เช่น: Authorization: Bearer REDACTED
```

## User-Agent

```bash
python photon.py -u https://example.com --user-agent "Mozilla/5.0 (X11; Linux x86_64) recon"
```

## Robots

Photon อ่าน `robots.txt` และเก็บ path ที่พบไว้ใน `robots.txt` (ไฟล์ผลลัพธ์) การเคารพ robots ให้ยึดตามข้อตกลง engagement

```bash
python photon.py -u https://example.com
cat example.com/robots.txt
```

## Sitemap

seed ด้วย sitemap เพื่อ coverage กว้างขึ้น:

```bash
python photon.py -u https://example.com -s https://example.com/sitemap.xml
```

## Seed URLs

```bash
python photon.py -u https://example.com \
  -s https://example.com/app \
     https://example.com/dashboard \
     https://example.com/api
```

---

# Part V — Advanced Crawling

## Deep Crawl

```bash
python photon.py -u https://example.com -l 5 -t 10 -d 0.2 --timeout 10
```

## Recursive Crawl

ค่าที่ควบคุม recursion คือ `-l` โดยตรง — ยิ่งสูงยิ่งไล่ลิงก์ต่อลิงก์ลึกขึ้น

```bash
python photon.py -u https://example.com -l 6 --exclude '(/static/|/assets/|\.png|\.jpg)'
```

## Crawl Optimization

หลักการ: **ตัดกิ่งที่ไม่ให้ค่า** ก่อน แล้วค่อยเพิ่ม depth

```bash
python photon.py -u https://example.com -l 4 -t 12 -d 0.1 \
  --exclude '(/tag/|/page/[0-9]+|/wp-content/uploads/)'
```

## Crawl Filtering (post-crawl)

Photon เก็บทุกอย่างก่อน แล้วเรากรองทีหลังจากไฟล์:

```bash
grep -E '/api/' example.com/internal.txt | sort -u > api_urls.txt
```

## Extension Filtering

```bash
grep -Ei '\.(js|json|xml|map)(\?|$)' example.com/internal.txt | sort -u
```

## URL Filtering

```bash
grep -E 'example\.com' example.com/internal.txt | sort -u
```

## Regex Filtering (ระหว่างครอว์ล)

```bash
python photon.py -u https://example.com -r '/(api|graphql|internal)/[a-zA-Z0-9_/-]+'
cat example.com/custom.txt
```

## Parameter Filtering

ดึงเฉพาะ URL ที่มีพารามิเตอร์ (มาจาก `fuzzable.txt`):

```bash
cat example.com/fuzzable.txt | sort -u
grep -oE '\?.*' example.com/fuzzable.txt | tr '&' '\n' | grep -oE '^[^=]+' | sort -u
```

## API Endpoint Filtering

```bash
grep -Ei '(/api/|/v[0-9]+/|graphql|\.json)' example.com/internal.txt example.com/endpoints.txt | sort -u
```

## External Resource Filtering

```bash
sort -u example.com/external.txt
awk -F/ '{print $3}' example.com/external.txt | sort | uniq -c | sort -rn
```

## JavaScript Filtering

```bash
sort -u example.com/scripts.txt
grep -Ei '(chunk|bundle|app|main|vendor)' example.com/scripts.txt
```

## Asset Filtering

```bash
grep -Ei '\.(png|jpg|jpeg|svg|gif|woff2?|ttf|pdf)(\?|$)' example.com/internal.txt | sort -u
```

---

# Part VI — URL Discovery

## Workflow

```
example.com
     |
     v
   Photon  ──► internal.txt / external.txt / fuzzable.txt / endpoints.txt
     |
     v
  Filter URLs (grep/awk/jq)
     |
     v
  Categorize (api / static / param / js / media)
     |
     v
  Prioritize (param+api ก่อน → static ทีหลัง)
```

## ประเภท URL และวิธีดึง

- **Dynamic URL** — มักอยู่ใน `fuzzable.txt` (มี `?param=`)
  ```bash
  sort -u example.com/fuzzable.txt
  ```
- **Static URL** — ไฟล์นิ่ง (asset)
  ```bash
  grep -Ei '\.(css|js|png|jpg|svg|woff2?)$' example.com/internal.txt | sort -u
  ```
- **Parameter URL** — สกัดชื่อพารามิเตอร์เพื่อทำ wordlist ของตัวเอง
  ```bash
  grep -oE '[?&][a-zA-Z0-9_]+=' example.com/fuzzable.txt | tr -d '?&=' | sort -u
  ```
- **API URL**
  ```bash
  grep -Ei '(/api/|/v[0-9]+/|graphql)' example.com/*.txt | sort -u
  ```
- **JS URL**
  ```bash
  sort -u example.com/scripts.txt
  ```
- **CDN URL**
  ```bash
  grep -Ei '(cdn|cloudfront|akamai|fastly|jsdelivr|unpkg)' example.com/external.txt | sort -u
  ```
- **Media URL**
  ```bash
  grep -Ei '\.(mp4|mp3|webm|pdf|zip)$' example.com/internal.txt | sort -u
  ```
- **Hidden URL** — จาก `--wayback` + endpoints ใน JS (ดู Part VII, X)

## รวม URL จากหลายแหล่งแล้ว dedupe

```bash
cat example.com/internal.txt example.com/endpoints.txt example.com/fuzzable.txt \
  | sort -u > example_all_urls.txt
wc -l example_all_urls.txt
```

---

# Part VII — JavaScript Recon

> JS คือขุมทรัพย์ของ endpoint/route/parameter ที่ไม่โผล่ใน HTML ปกติ Photon เก็บ URL ของไฟล์ JS (`scripts.txt`) และ endpoint ที่ดึงได้ (`endpoints.txt`)

## JS Collection

```bash
python photon.py -u https://example.com -l 3
sort -u example.com/scripts.txt
```

## JS Crawling (seed ด้วยไฟล์ JS ตรง ๆ)

```bash
python photon.py -u https://example.com/static/js/app.js -l 2
```

## JS Parsing / Endpoint Discovery

Photon ดึง endpoint ที่ฝังใน JS ให้อัตโนมัติ:

```bash
sort -u example.com/endpoints.txt
```

เสริมด้วยการดาวน์โหลด JS มาวิเคราะห์เอง:

```bash
mkdir -p js && cd js
while read -r u; do
  fn=$(echo "$u" | md5sum | cut -d' ' -f1).js
  curl -s "$u" -o "$fn"
done < ../example.com/scripts.txt
```

ค้น path/endpoint ในไฟล์ JS ที่โหลดมา:

```bash
grep -ohrE '"/[a-zA-Z0-9_/.-]+"' js/ | tr -d '"' | sort -u
grep -ohrE '(/api/|/v[0-9]+/|graphql)[a-zA-Z0-9_/.-]*' js/ | sort -u
```

## Secret Pattern Discovery (ในขอบเขตที่ได้รับอนุญาต)

```bash
python photon.py -u https://example.com --keys
cat example.com/keys.txt
```

ตรวจเพิ่มในไฟล์ JS ที่โหลดมา (คำที่บ่งชี้ config):

```bash
grep -inE '(api[_-]?key|secret|token|bearer|aws|firebase|clientId)' js/ | sort -u
```

**NOTE:** ผลลัพธ์เหล่านี้ต้องตรวจด้วยมือ ส่วนใหญ่เป็น public key/false positive หากพบ secret จริงของระบบที่คุณมีสิทธิ์ ให้ดำเนินการตามกระบวนการ responsible disclosure

## API Endpoint Discovery จาก JS

```bash
grep -ohrE '/(api|graphql|rest|internal)/[a-zA-Z0-9_/.-]+' js/ | sort -u > js_api_endpoints.txt
```

## Route Discovery (SPA)

```bash
grep -ohrE 'path:\s*["'\''][^"'\'']+' js/ | sed -E 's/.*["'\'']//' | sort -u
grep -ohrE '(component|route|lazy)\(' js/ | sort -u
```

## Source Map Discovery

```bash
grep -rlE 'sourceMappingURL' js/
grep -ohrE 'sourceMappingURL=[^ ]+' js/ | sort -u
# ถ้าอนุญาตและมีไฟล์ .map ให้ดึงมาช่วยอ่านโครงสร้าง
grep -oE 'https?://[^ "]+\.map' example.com/*.txt | sort -u
```

## Lazy-loaded JS / Chunk / Bundle Files

```bash
grep -Ei '(chunk|bundle|vendor|runtime|main|polyfill)[^/]*\.js' example.com/scripts.txt | sort -u
```

## ตัวอย่างแผนผัง JS recon

```
example.com
   |
   +-- /static/js/app.js ──► endpoints.txt (/api/v1/users, /api/v1/orders)
   |
   +-- /static/js/vendor.chunk.js ──► third-party SDK, analytics keys
   |
   +-- sourceMappingURL ──► app.js.map (ถ้าเข้าถึงได้/ได้รับอนุญาต)
```

---

# Part VIII — API Recon

## REST Endpoint Discovery

```bash
grep -Ei '(/api/|/v[0-9]+/)' example.com/internal.txt example.com/endpoints.txt | sort -u
```

## GraphQL Endpoint Discovery

```bash
grep -Ei 'graphql' example.com/*.txt | sort -u
```

**NOTE:** เอกสารนี้ครอบเฉพาะการ **ค้นพบ** endpoint เท่านั้น ไม่รวมการยิง introspection/มuta เพื่อโจมตี

## Swagger / OpenAPI Discovery

```bash
grep -Ei '(swagger|openapi|api-docs|redoc)' example.com/*.txt | sort -u
# path ยอดฮิตที่ควรลองยืนยันด้วยมือ (ในระบบที่มีสิทธิ์)
for p in /swagger.json /openapi.json /v3/api-docs /swagger-ui.html; do
  echo "check: https://example.com$p"
done
```

## JSON Endpoint Discovery

```bash
grep -Ei '\.json(\?|$)' example.com/internal.txt example.com/endpoints.txt | sort -u
```

## API Documentation Discovery

```bash
grep -Ei '(docs|documentation|developer|api-reference)' example.com/internal.txt | sort -u
```

## จัดหมวดผล API

```bash
grep -Ei '(/api/|/v[0-9]+/|graphql)' example.com/*.txt \
  | sort -u \
  | awk -F/ '{print $4"/"$5}' \
  | sort | uniq -c | sort -rn
```

---

# Part IX — Web Technology / Asset Recon

Photon เก็บลิงก์ asset ทุกชนิดไว้ในไฟล์ผลลัพธ์ นำมาแยกหมวดได้:

## HTML / CSS / JS

```bash
grep -Ei '\.css(\?|$)'  example.com/internal.txt | sort -u
grep -Ei '\.js(\?|$)'   example.com/scripts.txt example.com/internal.txt | sort -u
```

## Images / Fonts

```bash
grep -Ei '\.(png|jpe?g|gif|svg|webp)(\?|$)' example.com/internal.txt | sort -u
grep -Ei '\.(woff2?|ttf|eot|otf)(\?|$)'     example.com/internal.txt | sort -u
```

## เอกสาร (PDF / XML)

```bash
grep -Ei '\.(pdf|xml|csv|xlsx?|docx?)(\?|$)' example.com/*.txt | sort -u
```

## robots / sitemap / RSS / manifest

```bash
cat example.com/robots.txt
grep -Ei 'sitemap' example.com/*.txt | sort -u
grep -Ei '(rss|feed|atom)' example.com/internal.txt | sort -u
grep -Ei '(manifest\.json|manifest\.webmanifest)' example.com/*.txt | sort -u
```

## Web Technology Discovery (เสริมด้วยเครื่องมืออื่น)

Photon ไม่ได้ fingerprint เทคโนโลยีโดยตรง ให้ต่อกับเครื่องมือเฉพาะทาง:

```bash
# ตัวอย่าง: ส่ง host เข้าเครื่องมือ fingerprint ที่คุณมี
awk -F/ '{print $1"//"$3}' example.com/internal.txt | sort -u > hosts.txt
# แล้วใช้ whatweb/httpx (ดู Part XXIV/XXV)
```

## Asset Inventory (สรุปทรัพย์สิน)

```bash
{
  echo "== hosts =="; awk -F/ '{print $3}' example.com/internal.txt example.com/external.txt | sort -u
  echo "== js =="; wc -l < example.com/scripts.txt
  echo "== params =="; wc -l < example.com/fuzzable.txt
} | tee example_asset_inventory.txt
```

---

# Part X — Hidden Resources Discovery

## Workflow

```
Crawl ──► JS ──► Assets ──► Hidden Files ──► Interesting Files
```

## ไฟล์ที่ควรมองหา (แล้วตรวจในระบบที่มีสิทธิ์)

```bash
grep -Ei '\.(json|xml|bak|old|txt|map|env|config|yml|yaml|ini|sql|zip|tar\.gz)(\?|$)' \
  example.com/internal.txt example.com/endpoints.txt example.com/files.txt | sort -u
```

ตัวอย่างชื่อไฟล์น่าสนใจ:

```
config.js
swagger.json
.env.example
app.js.map
backup.zip
sitemap.xml
robots.txt
```

## รวม hidden candidates จาก wayback

```bash
python photon.py -u https://example.com --wayback -l 2
grep -Ei '\.(json|xml|bak|old|map|env|config)(\?|$)' example.com/*.txt | sort -u
```

## แนวทางตรวจสอบ (เชิงป้องกัน/ที่ได้รับอนุญาต)

- ยืนยันว่าไฟล์ **ไม่ควร** เข้าถึงได้จากภายนอก (เช่น `.env`, `.sql`, backup)
- หากพบว่า public → บันทึกเป็น finding เพื่อแจ้งเจ้าของระบบ/ทีม (responsible disclosure)
- **ห้าม** ดาวน์โหลด/เผยแพร่ข้อมูลลับของระบบที่ไม่ได้เป็นเจ้าของ

---

# Part XI — Output Files

โฟลเดอร์ผลลัพธ์ (default = ชื่อโฮสต์) มีไฟล์ dataset ต่อไปนี้ (ชื่ออาจต่างตามเวอร์ชัน — ดูของจริงด้วย `ls`):

| ไฟล์ | เนื้อหา |
|------|--------|
| `internal.txt` | URL ภายในโดเมนเป้าหมาย |
| `external.txt` | URL ภายนอก (โดเมนอื่น/third-party) |
| `fuzzable.txt` | URL ที่มีพารามิเตอร์ (พร้อมนำไป map surface) |
| `endpoints.txt` | endpoint ที่ดึงได้จาก JS |
| `scripts.txt` | URL ของไฟล์ JavaScript |
| `intel.txt` | ข้อมูล intel (email, social, S3 ฯลฯ) |
| `files.txt` | ไฟล์เอกสาร/สื่อที่พบ (pdf, xml ฯลฯ) |
| `robots.txt` | path ที่พบใน robots ของเป้าหมาย |
| `custom.txt` | ผลจาก `-r/--regex` |
| `keys.txt` | ผลจาก `--keys` (high-entropy strings) |
| `failed.txt` | URL ที่ร้องขอไม่สำเร็จ |
| `subdomains.txt` | subdomain จาก `--dns` |
| `exported.json` / `exported.csv` | ผลรวมจาก `-e json|csv` |

**NOTE:** ถ้าเวอร์ชันของคุณตั้งชื่อไฟล์ต่างออกไป ให้ยึดชื่อจริง — ตรวจด้วย:

```bash
ls -1 example.com/
```

## สำหรับแต่ละไฟล์

### `internal.txt`
- **Purpose:** รายการ URL ภายใน — แกนหลักของ recon
- **Format:** หนึ่ง URL ต่อบรรทัด
- **Process:**
  ```bash
  sort -u example.com/internal.txt | wc -l
  ```

### `external.txt`
- **Purpose:** ระบุ third-party / dependency ภายนอก
- **Process:**
  ```bash
  awk -F/ '{print $3}' example.com/external.txt | sort | uniq -c | sort -rn
  ```

### `fuzzable.txt`
- **Purpose:** URL มีพารามิเตอร์ → surface สำหรับ map input (ในงานที่ได้รับอนุญาต)
- **Process:**
  ```bash
  grep -oE '[?&][a-zA-Z0-9_]+=' example.com/fuzzable.txt | tr -d '?&=' | sort -u
  ```

### `endpoints.txt`
- **Purpose:** endpoint จาก JS
- **Process:**
  ```bash
  grep -Ei '(/api/|/v[0-9]+/)' example.com/endpoints.txt | sort -u
  ```

### `scripts.txt`
- **Purpose:** รายการไฟล์ JS สำหรับ JS recon (Part VII)

### `intel.txt`
- **Purpose:** อีเมล/โซเชียล/bucket
- **Process:**
  ```bash
  grep -Eo '[a-zA-Z0-9._%+-]+@example\.com' example.com/intel.txt | sort -u
  ```

### `files.txt`, `robots.txt`, `custom.txt`, `keys.txt`, `failed.txt`, `subdomains.txt`
- ใช้ pattern เดียวกัน: `sort -u`, `grep`, `wc -l` เพื่อสรุป/กรอง

---

# Part XII — JSON & Text Processing

## ดูโครงสร้าง export

```bash
python photon.py -u https://example.com -e json
jq . example.com/exported.json | head -n 40
```

## Filter

```bash
jq -r '.internal[]?' example.com/exported.json | sort -u
jq -r '.fuzzable[]?' example.com/exported.json | sort -u
```

**NOTE:** โครงสร้าง key ของ exported.json ต่างตามเวอร์ชัน — ตรวจ key จริงก่อน:

```bash
jq 'keys' example.com/exported.json
```

## Count

```bash
jq -r '.internal[]?' example.com/exported.json | wc -l
```

## Extract (เฉพาะ host)

```bash
jq -r '.internal[]?' example.com/exported.json | awk -F/ '{print $3}' | sort -u
```

## Deduplicate

```bash
sort -u example.com/internal.txt -o example.com/internal.txt
```

## Search

```bash
grep -Ei 'admin|login|dashboard' example.com/internal.txt
```

## Merge (หลายโดเมน)

```bash
cat */internal.txt | sort -u > all_internal.txt
```

## เครื่องมือข้อความที่ใช้บ่อย

```bash
# grep: ค้น pattern
grep -Ei '/api/' example.com/internal.txt
# awk: ตัด field ตาม /
awk -F/ '{print $3}' example.com/internal.txt | sort -u
# sed: แทนที่ scheme
sed -E 's#^https?://##' example.com/internal.txt | sort -u
# cut: ตัดพารามิเตอร์
cut -d'?' -f1 example.com/fuzzable.txt | sort -u
# sort | uniq -c: นับความถี่
awk -F/ '{print $3}' example.com/external.txt | sort | uniq -c | sort -rn
```

---

# Part XIII — Linux Automation

## Bash wrapper (รันสะดวก + ตั้งชื่อโฟลเดอร์ตามวันที่)

```bash
#!/usr/bin/env bash
# file: recon.sh  (chmod +x recon.sh)
set -euo pipefail
TARGET="$1"
DATE="$(date +%F)"
OUT="recon/${TARGET//[^a-zA-Z0-9]/_}_${DATE}"
python ~/Photon/photon.py -u "https://${TARGET}" -l 3 -t 10 -d 0.2 -o "$OUT" -e json
echo "[+] internal: $(wc -l < "$OUT/internal.txt")"
echo "[+] endpoints: $(wc -l < "$OUT/endpoints.txt")"
```

## Cron (recon ประจำสำหรับ asset ของตนเอง)

```bash
crontab -e
# ทุกวันจันทร์ 03:15 น. ครอว์ลเว็บองค์กรของตนเองเพื่อเฝ้าดู asset ใหม่
15 3 * * 1 /home/user/recon.sh example.com >> /home/user/recon/cron.log 2>&1
```

## xargs (ครอว์ลหลายโดเมนของตนเอง)

```bash
cat my_domains.txt | xargs -I{} -P2 python ~/Photon/photon.py -u https://{} -l 2 -o recon/{}
```

## parallel

```bash
parallel -j2 'python ~/Photon/photon.py -u https://{} -l 2 -o recon/{}' :::: my_domains.txt
```

## find + tee

```bash
find recon -name internal.txt -exec cat {} + | sort -u | tee master_urls.txt | wc -l
```

## Pipeline: Photon → jq → CSV → report

```bash
python ~/Photon/photon.py -u https://example.com -e json -o out
jq -r '.internal[]?' out/exported.json \
  | awk -F/ '{print $3","$0}' \
  | sort -u > report.csv
echo "host,url" | cat - report.csv > report_with_header.csv
```

```
Photon ──► exported.json ──► jq ──► CSV ──► report_with_header.csv
```

---

# Part XIV — Docker

## Build

```bash
cd Photon
docker build -t photon .
```

## Run (พื้นฐาน)

```bash
docker run -it --rm photon -u example.com
```

## Volume (ดึง output ออกมานอก container)

```bash
mkdir -p "$PWD/out"
docker run -it --rm -v "$PWD/out:/Photon/output" photon -u example.com -o /Photon/output/example
ls out/example
```

**NOTE:** path ปลายทางใน container ต่างตาม Dockerfile/เวอร์ชัน — ตรวจ WORKDIR ด้วย `docker run --rm photon --help` หรืออ่าน Dockerfile

## Environment

```bash
docker run -it --rm -e HTTPS_PROXY=http://127.0.0.1:8080 photon -u example.com
```

## Networking

```bash
# ใช้ network ของ host (ระวังผลกระทบ)
docker run -it --rm --network host photon -u example.com
```

## Update

```bash
cd Photon && git pull && docker build -t photon .
```

## Remove

```bash
docker rmi photon
docker image prune -f
```

---

# Part XV — Python Integration

> เรียกใช้ Photon จาก Python ด้วย `subprocess` แล้วอ่าน output — **ไม่แก้ source ของ Photon**

## เรียกใช้และอ่านผล

```python
#!/usr/bin/env python3
import subprocess, json, os, pathlib

def run_photon(target, level=3, threads=10, outdir="out"):
    cmd = [
        "python", os.path.expanduser("~/Photon/photon.py"),
        "-u", f"https://{target}",
        "-l", str(level), "-t", str(threads),
        "-e", "json", "-o", outdir,
    ]
    subprocess.run(cmd, check=True)
    return pathlib.Path(outdir)

def load_results(outdir):
    p = pathlib.Path(outdir) / "exported.json"
    if p.exists():
        return json.loads(p.read_text())
    # fallback: อ่านจากไฟล์ .txt
    data = {}
    for name in ["internal", "external", "fuzzable", "endpoints", "scripts"]:
        f = pathlib.Path(outdir) / f"{name}.txt"
        data[name] = f.read_text().splitlines() if f.exists() else []
    return data

if __name__ == "__main__":
    out = run_photon("example.com")
    res = load_results(out)
    print("internal:", len(res.get("internal", [])))
    print("endpoints:", len(res.get("endpoints", [])))
```

## parse output แบบเบา (ไม่ต้อง export)

```python
import pathlib
def read_dataset(outdir, name):
    f = pathlib.Path(outdir) / f"{name}.txt"
    return sorted(set(f.read_text().splitlines())) if f.exists() else []
```

## automation หลายเป้าหมาย (ของตนเอง)

```python
for t in ["example.com", "example.org", "example.net"]:
    run_photon(t, outdir=f"out/{t}")
```

---

# Part XVI — Source Code Structure

โครงสร้าง repo (โดยสังเขป — ตรวจของจริงด้วย `ls -R`):

```
Photon/
├── photon.py           # entrypoint + argparse + ลูปครอว์ล
├── core/               # โมดูลหลัก (utils, config, requester, regex, prompt, ...)
│   ├── config.py       # ค่า default: regex, ค่าคงที่, ส่วนขยายไฟล์ ฯลฯ
│   ├── utils.py        # ฟังก์ชันช่วย (writer, is_link, ...)
│   ├── requester.py    # ยิง HTTP request
│   ├── zap.py          # อ่าน sitemap/robots เป็น seed (ตามเวอร์ชัน)
│   └── ...
├── plugins/            # wayback, dnsdumpster, exporter
├── requirements.txt
├── Dockerfile
└── README.md
```

จุดที่ควรอ่านเพื่อ debug/พัฒนา:

- `photon.py` — ลำดับการทำงาน, การจัด dataset, การเรียก writer
- `core/config.py` — ค่า default (level, threads, extensions, regex intel)
- `core/utils.py` — ฟังก์ชัน `writer()` ที่กำหนดชื่อไฟล์ output
- `plugins/exporter.py` — โครงสร้าง json/csv ที่ export

ดู argparse จริง:

```bash
grep -nE "add_argument" ~/Photon/photon.py
```

ดูชื่อไฟล์ output จริงในโค้ด:

```bash
grep -rnE "writer\(|\.txt" ~/Photon/core ~/Photon/photon.py
```

**NOTE:** อ่านโค้ดเพื่อทำความเข้าใจ/แก้ bug ของ pipeline ตัวเอง — เอกสารนี้ไม่แนะนำให้ดัดแปลง Photon เพื่อวัตถุประสงค์โจมตี

---

# Part XVII — Performance Optimization

| ปัจจัย | ผล | คำแนะนำ |
|--------|-----|---------|
| `-t` threads | เร็วขึ้น แต่โหลดเป้าหมายหนัก | เริ่ม 5–10, เพิ่มเมื่อมั่นใจว่าไม่กระทบ |
| `-l` level | coverage เพิ่ม, เวลาเพิ่มทวีคูณ | 2–3 สำหรับสำรวจ, 4–5 สำหรับเจาะลึก |
| `-d` delay | ลดภาระ/หลบ rate-limit | 0.1–0.5 กับเว็บ production |
| `--timeout` | กัน request ค้าง | 5–10 |
| `--exclude` | ตัดกิ่งขยะ | ตัด `/tag/`, `/page/`, uploads |
| memory | โตตามจำนวน URL | เว็บใหญ่ให้ลด level + exclude |

## สูตรตั้งค่าตามสถานการณ์

```bash
# เว็บเล็ก/สแกนเร็ว
python photon.py -u https://example.com -l 2 -t 10

# เว็บกลาง/สมดุล
python photon.py -u https://example.com -l 3 -t 8 -d 0.2 --timeout 8 \
  --exclude '(/tag/|/page/[0-9]+)'

# เว็บใหญ่/ควบคุมภาระ
python photon.py -u https://example.com -l 3 -t 5 -d 0.5 --timeout 10 \
  --exclude '(/uploads/|/static/|\.(png|jpg|css)$)'
```

## วัดผล

```bash
time python photon.py -u https://example.com -l 3 -t 8 -o out
wc -l out/internal.txt out/endpoints.txt out/fuzzable.txt
```

---

# Part XVIII — Large Website Recon

Workflow สำหรับเว็บใหญ่ (news / university / enterprise / docs / SaaS) — ใช้ตัวอย่าง `example.com` เท่านั้น:

```
1) ครอว์ลตื้นก่อน (-l 2) เพื่อ map โครงสร้างหลัก
2) ระบุ "กิ่งขยะ" (pagination, tag, media) แล้ว --exclude
3) แยก subtree สำคัญเป็น seed (-s /app /api /docs)
4) เพิ่ม level เฉพาะ subtree ที่มีค่า
5) รวมผล + dedupe + จัดหมวด
```

## สคริปต์ตัวอย่าง

```bash
# รอบ 1: map
python photon.py -u https://example.com -l 2 -t 8 -o out/map

# ระบุกิ่งที่ควรตัด
awk -F/ '{print $4}' out/map/internal.txt | sort | uniq -c | sort -rn | head

# รอบ 2: เจาะ subtree
python photon.py -u https://example.com -l 4 -t 6 -d 0.3 \
  -s https://example.com/app https://example.com/api \
  --exclude '(/tag/|/page/[0-9]+|/uploads/)' -o out/deep -e json
```

---

# Part XIX — Bug Bounty Recon Workflows

> **Recon เท่านั้น** — ไม่มี exploit/bypass/privesc ทุก workflow อยู่ในกรอบ scope ที่โปรแกรมอนุญาต

**W1. Initial Crawl**
```bash
python photon.py -u https://example.com -l 2 -t 8 -o bb/initial
```

**W2. JS Recon**
```bash
python photon.py -u https://example.com -l 3 -o bb/js
sort -u bb/js/scripts.txt
```

**W3. Endpoint Discovery**
```bash
sort -u bb/js/endpoints.txt
```

**W4. Sitemap Collection**
```bash
python photon.py -u https://example.com -s https://example.com/sitemap.xml -o bb/sitemap
```

**W5. Asset Inventory**
```bash
grep -Ei '\.(js|json|xml|pdf)$' bb/js/internal.txt | sort -u
```

**W6. API Inventory**
```bash
grep -Ei '(/api/|/v[0-9]+/|graphql)' bb/js/*.txt | sort -u
```

**W7. Hidden URL Collection (wayback)**
```bash
python photon.py -u https://example.com --wayback -l 2 -o bb/wayback
```

**W8. Parameter Inventory**
```bash
grep -oE '[?&][a-zA-Z0-9_]+=' bb/js/fuzzable.txt | tr -d '?&=' | sort -u > bb/params.txt
```

**W9. Intel Collection (email/social)**
```bash
sort -u bb/js/intel.txt
```

**W10. Secret Surface (keys)**
```bash
python photon.py -u https://example.com --keys -o bb/keys
```

**W11. Subdomain Seed (dns)**
```bash
python photon.py -u https://example.com --dns -o bb/dns
sort -u bb/dns/subdomains.txt
```

**W12. Regex Harvest**
```bash
python photon.py -u https://example.com -r '/(api|internal|admin)/[a-z0-9_/-]+' -o bb/regex
cat bb/regex/custom.txt
```

**W13. External Dependency Map**
```bash
awk -F/ '{print $3}' bb/js/external.txt | sort | uniq -c | sort -rn
```

**W14. Media/Doc Harvest**
```bash
grep -Ei '\.(pdf|docx?|xlsx?)$' bb/js/files.txt | sort -u
```

**W15. Merge & Dedupe (master list)**
```bash
cat bb/*/internal.txt bb/*/endpoints.txt | sort -u > bb/master_urls.txt
```

**W16. Prioritize (param+api ก่อน)**
```bash
grep -Ei '(\?|/api/|/v[0-9]+/)' bb/master_urls.txt | sort -u > bb/priority.txt
```

**W17. Diff รอบก่อน-รอบใหม่ (เจอ asset ใหม่)**
```bash
comm -13 <(sort bb/master_prev.txt) <(sort bb/master_urls.txt) > bb/new_assets.txt
```

**W18. Feed to httpx (ยืนยัน host ที่ live)**
```bash
awk -F/ '{print $1"//"$3}' bb/master_urls.txt | sort -u | httpx -silent
```

**W19. Feed to katana/gau (ขยายผล)**
```bash
awk -F/ '{print $1"//"$3}' bb/master_urls.txt | sort -u | katana -silent
```

**W20. Report Assembly**
```bash
{
  echo "# Recon summary: example.com ($(date +%F))"
  echo "- hosts: $(awk -F/ '{print $3}' bb/master_urls.txt | sort -u | wc -l)"
  echo "- urls: $(wc -l < bb/master_urls.txt)"
  echo "- api: $(grep -Eic '(/api/|graphql)' bb/master_urls.txt)"
} > bb/summary.md
```

---

# Part XX — Corporate Website Recon

```
Company Domain (example.com)
   |
   +── Photon crawl ──► internal/external/scripts
   |
   +── Assets ──► js/css/img/pdf inventory
   |
   +── Subpaths ──► /careers /investors /support /docs
   |
   +── Public Files ──► pdf, xlsx, sitemap
   |
   +── Technology Inventory ──► external deps + fingerprint (เครื่องมือเสริม)
   |
   +── Documentation ──► /docs /developer /api-reference
```

```bash
python photon.py -u https://example.com -l 3 -t 6 -d 0.3 -o corp/example -e json
grep -Ei '(careers|investor|support|docs|developer)' corp/example/internal.txt | sort -u
grep -Ei '\.(pdf|xlsx?|docx?)$' corp/example/files.txt | sort -u
```

---

# Part XXI — Threat Intelligence Workflow

ใช้ Photon เก็บ **IOC เชิงโครงสร้าง** จากเว็บ (เพื่อวิเคราะห์/เฝ้าระวัง asset ของตนเอง):

- **URLs / Domains** — จาก internal/external
- **CDN / Third-party Scripts** — จาก external + scripts
- **Analytics / Tracking** — จาก external

```bash
# third-party domains ทั้งหมด
awk -F/ '{print $3}' example.com/external.txt | sort -u > ti/third_parties.txt

# สคริปต์ภายนอก (supply-chain surface)
grep -Ei '^https?://' example.com/scripts.txt | awk -F/ '{print $3}' | sort -u > ti/ext_scripts.txt

# analytics/tracking ที่พบบ่อย
grep -Ei '(google-analytics|googletagmanager|hotjar|segment|mixpanel|facebook)' \
  example.com/external.txt | sort -u
```

**การวิเคราะห์:** เทียบ `third_parties.txt` กับ baseline ที่อนุมัติไว้ → domain ใหม่ที่โผล่มาคือสิ่งที่ต้องสอบสวน (อาจเป็น script ที่ถูกฝังโดยไม่ตั้งใจ)

---

# Part XXII — Blue Team Workflow

ใช้ Photon ตรวจเว็บ **ขององค์กรตนเอง** เพื่อลด attack surface:

- **Asset Inventory** — รู้ว่ามีอะไร public บ้าง
- **Forgotten Files** — `.bak/.old/.env/backup` ที่หลุด
- **Old JS / Old APIs** — เวอร์ชันเก่าที่ควรถอด
- **Documentation / Backup** — เอกสาร/สำรองที่ไม่ควร public
- **Public Exposure** — endpoint ภายในที่โผล่ออกมา

```bash
python photon.py -u https://example.com --keys --dns -l 3 -o blue/example -e json

# ไฟล์ที่ไม่ควร public
grep -Ei '\.(env|bak|old|sql|zip|config|yml|yaml)(\?|$)' blue/example/*.txt | sort -u

# endpoint ภายในที่หลุด
grep -Ei '(internal|staging|dev|test|admin)' blue/example/internal.txt | sort -u
```

**การใช้ผล:** ทุกบรรทัดที่เจอ = ticket ให้ทีมปิด/ย้าย/จำกัดสิทธิ์ แล้วครอว์ลซ้ำเพื่อยืนยันว่าหายไปแล้ว

---

# Part XXIII — Red Team Recon Workflow

ภายใต้ engagement ที่ได้รับอนุญาต — ใช้ Photon ในเฟส recon เท่านั้น:

- **Crawl** — เก็บ URL/endpoint
- **JS Inventory** — หา endpoint/route ที่ซ่อนใน JS
- **Endpoint Inventory** — รวม API surface
- **Technology Mapping** — external deps (ต่อเครื่องมือ fingerprint)
- **Asset Mapping** — โฮสต์/subdomain

```bash
python photon.py -u https://example.com --dns -l 3 -t 6 -d 0.3 -o red/example -e json
sort -u red/example/endpoints.txt
awk -F/ '{print $1"//"$3}' red/example/internal.txt | sort -u > red/example/hosts.txt
```

**NOTE:** ทั้งหมดคือการ **รวบรวมข้อมูล** ขั้นตอนถัดไป (การทดสอบช่องโหว่/exploitation) อยู่นอกขอบเขตเอกสารนี้ และต้องทำตาม RoE ที่ตกลงไว้เท่านั้น

---

# Part XXIV — Integration กับเครื่องมือ OSINT อื่น

Photon เก่งเรื่อง “ครอว์ล + ดึง endpoint จาก JS” จึงวางเป็น **ต้นน้ำ/กลางน้ำ** ของ pipeline

**I1. subfinder → Photon** (ครอว์ลทุก subdomain ที่ค้นได้)
```bash
subfinder -d example.com -silent | while read -r h; do
  python photon.py -u "https://$h" -l 2 -o out/"$h"
done
```

**I2. amass → Photon**
```bash
amass enum -passive -d example.com -o subs.txt
xargs -I{} python photon.py -u https://{} -l 2 -o out/{} < subs.txt
```

**I3. Photon → httpx** (คัดเฉพาะ host ที่ live)
```bash
awk -F/ '{print $1"//"$3}' out/*/internal.txt | sort -u | httpx -silent -status-code
```

**I4. Photon → katana** (ขยายการครอว์ลด้วย engine อื่น)
```bash
sort -u out/*/internal.txt | katana -silent -jc
```

**I5. Photon + gau/waybackurls** (รวม URL ประวัติศาสตร์)
```bash
gau example.com | sort -u > gau.txt
cat out/*/internal.txt gau.txt | sort -u > merged.txt
```

**I6. Photon --wayback (ในตัว)**
```bash
python photon.py -u https://example.com --wayback -l 2 -o out/wb
```

**I7. Photon → nuclei (เฉพาะ template ที่ปลอดภัย/ได้รับอนุญาต)**
```bash
awk -F/ '{print $1"//"$3}' out/*/internal.txt | sort -u | httpx -silent | nuclei -silent
```

**I8. Photon → gf pattern**
```bash
sort -u out/*/fuzzable.txt | gf ssrf 2>/dev/null | sort -u   # ระบุ candidate ให้ทีมตรวจต่อ
```

**I9. Photon endpoints → เปรียบเทียบ OpenAPI ของตนเอง**
```bash
comm -23 <(sort out/*/endpoints.txt) <(jq -r '.paths|keys[]' openapi.json | sort)
```

**I10. theHarvester + Photon intel**
```bash
theHarvester -d example.com -b bing -f th.json
cat out/*/intel.txt th.json | grep -Eo '[a-z0-9._%+-]+@example\.com' | sort -u
```

**I11. SpiderFoot** — นำ domain/subdomain จาก Photon ป้อนเป็น target seed ใน SpiderFoot

**I12. Maltego** — import `external.txt`/`subdomains.txt` เป็น entity เพื่อทำ graph

**I13. Photon → dnsx** (resolve subdomain)
```bash
sort -u out/dns/subdomains.txt | dnsx -silent -a -resp
```

**I14. Photon → anew** (คัดเฉพาะของใหม่เข้าคลัง)
```bash
sort -u out/*/internal.txt | anew master_urls.txt
```

**I15. Photon → csv → spreadsheet**
```bash
python photon.py -u https://example.com -e csv -o out/example
```

```
subfinder/amass ─► Photon ─► httpx/katana/gau ─► gf/nuclei ─► report
```

---

# Part XXV — Kali Linux Toolkit (ใช้คู่ Photon)

```bash
# curl: ดึงหน้า/ไฟล์เดี่ยวมายืนยัน
curl -sI https://example.com/robots.txt

# wget: mirror เฉพาะจุด (ในระบบที่มีสิทธิ์)
wget -q -O app.js https://example.com/static/js/app.js

# dig/host/nslookup: ยืนยัน DNS ของ host ที่ Photon เจอ
dig +short example.com A
host example.com
nslookup example.com

# jq: ประมวลผล exported.json
jq -r '.internal[]?' out/exported.json | sort -u

# grep/awk/sed/cut/xargs: จัดการ text (ดู Part XII)
awk -F/ '{print $3}' out/internal.txt | sort -u
```

ตัวอย่างต่อท่อครบวง:

```bash
python photon.py -u https://example.com --stdout internal \
  | awk -F/ '{print $1"//"$3}' | sort -u \
  | httpx -silent | tee live_hosts.txt
```

---

# Part XXVI — Case Studies (ข้อมูลสมมติทั้งหมด)

> ทุก case ใช้ `example.com/org/net` และ IP TEST-NET เท่านั้น เป็นสถานการณ์จำลองเพื่อสอนวิธีคิด

**CS1 — เว็บบริษัทขนาดเล็ก (example.com)**
```bash
python photon.py -u https://example.com -l 2 -t 8 -o cs/1
```
พบ `/careers`, `/contact`, อีเมลใน `intel.txt` → ทำ contact map

**CS2 — เว็บข่าว (example.org) มี pagination มหาศาล**
```bash
python photon.py -u https://example.org -l 3 --exclude '(/page/[0-9]+|/tag/)' -o cs/2
```
บทเรียน: ไม่ตัด pagination = ครอว์ลไม่จบ

**CS3 — SPA (example.net) โครงสร้างอยู่ใน JS**
```bash
python photon.py -u https://example.net -l 3 -o cs/3
sort -u cs/3/endpoints.txt
```
endpoint จริงมาจาก `endpoints.txt` ไม่ใช่ HTML

**CS4 — เว็บมหาวิทยาลัย (example.edu จำลองเป็น example.org)**
```bash
python photon.py -u https://example.org -l 3 -s https://example.org/faculty -o cs/4
```
seed แยกคณะช่วย coverage

**CS5 — พบ swagger (example.com)**
```bash
grep -Ei '(swagger|openapi|api-docs)' cs/1/*.txt
```
ยืนยันด้วยมือว่าเปิด public หรือไม่ (ระบบของตนเอง)

**CS6 — .env.example หลุด (example.net)**
```bash
grep -Ei '\.env' cs/3/*.txt
```
ตรวจว่าเป็น `.env.example` (ไม่ลับ) หรือ `.env` จริง (ต้องปิด)

**CS7 — source map เปิดอยู่ (example.com)**
```bash
grep -Ei 'sourceMappingURL|\.map$' cs/1/*.txt
```
บันทึกเป็น finding ให้ทีมพิจารณาปิดใน production

**CS8 — third-party script เพียบ (example.org)**
```bash
awk -F/ '{print $3}' cs/2/external.txt | sort | uniq -c | sort -rn
```
ทำ supply-chain inventory

**CS9 — subdomain sprawl (example.com)**
```bash
python photon.py -u https://example.com --dns -o cs/9
sort -u cs/9/subdomains.txt
```

**CS10 — wayback เจอ endpoint เก่า (example.net)**
```bash
python photon.py -u https://example.net --wayback -l 2 -o cs/10
comm -13 <(sort cs/3/internal.txt) <(sort cs/10/internal.txt)
```

**CS11 — เฝ้าดู asset ใหม่รายสัปดาห์ (example.com)**
```bash
sort -u cs/1/internal.txt | anew cs/baseline.txt
```

**CS12 — รวมทุกโดเมนของตนเองเป็น master**
```bash
cat cs/*/internal.txt | sort -u | wc -l
```

**Host/IP สมมติที่ใช้อ้างอิงในเอกสาร:** `192.0.2.15`, `198.51.100.20`, `203.0.113.10` (TEST-NET — ไม่ใช่ระบบจริง)

---

# Part XXVII — Troubleshooting (50+ ปัญหา)

**Installation / Python**
1. `python: command not found` → ใช้ `python3`; หรือสร้าง alias
2. `pip: command not found` → `sudo apt install python3-pip`
3. ImportError หลัง clone → `pip3 install -r requirements.txt`
4. เวอร์ชัน Python เก่า → ใช้ venv กับ Python 3.8+
5. แพ็กเกจชนกับระบบ → ใช้ `python3 -m venv`
6. `externally-managed-environment` (PEP 668) → ใช้ venv หรือ `pipx`
7. `tld`/dependency หาย → ติดตั้งซ้ำจาก requirements
8. รันจากนอกโฟลเดอร์ repo → `cd Photon` ก่อน หรือใช้ path เต็ม
9. สิทธิ์เขียนโฟลเดอร์ output ไม่ได้ → เลือก `-o` ไปที่ path ที่เขียนได้
10. Windows path ปน → รันบน Linux/WSL

**SSL / Network**
11. `SSLError` → เว็บใช้ cert ผิด/หมดอายุ; ตรวจด้วย `curl -v`
12. ผ่าน proxy องค์กร → ตั้ง `HTTPS_PROXY`/`-p`
13. `ConnectionError` → เป้าหมายบล็อก/ล่ม; ลอง `curl -I`
14. โดน rate-limit → เพิ่ม `-d`, ลด `-t`
15. Timeout ถี่ → เพิ่ม `--timeout`
16. IPv6 มีปัญหา → บังคับ resolve ผ่าน `/etc/hosts` หรือ DNS
17. redirect วน → seed ด้วย URL ปลายทางตรง ๆ
18. WAF ตอบ 403 กับ UA เริ่มต้น → `--user-agent` ที่เหมาะสม (งานที่ได้รับอนุญาต)
19. ต้อง auth ถึงเข้าได้ → `-c` cookie / `--headers`
20. โดน captcha → นอกวิสัย crawler; ประสานเจ้าของระบบ

**DNS**
21. `--dns` ว่างเปล่า → บริการ dnsdumpster เปลี่ยน/จำกัด; ใช้ subfinder/amass เสริม
22. subdomain ไม่ resolve → `dnsx`/`dig` ยืนยัน
23. DNS ภายในองค์กร → ตั้ง resolver ให้ถูก

**Thread / Memory / Performance**
24. RAM หมดกับเว็บใหญ่ → ลด `-l`, ใช้ `--exclude`
25. CPU พุ่ง → ลด `-t`
26. ครอว์ลไม่จบ → ตัด pagination/tag ด้วย `--exclude`
27. ช้ามาก → เพิ่ม `-t` เล็กน้อย + ตรวจ network
28. เครื่องค้าง → จำกัด scope, รันเป็น batch

**Output**
29. ไม่มีไฟล์ output → ครอว์ลไม่พบลิงก์ (เว็บ JS-only) → seed ด้วยไฟล์ JS
30. ไฟล์ output ชื่อไม่ตรงคู่มือ → `ls` ดูชื่อจริง (ต่างตามเวอร์ชัน)
31. `exported.json` ไม่มี → ลืมใส่ `-e json`
32. json key ไม่ตรง → `jq 'keys'` ตรวจ schema จริง
33. ผลว่าง (empty result) → level ต่ำ/โดนบล็อก/ต้อง auth
34. URL ซ้ำ → `sort -u` เสมอ
35. อักขระเพี้ยน (encoding) → บังคับ `LANG=C.UTF-8`

**Docker**
36. build ล้ม → ตรวจ Docker daemon, เน็ต, base image
37. ดึง output ไม่ได้ → ใช้ `-v` mount volume + `-o` ชี้ไป path ที่ mount
38. network ใน container เข้าไม่ถึงเป้าหมาย → `--network host` (ระวังผลกระทบ)
39. permission ของ volume → ตรวจ uid/gid, `chmod` โฟลเดอร์ out

**Robots / Sitemap / JS**
40. `robots.txt` ว่าง → เป้าหมายไม่มี robots; ไม่ใช่ error
41. sitemap ใหญ่มาก → seed เฉพาะบางส่วน
42. JS parsing ไม่เจอ endpoint → JS ถูก minify/obfuscate; โหลด `.map` (ถ้าได้รับอนุญาต)
43. chunk file เยอะ → กรองด้วย `grep -Ei 'chunk|bundle'`

**อื่น ๆ**
44. `--wayback` ช้า/ว่าง → archive.org จำกัด; ลองใหม่ภายหลัง
45. `--keys` เจอแต่ false positive → ตรวจด้วยมือ, cross-check
46. regex ไม่ทำงาน → ครอบ single quote, escape ให้ถูก
47. `--stdout` ไม่ออกอะไร → ชื่อ dataset ผิด; ดู `--help`
48. `--update` conflict → ใช้ `git stash` แล้ว `git pull`
49. รันหลาย instance ชน output → แยก `-o` คนละโฟลเดอร์
50. ผลต่างกันทุกครั้ง → เว็บ dynamic/บาง path สุ่ม; ครอว์ลซ้ำแล้ว union ผล
51. โดนบล็อก IP → ลด aggressiveness, ประสานเจ้าของระบบ, เคารพ scope
52. ไม่แน่ใจว่า flag มีจริง → `python photon.py --help` คือแหล่งความจริงสุดท้าย

---

# Part XXVIII — Command Encyclopedia

รวมคำสั่งพร้อม Syntax / Example / Output / Notes

```bash
# help
python photon.py --help
# → พิมพ์ flag ทั้งหมดของเวอร์ชันนั้น

# crawl พื้นฐาน
python photon.py -u https://example.com
# → โฟลเดอร์ example.com/ พร้อม dataset

# depth + threads + delay
python photon.py -u https://example.com -l 3 -t 8 -d 0.2

# export json + output dir
python photon.py -u https://example.com -e json -o out/example

# regex harvest
python photon.py -u https://example.com -r '/api/v[0-9]+/[a-z]+'   # → custom.txt

# exclude
python photon.py -u https://example.com --exclude '(logout|/tag/)'

# cookie / headers / UA
python photon.py -u https://example.com -c "session=REDACTED"
python photon.py -u https://example.com --headers
python photon.py -u https://example.com --user-agent "recon-UA"

# dns / keys / wayback / clone
python photon.py -u https://example.com --dns       # → subdomains.txt
python photon.py -u https://example.com --keys      # → keys.txt
python photon.py -u https://example.com --wayback
python photon.py -u https://example.com --clone

# only-urls / verbose / timeout / proxy
python photon.py -u https://example.com --only-urls
python photon.py -u https://example.com -v
python photon.py -u https://example.com --timeout 10
python photon.py -u https://example.com -p 127.0.0.1:8080

# stdout pipe
python photon.py -u https://example.com --stdout internal | httpx -silent

# update
python photon.py --update
```

---

# Part XXIX — Workflow Encyclopedia (30+)

แต่ละ workflow: Objective / Input / Commands / Output / Analysis / Checklist

**WF01 Quick Map**
- Objective: รู้โครงสร้างเว็บเร็ว ๆ
- Commands: `python photon.py -u https://example.com -l 2 -o wf/01`
- Output: internal.txt
- Checklist: [ ] host list [ ] top paths

**WF02 Deep Crawl (subtree)**
- `python photon.py -u https://example.com -l 4 -s https://example.com/app --exclude '(/tag/)' -o wf/02`

**WF03 JS Endpoint Harvest**
- `sort -u wf/02/endpoints.txt > wf/02/api.txt`

**WF04 Parameter Inventory**
- `grep -oE '[?&][a-zA-Z0-9_]+=' wf/02/fuzzable.txt | tr -d '?&=' | sort -u`

**WF05 Wayback Union**
- `python photon.py -u https://example.com --wayback -o wf/05 && cat wf/02/internal.txt wf/05/internal.txt | sort -u`

**WF06 Subdomain Seeding**
- `python photon.py -u https://example.com --dns -o wf/06`

**WF07 Secret Surface**
- `python photon.py -u https://example.com --keys -o wf/07`

**WF08 Third-Party Inventory**
- `awk -F/ '{print $3}' wf/02/external.txt | sort | uniq -c | sort -rn`

**WF09 Doc/File Harvest**
- `grep -Ei '\.(pdf|docx?|xlsx?)$' wf/02/files.txt | sort -u`

**WF10 Live Host Verify**
- `awk -F/ '{print $1"//"$3}' wf/02/internal.txt | sort -u | httpx -silent`

**WF11 Endpoint Diff vs OpenAPI**
- `comm -23 <(sort wf/02/endpoints.txt) <(jq -r '.paths|keys[]' openapi.json|sort)`

**WF12 New-Asset Monitor**
- `sort -u wf/02/internal.txt | anew wf/baseline.txt`

**WF13 Multi-Domain Batch**
- `xargs -I{} python photon.py -u https://{} -o wf/multi/{} < my_domains.txt`

**WF14 CSV Report**
- `python photon.py -u https://example.com -e csv -o wf/14`

**WF15 JSON→jq Pipeline**
- `jq -r '.internal[]?' wf/14/exported.json | sort -u` (ถ้า export json)

**WF16 Regex Endpoint Map**
- `python photon.py -u https://example.com -r '/(api|graphql)/[a-z0-9_/-]+' -o wf/16`

**WF17 Static vs Dynamic Split**
- `grep -E '\?' wf/02/internal.txt > wf/dyn.txt; grep -vE '\?' wf/02/internal.txt > wf/static.txt`

**WF18 CDN Mapping**
- `grep -Ei '(cdn|cloudfront|fastly|akamai)' wf/02/external.txt | sort -u`

**WF19 Intel Extract**
- `grep -Eo '[a-z0-9._%+-]+@example\.com' wf/02/intel.txt | sort -u`

**WF20 Source Map Check**
- `grep -Ei 'sourceMappingURL|\.map$' wf/02/*.txt`

**WF21 Clone for Offline Review**
- `python photon.py -u https://example.com --clone -o wf/21`

**WF22 Proxy-Through (lab)**
- `python photon.py -u https://example.com -p 127.0.0.1:8080 -o wf/22`

**WF23 Rate-Limited Polite Crawl**
- `python photon.py -u https://example.com -t 3 -d 1 -o wf/23`

**WF24 Priority List (api+param)**
- `grep -Ei '(\?|/api/|graphql)' wf/02/internal.txt | sort -u > wf/priority.txt`

**WF25 Merge All Domains**
- `cat wf/multi/*/internal.txt | sort -u > wf/master.txt`

**WF26 Feed katana**
- `sort -u wf/master.txt | katana -silent`

**WF27 Feed gau**
- `gau example.com | anew wf/master.txt`

**WF28 Blue-Team Exposure Scan**
- `grep -Ei '(\.env|\.bak|backup|staging|internal)' wf/02/*.txt | sort -u`

**WF29 Weekly Cron Recon**
- ตั้ง cron รัน `recon.sh` (Part XIII)

**WF30 Full Report Assembly**
- รวม summary.md + master.txt + asset_inventory.txt เป็นรายงานเดียว

**WF31 Endpoint→nuclei (authorized)**
- `awk -F/ '{print $1"//"$3}' wf/master.txt | httpx -silent | nuclei -silent`

**WF32 Delta Since Last Scan**
- `comm -13 <(sort wf/prev_master.txt) <(sort wf/master.txt) > wf/new.txt`

---

# Part XXX — Quick Reference

## Photon (ท่าที่ใช้บ่อย)

```bash
python photon.py --help                                   # flag ทั้งหมด
python photon.py -u https://example.com                    # crawl
python photon.py -u https://example.com -l 3 -t 8 -d 0.2   # ปรับความเข้ม
python photon.py -u https://example.com -e json -o out     # export
python photon.py -u https://example.com --dns --keys       # subdomain + keys
python photon.py -u https://example.com --wayback          # seed จาก archive
python photon.py -u https://example.com --exclude '(/tag/)' # ตัดกิ่ง
python photon.py -u https://example.com --stdout internal | httpx -silent
```

## Text/JSON

```bash
sort -u file.txt                              # dedupe
awk -F/ '{print $3}' file.txt | sort -u       # host list
cut -d'?' -f1 fuzzable.txt | sort -u          # ตัด param
grep -Ei '(/api/|graphql)' *.txt | sort -u    # API surface
jq -r '.internal[]?' exported.json | sort -u  # จาก json
comm -13 <(sort old) <(sort new)              # ของใหม่
```

## Integration

```bash
subfinder -d example.com -silent | while read h; do python photon.py -u https://$h -o out/$h; done
awk -F/ '{print $1"//"$3}' out/*/internal.txt | sort -u | httpx -silent
sort -u out/*/internal.txt | katana -silent
gau example.com | anew master.txt
```

## Docker

```bash
docker build -t photon .
docker run -it --rm -v "$PWD/out:/Photon/output" photon -u example.com -o /Photon/output/example
```

## Troubleshooting เร็ว

```bash
python photon.py --help          # flag มีจริงไหม
ls -1 example.com/               # ชื่อไฟล์ output จริง
curl -vI https://example.com     # ตรวจ SSL/redirect/บล็อก
jq 'keys' out/exported.json      # schema json จริง
```

---

## ปิดท้าย

- Photon = ต้นน้ำเก็บ URL/endpoint ที่ต่อท่อเข้าทุก pipeline recon ได้
- ยืนยัน flag/ชื่อไฟล์กับเวอร์ชันจริงเสมอ (`--help`, `ls`)
- ใช้กับเป้าหมายที่มีสิทธิ์เท่านั้น เคารพ scope และ rate limit
- เอกสารนี้ครอบเฉพาะ reconnaissance และ asset inventory โดยเจตนา ไม่รวมเนื้อหา exploitation

_จบคู่มือ_
