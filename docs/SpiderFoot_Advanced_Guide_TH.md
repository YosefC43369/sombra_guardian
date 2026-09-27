# SpiderFoot Advanced OSINT Field Manual

> Advanced Practical Field Manual ภาษาไทยสำหรับ SpiderFoot — เน้น CLI, Module, Scan Workflow, Event Analysis, Correlation, Automation และ Reporting ทุกคำสั่งตรวจกับ SpiderFoot 4.0.0 สำหรับงาน OSINT และ Defensive Intelligence บนระบบของตนเอง, Lab, CTF, องค์กรที่ได้รับอนุญาต และข้อมูลสาธารณะเท่านั้น

## สารบัญ

- [1. Introduction](#1-introduction)
- [2. Environment Preparation](#2-environment-preparation)
- [3. SpiderFoot Installation](#3-spiderfoot-installation)
- [4. SpiderFoot CLI](#4-spiderfoot-cli)
- [5. SpiderFoot Web UI](#5-spiderfoot-web-ui)
- [6. Configuration](#6-configuration)
- [7. Modules Architecture](#7-modules-architecture)
- [8. Module Management](#8-module-management)
- [9. Scan Profiles](#9-scan-profiles)
- [10. Target Types](#10-target-types)
- [11. Domain Intelligence](#11-domain-intelligence)
- [12. DNS Intelligence](#12-dns-intelligence)
- [13. Subdomain Enumeration](#13-subdomain-enumeration)
- [14. IP Intelligence](#14-ip-intelligence)
- [15. ASN Intelligence](#15-asn-intelligence)
- [16. Netblock Intelligence](#16-netblock-intelligence)
- [17. WHOIS](#17-whois)
- [18. Certificate Intelligence](#18-certificate-intelligence)
- [19. Email Intelligence](#19-email-intelligence)
- [20. Username Intelligence](#20-username-intelligence)
- [21. Person Intelligence](#21-person-intelligence)
- [22. Organization Intelligence](#22-organization-intelligence)
- [23. Website Intelligence](#23-website-intelligence)
- [24. URL Intelligence](#24-url-intelligence)
- [25. Web Technology Discovery](#25-web-technology-discovery)
- [26. Public Infrastructure Discovery](#26-public-infrastructure-discovery)
- [27. Cloud Infrastructure OSINT](#27-cloud-infrastructure-osint)
- [28. Search Engine Intelligence](#28-search-engine-intelligence)
- [29. Social Media Intelligence](#29-social-media-intelligence)
- [30. Dark Web / Onion Intelligence](#30-dark-web--onion-intelligence)
- [31. Breach Intelligence](#31-breach-intelligence)
- [32. Threat Intelligence](#32-threat-intelligence)
- [33. Malware Intelligence](#33-malware-intelligence)
- [34. IOC Investigation](#34-ioc-investigation)
- [35. Reputation Intelligence](#35-reputation-intelligence)
- [36. Passive DNS](#36-passive-dns)
- [37. Certificate Transparency](#37-certificate-transparency)
- [38. Geolocation-related Intelligence](#38-geolocation-related-intelligence)
- [39. Cryptocurrency-related Intelligence](#39-cryptocurrency-related-intelligence)
- [40. Metadata Intelligence](#40-metadata-intelligence)
- [41. Event Correlation](#41-event-correlation)
- [42. False Positive Analysis](#42-false-positive-analysis)
- [43. Graph-Oriented Analysis](#43-graph-oriented-analysis)
- [44. Investigation Workflow](#44-investigation-workflow)
- [45. Advanced Scan Configuration](#45-advanced-scan-configuration)
- [46. Module Dependency Analysis](#46-module-dependency-analysis)
- [47. API Integration](#47-api-integration)
- [48. API Key Management](#48-api-key-management)
- [49. Rate Limits](#49-rate-limits)
- [50. OPSEC](#50-opsec)
- [51. Automation](#51-automation)
- [52. CLI Automation](#52-cli-automation)
- [53. Scripting](#53-scripting)
- [54. JSON Output](#54-json-output)
- [55. CSV Output](#55-csv-output)
- [56. Database / Storage](#56-database--storage)
- [57. Data Processing](#57-data-processing)
- [58. Export](#58-export)
- [59. Reporting](#59-reporting)
- [60. Evidence Handling](#60-evidence-handling)
- [61. Integration with Other OSINT Tools](#61-integration-with-other-osint-tools)
- [62. Threat Intelligence Workflow](#62-threat-intelligence-workflow)
- [63. Infrastructure Investigation](#63-infrastructure-investigation)
- [64. Corporate OSINT Workflow](#64-corporate-osint-workflow)
- [65. Digital Investigation Workflow](#65-digital-investigation-workflow)
- [66. Large-Scale Investigation](#66-large-scale-investigation)
- [67. Performance Optimization](#67-performance-optimization)
- [68. Troubleshooting](#68-troubleshooting)
- [69. Security Hardening](#69-security-hardening)
- [70. Practical Case Studies](#70-practical-case-studies)
- [71. Advanced Workflows](#71-advanced-workflows)
- [72. Command Reference](#72-command-reference)
- [73. Final Checklist](#73-final-checklist)

## 1. Introduction
### 1.1 คู่มือนี้คืออะไร
Field Manual สำหรับผู้ที่ใช้ SpiderFoot เป็นอยู่แล้ว และต้องการใช้ในระดับ Advanced ตั้งแต่เลือก Module, ควบคุม Scan, วิเคราะห์ Event, เขียน Correlation Rule, ทำ Automation ไปจนถึงออกรายงาน

ลำดับการเขียนในทุกบท: `COMMAND > PROCEDURE > EXAMPLE > OUTPUT > EXPLANATION`

### 1.2 Baseline Version ที่ใช้ตรวจสอบ
ทุกคำสั่ง, Option, ชื่อ Module, Event Type, Endpoint และ Database Table ในคู่มือนี้ตรวจกับ Source Code ของ **SpiderFoot 4.0.0** (Repository `smicallef/spiderfoot`, branch `master`) และทดสอบรันจริงบนเครื่องทดสอบ
- `sf.py` — ตัวหลัก ใช้รัน Scan ผ่าน CLI หรือเปิด Web UI
- `sfcli.py` — CLI Client แบบ Interactive ที่คุยกับ Web UI Server
- 230 Module (ไม่นับ Storage module), 171 Event Type (ไม่นับ `ROOT`), 37 Correlation Rule

> **หมายเหตุ:** Syntax อาจแตกต่างกันตาม SpiderFoot Version ที่ติดตั้งอยู่ ตรวจเวอร์ชันของคุณด้วย `python3 sf.py -V` ก่อนใช้คำสั่งในคู่มือ ถ้าเป็นเวอร์ชันอื่น ให้ตรวจ `--help`, `-M` และ `-T` ของเครื่องตัวเองเสมอ

### 1.3 สถาปัตยกรรมที่ต้องเข้าใจก่อนใช้ระดับ Advanced
```
Target (Seed)
   │  sf.py ตรวจชนิด Target → สร้าง Event เริ่มต้น (ROOT)
   ▼
Module A ──produces──> Event X ──watched by──> Module B ──> Event Y ...
   │
   ▼
sfp__stor_db  → SQLite (tbl_scan_results)
sfp__stor_stdout → หน้าจอ (เฉพาะ sf.py CLI)
   │
   ▼  (หลัง Scan จบ)
Correlation Rules (YAML) → tbl_scan_correlation_results
   │
   ▼
Web UI / sfcli.py / Export (CSV, JSON, Excel, GEXF)
```
หลักคิดสำคัญ:
- SpiderFoot เป็นระบบ **Publish/Subscribe ตาม Event Type** — Module แต่ละตัวประกาศว่า "รับ Event ชนิดใด" และ "ผลิต Event ชนิดใด"
- Scan ขยายตัวเองได้ เพราะ Event ที่ Module หนึ่งสร้าง จะไปกระตุ้น Module อื่นต่อ
- การควบคุม Scan จึงเท่ากับการควบคุม **ชุด Module** และ **ชนิด Event** ที่ยอมให้ไหล

### 1.4 Intelligence Cycle ที่ใช้ในคู่มือ
```
Collection → Processing → Correlation → Validation → Analysis → Reporting
```
รายละเอียดการ Map แต่ละขั้นกับ SpiderFoot ดูบท 44

### 1.5 ขอบเขตการใช้งาน
> **คำเตือน:** คู่มือนี้เป็นคู่มือ OSINT และ Defensive Intelligence ใช้กับระบบของตนเอง, Lab, CTF, องค์กรที่ได้รับอนุญาตเป็นลายลักษณ์อักษร และข้อมูลสาธารณะเท่านั้น คู่มือนี้ไม่มีขั้นตอนสำหรับการเข้าถึงโดยไม่ได้รับอนุญาต, Credential Theft, Account Takeover, Malware Deployment, Persistence, DDoS, Data Theft, Exploitation หรือการหลบเลี่ยงระบบรักษาความปลอดภัย

ข้อมูลตัวอย่างทั้งหมดใช้ค่าที่สงวนไว้สำหรับเอกสาร:
```
Domain  : example.com  example.org  example.net  (และ subdomain เช่น test.example.org)
IPv4    : 192.0.2.0/24  198.51.100.0/24  203.0.113.0/24
IPv6    : 2001:db8::/32
ASN     : 64496–64511
Email   : alice@example.com
Username: alice_example
Person  : "Alice Example" (ชื่อสมมติ)
Phone   : +6620000000 (ค่าสมมติ)
```
ผลลัพธ์ตัวอย่างในคู่มือเป็นค่าที่ปรับให้เป็นค่าสงวน เพื่อแสดง "รูปแบบ" ของผลลัพธ์ ไม่ใช่ผลจริงของเป้าหมายใด

## 2. Environment Preparation
### 2.1 ตรวจเครื่อง
```bash
uname -a
cat /etc/os-release | head -3
python3 --version
free -h
df -h ~
nproc
```
- SpiderFoot 4.0 เป็น Python 3 ตรวจว่ามี `python3` และ `pip`
- Scan ขนาดใหญ่ใช้ RAM และดิสก์มาก (SQLite โตเร็ว) ดูบท 56 และ 67

### 2.2 เครื่องมือเสริมที่ใช้ทั้งคู่มือ
```bash
sudo apt update
sudo apt install -y git python3-venv python3-pip jq sqlite3 curl wget \
  dnsutils whois csvkit
```
- `jq` — ประมวลผล JSON
- `sqlite3` — Query ฐานข้อมูลของ SpiderFoot โดยตรง
- `dnsutils` (`dig`, `nslookup`), `whois` — ตรวจยืนยันผลแบบอิสระ
- `csvkit` — จัดการ CSV ที่มี Comma/Newline ในข้อมูล (ถ้า Package ไม่มีในระบบ ใช้ `pip install csvkit`)

### 2.3 แยก Data Directory ต่อ Case
SpiderFoot อ่าน Environment Variable สามตัวเพื่อกำหนดที่เก็บข้อมูล (ตรวจจาก `spiderfoot/helpers.py`):

| Variable | ค่า Default | เก็บอะไร |
|---|---|---|
| `SPIDERFOOT_DATA` | `~/.spiderfoot/` | `spiderfoot.db`, `passwd`, `spiderfoot.key/.crt` |
| `SPIDERFOOT_LOGS` | `~/.spiderfoot/logs` | `spiderfoot.debug.log`, `spiderfoot.error.log` |
| `SPIDERFOOT_CACHE` | `~/.spiderfoot/cache` | Cache ของ Module |

ใช้ตัวแปรเหล่านี้แยกฐานข้อมูลของแต่ละ Case ไม่ให้ปนกัน:
```bash
CASE=CASE-2026-010-example
mkdir -p ~/cases/$CASE/{sfdata,logs,cache,exports,evidence,notes,raw}
export SPIDERFOOT_DATA=~/cases/$CASE/sfdata
export SPIDERFOOT_LOGS=~/cases/$CASE/logs
export SPIDERFOOT_CACHE=~/cases/$CASE/cache
env | grep SPIDERFOOT_
```
ผลลัพธ์:
```
SPIDERFOOT_DATA=/home/kali/cases/CASE-2026-010-example/sfdata
SPIDERFOOT_LOGS=/home/kali/cases/CASE-2026-010-example/logs
SPIDERFOOT_CACHE=/home/kali/cases/CASE-2026-010-example/cache
```
> **หมายเหตุ:** API Key และการตั้งค่าที่บันทึกผ่าน Web UI จะอยู่ใน `spiderfoot.db` ของ Data Directory นั้น ถ้าเปลี่ยน `SPIDERFOOT_DATA` ต้องนำเข้า API Key ใหม่ (บท 48)

### 2.4 ไฟล์บันทึก Case
```bash
cat > ~/cases/$CASE/notes/scope.md << 'EOF'
Case: CASE-2026-010-example
Authorization: <เลขที่หนังสืออนุญาต>
In-scope: example.com, 203.0.113.0/24
Out-of-scope: third-party SaaS, บุคคลภายนอก
Allowed modules: passive only (ห้าม invasive)
Analyst: <ชื่อ>
EOF
```

## 3. SpiderFoot Installation
### 3.1 วิธีที่ 1 — Kali Package
```bash
sudo apt update
sudo apt install -y spiderfoot
dpkg -L spiderfoot | grep bin/
```
- บน Kali โดยทั่วไป Package จะให้คำสั่ง Wrapper สำหรับ `sf.py` และ `sfcli.py` ให้ดูชื่อจริงจากผล `dpkg -L` (มักเป็น `spiderfoot` และ `spiderfoot-cli`)
- ถ้าใช้ Kali Package ให้แทน `python3 sf.py` ในคู่มือด้วยคำสั่ง Wrapper นั้น

ตรวจด้วย `spiderfoot -V` → ถ้าเป็น 4.0 จะเห็น `SpiderFoot 4.0.0: Open Source Intelligence Automation.`

### 3.2 วิธีที่ 2 — Source + Virtualenv (แนะนำสำหรับงาน Advanced)
```bash
mkdir -p ~/tools && cd ~/tools
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python3 sf.py -V
```
- Virtualenv แยก Dependency ไม่ให้ชนกับ Python ของระบบ
- ต้อง `cd` ไปที่โฟลเดอร์ `spiderfoot` ก่อนรัน `sf.py` เพราะ Module และ Correlation Rule ถูกโหลดจากโฟลเดอร์ `modules/` และ `correlations/` ที่อยู่ข้าง `sf.py`

ทำ Wrapper Script ให้เรียกจากที่ไหนก็ได้:
```bash
mkdir -p ~/bin
cat > ~/bin/sf << 'EOF'
#!/usr/bin/env bash
cd ~/tools/spiderfoot && exec .venv/bin/python sf.py "$@"
EOF
chmod +x ~/bin/sf
sf -V
```
คู่มือนี้ใช้ `python3 sf.py` เป็นรูปแบบหลัก (รันจากโฟลเดอร์ SpiderFoot ที่เปิด venv แล้ว)

### 3.3 วิธีที่ 3 — Docker
```bash
cd ~/tools/spiderfoot
docker build -t spiderfoot .
docker volume create spiderfoot-data
docker run -d --name spiderfoot \
  -p 127.0.0.1:5001:5001 \
  -v spiderfoot-data:/var/lib/spiderfoot \
  spiderfoot
docker logs spiderfoot | tail -5
```
- `Dockerfile` ตั้ง `SPIDERFOOT_DATA=/var/lib/spiderfoot` และรัน `sf.py -l 0.0.0.0:5001` ภายใน Container
- `-p 127.0.0.1:5001:5001` ผูก Port ไว้ที่ Localhost ของเครื่อง Host เท่านั้น
- `Dockerfile.full` และ `docker-compose-full.yml` เป็นรุ่นที่ติดตั้งเครื่องมือภายนอก (สำหรับ Module ที่ขึ้นต้นด้วย `sfp_tool_`)

> **คำเตือน:** `docker-compose.yml` ใน Repository ใช้ `ports: - "5001:5001"` ซึ่งเปิดทุก Interface ของ Host ถ้าใช้ docker compose ให้แก้เป็น `"127.0.0.1:5001:5001"` ก่อน (บท 69)

รัน CLI Scan ใน Container:
```bash
docker exec -it spiderfoot /opt/venv/bin/python sf.py -V
```

### 3.4 Update
```bash
cd ~/tools/spiderfoot
git fetch --tags
git log --oneline -1
git pull
. .venv/bin/activate && pip install -r requirements.txt
python3 sf.py -V
```
- สำรอง `spiderfoot.db` ก่อน Update ทุกครั้ง (บท 56)
- Module ที่เปลี่ยนชื่อหรือถูกลบใน Version ใหม่ จะทำให้ Script อัตโนมัติที่ระบุ `-m` ล้มเหลว ให้ตรวจรายชื่อด้วย `-M` หลัง Update

### 3.5 ตรวจการติดตั้งแบบครบ
```bash
python3 sf.py -V
python3 sf.py -M 2>/dev/null | wc -l
python3 sf.py -T 2>/dev/null | wc -l
ls correlations/*.yaml | grep -v template | wc -l
```
ผลลัพธ์บน 4.0.0:
```
SpiderFoot 4.0.0: Open Source Intelligence Automation.
230
171
37
```

## 4. SpiderFoot CLI
SpiderFoot มี CLI สองแบบ แยกให้ชัดก่อน:

| ตัว | ทำงานอย่างไร | ใช้เมื่อ |
|---|---|---|
| `sf.py` | รัน Scan ในโปรเซสตัวเอง แสดงผลทาง stdout และเก็บลง DB | Automation, Pipeline, Scan ครั้งเดียว |
| `sfcli.py` | Client ที่คุยกับ Web UI Server ผ่าน HTTP | จัดการ Scan หลายตัวบน Server, ดูผล, Export |

### 4.1 Option ทั้งหมดของ `sf.py` (4.0.0)
```
-h, --help          Help
-d, --debug         Debug output
-l IP:port          เปิด Web UI Server
-m mod1,mod2,...    เลือก Module เอง
-M, --modules       แสดงรายชื่อ Module
-C scanID           รัน Correlation Rules กับ Scan ที่มีอยู่
-s TARGET           Target ของ Scan
-t type1,type2,...  เลือกชนิด Event ที่ต้องการ (เลือก Module อัตโนมัติ)
-u {all,footprint,investigate,passive}  เลือก Module ตาม Use Case
-T, --types         แสดงรายชื่อ Event Type
-o {tab,csv,json}   รูปแบบ Output (Default: tab)
-H                  ไม่พิมพ์ Header (tab/csv)
-n                  ตัด Newline ในข้อมูล
-r                  แสดง Source Data (tab/csv)
-S LENGTH           จำกัดความยาวข้อมูลที่แสดง
-D DELIMITER        ตัวคั่น CSV (ใช้กับ -o csv เท่านั้น)
-f                  กรอง Event ที่ไม่ได้ขอด้วย -t ออก
-F type1,type2,...  แสดงเฉพาะ Event Type ที่ระบุ
-x                  STRICT MODE (ใช้กับ -t เท่านั้น)
-q                  ปิด Logging (ซ่อน Error ด้วย)
-V, --version       แสดงเวอร์ชัน
-max-threads N      จำนวน Module ที่รันพร้อมกันสูงสุด
```
> **หมายเหตุ:** `-max-threads` ใช้ขีดเดียวตามที่ประกาศใน Source ของ 4.0 (ไม่ใช่ `--max-threads`)

### 4.2 Version / Help
- **Command:** `python3 sf.py -V` / `python3 sf.py --help`
- **Purpose:** ยืนยัน Version และ Option ที่เครื่องนี้รองรับจริง
- **Expected Result:** `SpiderFoot 4.0.0: Open Source Intelligence Automation.`
- **Common Error:** `ModuleNotFoundError: No module named 'cherrypy'` → ยังไม่ได้เปิด venv หรือยังไม่ได้ `pip install -r requirements.txt`

### 4.3 แสดงรายชื่อ Module และ Event Type
```bash
python3 sf.py -M 2>/dev/null | head -3
python3 sf.py -T 2>/dev/null | grep -E '^(IP_ADDRESS|INTERNET_NAME|EMAILADDR) '
```
- **Purpose:** หาชื่อ Module และชื่อ Event Type ที่ถูกต้องก่อนใส่ใน `-m`, `-t`, `-F`
- **Expected Result:**

```
sfp_abstractapi            Look up domain, phone and IP address information from AbstractAPI.
sfp_abusech                Check if a host/domain, IP address or netblock is malicious according to Abuse.ch.
sfp_abuseipdb              Check if an IP address is malicious according to AbuseIPDB.com blacklist.
EMAILADDR                                      Email Address
INTERNET_NAME                                  Internet Name
IP_ADDRESS                                     IP Address
```
- **Common Error:** ใช้ชื่อ Event แบบคำอธิบาย (เช่น `IP Address`) ใน `-t` → ต้องใช้ชื่อแบบรหัส (`IP_ADDRESS`)

> **หมายเหตุ:** `2>/dev/null` ซ่อนข้อความ Log ที่ออกทาง stderr ให้เหลือเฉพาะรายการ

### 4.4 Scan ด้วย Module ที่เลือกเอง (`-s` + `-m`)
```bash
python3 sf.py -s example.com -m sfp_dnsresolve,sfp_dnsraw -q
```
- **Purpose:** ควบคุม Scan แบบแม่นยำที่สุด รันเฉพาะ Module ที่ระบุ
- **Parameter:** `-s` Target, `-m` รายชื่อ Module คั่นด้วย Comma (ไม่มีช่องว่าง)
- **Expected Result (รูปแบบ tab):**

```
Source                        	Type                                         	Data
SpiderFoot UI                 	Internet Name                                	example.com
SpiderFoot UI                 	Domain Name                                  	example.com
sfp_dnsraw                    	Name Server (DNS NS Records)                 	ns1.example.net
sfp_dnsraw                    	DNS SPF Record                               	v=spf1 -all
sfp_dnsresolve                	IP Address                                   	203.0.113.10
```
- **Common Error:** ใส่ชื่อ Module ผิด → Scan เริ่มแต่ Module นั้นไม่ถูกโหลด ให้ดูบรรทัด `Modules enabled (N): ...` ใน Log (อย่าใช้ `-q` ตอนทดสอบ)

> **คำเตือน:** ถ้ารัน `sf.py -s <target>` โดย **ไม่ระบุ** `-m`, `-t` หรือ `-u` SpiderFoot จะแจ้ง `You didn't specify any modules, types or use case, so all modules will be enabled.` และเปิด **ทุก Module** รวมถึง Module ที่มี Flag `invasive` เช่น Port Scanner ห้ามทำกับเป้าหมายที่ไม่ได้รับอนุญาต

### 4.5 Scan ตาม Use Case (`-u`)
```bash
python3 sf.py -s example.com -u passive -o json -q > ~/cases/$CASE/raw/passive.json
```
- **Purpose:** เลือก Module ตามกลุ่มที่ผู้พัฒนากำหนดใน `meta.useCases` ของแต่ละ Module
- **Parameter:** `all`, `footprint`, `investigate`, `passive` (ตัวพิมพ์เล็ก — `sf.py` แปลงตัวแรกเป็นตัวใหญ่ให้เอง)
- **Expected Result:** JSON Array ของ Event
- **Common Error:** Scan แบบ `passive` ยังเปิด Module จำนวนมาก (รวม Module ที่ต้องใช้ API Key) Module ที่ไม่มี Key จะแจ้ง Error ใน Log แต่ Scan ยังเดินต่อ

> **หมายเหตุ:** "Passive" ในความหมายของ SpiderFoot คือ Module ที่ **ไม่ติดต่อเป้าหมายโดยตรง** แต่ยังส่งข้อมูลเป้าหมายไปยังบริการภายนอก (API Provider) ดูบท 50 ส่วน `-u footprint` และ `-u investigate` มี Module `invasive` รวมอยู่ด้วย (`-u passive` ไม่มี)

### 4.6 Scan ตามชนิดข้อมูลที่ต้องการ (`-t`)
```bash
# ใช้กับ Asset ที่ได้รับอนุญาตให้ทำ Active scan เท่านั้น
python3 sf.py -s <AUTHORIZED_DOMAIN> -t INTERNET_NAME,IP_ADDRESS -f -q
```
- **Purpose:** บอกว่า "ต้องการข้อมูลชนิดนี้" แล้วให้ SpiderFoot เลือก Module ที่ผลิต Event นั้น **รวมถึง Module ที่ผลิต Input ของ Module เหล่านั้นแบบวนซ้ำ**
- **Parameter:** `-t` รายชื่อ Event Type, `-f` แสดงเฉพาะชนิดที่ขอ
- **Expected Result:** รายการ Internet Name และ IP Address
- **Common Error:** `-f` ใช้ได้เฉพาะคู่กับ `-t` (ไม่งั้นได้ `You can only use -f with -t.`)

> **คำเตือน (คำนวณจาก Logic ของ 4.0.0):** `-t IP_ADDRESS,IPV6_ADDRESS` เปิด **148 Module** และ `-t MALICIOUS_IPADDR` เปิด **181 Module** ทั้งสองกรณีรวม `sfp_portscan_tcp`, `sfp_tool_nmap`, `sfp_tool_nuclei` (Flag `invasive`) และ `sfp_dnsbrute` เพราะ Module เหล่านี้ผลิต Event ที่ `sfp_dnsresolve` รับได้ ห้ามใช้ `-t` โดยไม่มี `-x` กับเป้าหมายที่ไม่ได้อนุญาต Active scan ให้ตรวจรายการ Module ก่อนด้วย Dry-run ในบท 46.2 หรือใช้ `-m` / `-x` แทน

### 4.7 Strict Mode (`-x`)
```bash
python3 sf.py -s 203.0.113.10 -t MALICIOUS_IPADDR,BLACKLISTED_IPADDR -x -q
```
- **Purpose:** เปิดเฉพาะ Module ที่ **รับ Target ได้โดยตรง** และ **ผลิตชนิดที่ขอ** แล้วกรอง Output ของทุก Module ให้เหลือเฉพาะชนิดที่ขอ ทำให้ Scan ไม่ขยายตัว
- **Parameter:** ต้องใช้คู่กับ `-t` และห้ามใช้กับ `-m`
- **Expected Result:** เฉพาะ Event ชนิด `MALICIOUS_IPADDR` / `BLACKLISTED_IPADDR` (ถ้ามี)
- **Common Error:**

```
-x can only be used with -t. Use --help for guidance.
-x can only be used with -t and not with -m. Use --help for guidance.
Based on your criteria, no modules were enabled.
```
ข้อความสุดท้ายแปลว่าไม่มี Module ใดที่รับ Target ชนิดนี้และผลิตชนิดที่ขอพร้อมกัน

### 4.8 Output Format
```bash
# JSON
python3 sf.py -s example.com -m sfp_dnsraw -o json -q > out.json
# CSV พร้อม Source Data และตัด Newline
python3 sf.py -s example.com -m sfp_dnsraw -o csv -r -n -q > out.csv
# Tab ไม่มี Header, แสดงเฉพาะบางชนิด
python3 sf.py -s example.com -m sfp_dnsresolve -F IP_ADDRESS,IPV6_ADDRESS -H -q
```
กฎที่ตรวจจาก Source:
- `-r` และ `-H` ใช้ได้กับ `tab` และ `csv` เท่านั้น
- `-D` ใช้ได้กับ `csv` เท่านั้น
- ข้อมูลที่พิมพ์ทาง stdout คือผลลัพธ์ ส่วน Log ออกทาง stderr → Redirect แยกได้

> **คำเตือน (พบจากการทดสอบ 4.0.0):** `-o csv` **โดยไม่ใส่** `-r` จะพิมพ์ Header 3 คอลัมน์ (`Source,Type,Data`) แต่ทุกแถวมี 4 ฟิลด์ (มี Source Data อยู่ด้วยเสมอ) ทำให้โปรแกรมอ่าน CSV เลื่อนคอลัมน์ ให้ใช้ `-o csv -r` ทุกครั้ง Header จะเป็น `Source,Type,Source Data,Data` และตรงกับข้อมูล

รายละเอียดโครงสร้าง JSON/CSV ดูบท 54 และ 55

### 4.9 Logging และ Debugging
```bash
# Log ปกติไปไฟล์ ผลลัพธ์ไปอีกไฟล์
python3 sf.py -s example.com -m sfp_dnsraw -o json > out.json 2> scan.log
# Debug เต็ม
python3 sf.py -s example.com -m sfp_dnsraw -d 2> debug.log
# Log ที่ SpiderFoot เขียนเอง
ls -l $SPIDERFOOT_LOGS/
tail -f $SPIDERFOOT_LOGS/spiderfoot.error.log
```
- `-q` ปิด Log ทั้งหมด รวมถึง Error — ใช้เฉพาะเมื่อ Pipeline ทดสอบผ่านแล้ว
- `-d` เปิด Debug ช่วยดู Request ที่ Module ส่งออกไป
- Log บนหน้าจอขึ้นต้นด้วยรูปแบบ `YYYY-MM-DD HH:MM:SS,ms [LEVEL] component : message`

ตัวอย่าง Log:
```
2026-09-25 20:25:42,652 [INFO] sf : Modules enabled (3): sfp_dnsraw,sfp__stor_db,sfp__stor_stdout
2026-09-25 20:25:43,466 [INFO] sflib : Scan [1FEBE309] for 'example.com' initiated.
```
`1FEBE309` คือ **Scan ID** ใช้ต่อกับ `-C`, Web UI และ `sfcli.py`

### 4.10 Concurrency (`-max-threads`)
```bash
python3 sf.py -s example.com -u passive -max-threads 2 -o json -q > out.json
```
- **Purpose:** จำกัดจำนวน Module ที่ทำงานพร้อมกัน (ค่า Global `_maxthreads` Default = 3)
- ลดค่าเมื่อเจอ Rate Limit หรือเครื่องทรัพยากรน้อย เพิ่มค่าเมื่อ Scan ช้าและ Provider รับไหว (บท 67)

### 4.11 Correlation ภายหลัง (`-C`)
```bash
python3 sf.py -C 1FEBE309
```
- **Purpose:** รัน Correlation Rules ใหม่กับ Scan เดิม เช่น หลังเพิ่ม Rule ที่เขียนเอง
- **Expected Result:** Log `Running 37 correlation rules against scan, 1FEBE309.` แล้วจบ ผลไปดูใน Web UI หรือ `sfcli.py correlations`
- **Common Error:** Scan ID อยู่คนละ Database → ตรวจ `SPIDERFOOT_DATA` ให้ชี้ Database เดียวกับตอน Scan

> **หมายเหตุ:** ปกติ Correlation รันอัตโนมัติหลัง Scan จบอยู่แล้ว (Log: `Running 37 correlation rules on scan ...`) ใช้ `-C` เมื่อต้องการรันซ้ำ

### 4.12 เปิด Web UI Server (`-l`)
```bash
python3 sf.py -l 127.0.0.1:5001
```
- **Expected Result:** ข้อความให้เปิด Browser ไปที่ `http://127.0.0.1:5001/` และ Log `Starting web server at 127.0.0.1:5001 ...`
- **Common Error:** `Invalid ip:port format.` → ต้องมีทั้ง IP และ Port / Port ถูกใช้อยู่ → ดูบท 68

### 4.13 การหยุด Scan ของ `sf.py`
- กด `Ctrl+C` — SpiderFoot ตั้งสถานะ Scan เป็น `ABORTED` ใน Database แล้วออกทันที (Exit code ไม่เป็น 0)
- Event ที่บันทึกลง Database ไปแล้วยังอยู่ ดูต่อใน Web UI ได้ แต่ Correlation อาจไม่ได้รัน ให้สั่ง `-C <scanID>` เอง
- รัน `sf.py` โดยไม่ใส่ Argument เลย จะได้ข้อความ `SpiderFoot requires -l <ip>:<port> to start the web server.`

### 4.14 `sfcli.py` — Option
```
-d, --debug     Debug
-s URL          URL ของ Server (Default: http://127.0.0.1:5001)
-u USER         Username
-p PASS         Password (ไม่แนะนำ — เห็นใน Process list)
-P PASSFILE     ไฟล์ Password (แนะนำ)
-e FILE         รันคำสั่งจากไฟล์
-l FILE         ไฟล์ History (Default: ~/.spiderfoot_history)
-n              ปิด History
-o FILE         Spool คำสั่งและผลลัพธ์ลงไฟล์
-i              ยอมรับ SSL ที่ไม่ผ่านการตรวจ
-q              Silent (แสดงเฉพาะ Error)
-k              ปิดสี
-b, -v          แสดง Banner/Version แล้วออก
```

### 4.15 `sfcli.py` — คำสั่ง
```
ping                                   ตรวจว่า Server ตอบ
modules | types | correlationrules    รายการ Module / Event Type / Rule
scans [-x]                             รายการ Scan
start <target> (-m m1,..|-t t1,..|-u case) [-n name] [-w]
stop <sid>                             Abort Scan
delete <sid>                           ลบ Scan
scaninfo <sid> [-c]                    สถานะ (+ Config ของ Scan ถ้าใส่ -c)
data <sid> [-t type] [-x] [-u]         ดูผล (-u = Unique, -x = Extended)
summary <sid> [-t]                     สรุปตามชนิด
correlations <sid> [-c correlation_id] ผล Correlation
find "<string|/regex/>" <[-s sid]|[-t type]> [-x]
export <sid> [-t type] [-f file]       type = csv | json | gexf (default json)
logs <sid> [-l count] [-w]             ดู/ติดตาม Log
set [opt [= <val>]]                    ดู/ตั้งค่า
query <SQL>                            รัน SQL กับ Database
load <file> | shell | history | spool | debug | clear | exit
```
Pipe ที่ใช้ต่อท้ายผลลัพธ์ได้: `| str <text>`, `| grep <text>`, `| regex <pattern>`, `| top N`, `| last N`, `| file <path>`

ตัวอย่าง Session:
```bash
python3 sfcli.py -s http://127.0.0.1:5001 -n
```

```
sf> ping
[*] Server http://127.0.0.1:5001 responding.
sf> start example.com -m sfp_dnsraw,sfp_dnsresolve -n dns-baseline
[*] Successfully initiated scan.
[*] Scan ID: 143B53FF
sf> data 143B53FF -t PROVIDER_DNS
Data                        Type
---------------------------+--------------
ns1.example.net            | PROVIDER_DNS
ns2.example.net            | PROVIDER_DNS
sf> find "*example.net*" -s 143B53FF
sf> export 143B53FF -t json -f /home/kali/cases/CASE-2026-010-example/exports/dns-baseline.json
sf> types | top 3
```

### 4.16 Quirk ของ `sfcli.py` ที่พบจากการทดสอบ 4.0.0
1. **Use Case ต้องขึ้นต้นตัวใหญ่** — `start example.org -u passive` ได้ `Incorrect usage: no modules specified for scan.` เพราะ Server เทียบกับค่า `Passive` แบบตรงตัว ให้ใช้ `-u Passive`, `-u Footprint`, `-u Investigate` หรือ `-u all`
2. **`-e FILE` ล้มเหลว** — ได้ `AttributeError: 'str' object has no attribute 'readline'` ให้ส่งคำสั่งทาง stdin แทน:

```bash
cat > cmds.txt << 'EOF'
scans
data 143B53FF -t IP_ADDRESS -u
EOF
python3 sfcli.py -s http://127.0.0.1:5001 -n -k < cmds.txt
```
3. **`find` ตรงตัว** — `find "example"` หาเฉพาะค่าที่เท่ากันพอดี ใช้ `*` เป็น Wildcard (`"*example*"`) หรือ `/regex/`
4. **`set` ใช้ชื่อแบบมีคำนำหน้า** — `global._maxthreads`, `module.sfp_virustotal.api_key` (ดูบท 6.4)

## 5. SpiderFoot Web UI
### 5.1 เปิดใช้งาน
```bash
cd ~/tools/spiderfoot && . .venv/bin/activate
export SPIDERFOOT_DATA=~/cases/$CASE/sfdata
python3 sf.py -l 127.0.0.1:5001
```
เปิด Browser ไปที่ `http://127.0.0.1:5001/` แถบเมนูด้านบนมี **New Scan**, **Scans**, **Settings**

ตรวจจาก Terminal อีกหน้าต่าง: `curl -s http://127.0.0.1:5001/ping` → `["SUCCESS", "4.0.0"]`

### 5.2 New Scan — ขั้นตอนคลิกจริง
1. คลิก **New Scan**
2. **Scan Name** — ตั้งชื่อที่ค้นหาได้ภายหลัง เช่น `CASE010-example.com-passive-v1`
3. **Scan Target** — ใส่ Target ตามรูปแบบในบท 10 (Username/ชื่อคนต้องครอบด้วย `"`)
4. เลือกวิธีเลือก Module จาก 3 Tab:
   - **By Use Case** — All / Footprint / Investigate / Passive
   - **By Required Data** — ติ๊กชนิดข้อมูลที่ต้องการ (เทียบเท่า `-t`)
   - **By Module** — ติ๊ก Module ทีละตัว มีปุ่ม **Select All** / **De-Select All**
5. ตรวจ Module ที่ต้องใช้ API Key ว่าตั้ง Key แล้วใน Settings (ข้อ 5.6)
6. คลิก **Run Scan Now**

> **หมายเหตุ:** ถ้าติ๊กทั้งใน By Module และ By Required Data Server จะใช้รายการ Module ก่อน (ตรวจจาก Logic ของ `startscan`) เลือกวิธีเดียวต่อ Scan เพื่อไม่ให้สับสน แท็บ **By Required Data** ใช้การเลือก Module แบบวนซ้ำเหมือน `-t` จึงอาจเปิด Module `invasive` ได้ (บท 4.6)

### 5.3 Scans — หน้ารายการ
แต่ละแถวแสดง Name, Target, Started, Finished, Status, จำนวน Element และจำนวน Correlation ตามระดับ Risk

สถานะที่พบได้:
```
STARTING → STARTED → RUNNING → FINISHED
                             → ABORT-REQUESTED → ABORTED
                             → ERROR-FAILED
```
การจัดการ Scan (เลือก Scan แล้วใช้ปุ่มในหน้ารายการ ตำแหน่งปุ่มอาจต่างตามเวอร์ชัน):
- **Stop** — หยุด Scan ที่กำลังรัน
- **Delete** — ลบ Scan และผลลัพธ์ทั้งหมด
- **Re-run** — รัน Scan ซ้ำด้วยการตั้งค่าเดิม (Endpoint `rerunscan`)
- **Clone** — เปิดหน้า New Scan ที่กรอกค่าเดิมไว้ให้แก้ (Endpoint `clonescan`)
- **Export** — Export หลาย Scan พร้อมกัน

> **หมายเหตุ:** SpiderFoot 4.0 **ไม่มี** Pause/Resume Scan (ไม่มี Endpoint สำหรับฟังก์ชันนี้) ทางเลือกคือ Stop แล้ว Re-run หรือ Clone ใหม่

### 5.4 หน้าผล Scan
คลิกชื่อ Scan จะเห็นแท็บ/ปุ่ม:

| แท็บ | ใช้ทำอะไร |
|---|---|
| **Status** | สรุปจำนวน Event ตามชนิด, สถานะ Scan |
| **Browse** | ดู Event ทีละชนิด ค้นหา Export และตั้ง False Positive |
| **Correlations** | ผล Correlation Rule แยกตาม Risk |
| **Graph** | Visualization ความสัมพันธ์ของ Event |
| **Scan Settings** | Module และ Config ที่ใช้ใน Scan นี้ |
| **Log** | Log ของ Scan ดาวน์โหลดได้ |

### 5.5 Browse — วิเคราะห์ Event
1. แท็บ **Browse** → คลิกชนิด Event เช่น `Internet Name`
2. สลับ **Full Data View** / **Unique Data View** (Unique = ตัดค่าซ้ำ)
3. ช่อง **Search** — ค้นหาในผลลัพธ์ของชนิดนั้น
4. ปุ่ม **Set/Unset False Positive flag** — เลือกแถวแล้วตั้ง FP (Event ลูกจะถูกตั้ง FP ตามไปด้วย)
5. **Hide False Positives** — ซ่อนแถวที่ตั้ง FP แล้ว
6. ปุ่ม **Export Data** — ดาวน์โหลดข้อมูลที่กำลังดูเป็น CSV / Excel

### 5.6 Settings และ API
1. คลิก **Settings**
2. ด้านซ้ายเป็นรายการ **Global** และ Module ทุกตัว
3. คลิก Module เช่น `VirusTotal` → ใส่ `API Key` = `YOUR_API_KEY`
4. คลิก **Save Changes**
5. ปุ่มอื่น: **Import API Keys**, **Export API Keys**, **Reset to Factory Default**

> **หมายเหตุ:** ปุ่ม Export API Keys ส่งออก Option **ของทุก Module** (ไม่ใช่เฉพาะ Key) ในรูปแบบ `sfp_xxx:option=value` ส่วน Global Option ที่ขึ้นต้นด้วย `_` จะไม่ถูกส่งออก (ตรวจจาก `optsexport`)

### 5.7 Graph และ Visualization
- แท็บ **Graph** มีปุ่ม **Random Layout**, **Force Layout**, **Save Image**
- ใช้ดูภาพรวม เหมาะกับ Scan ขนาดเล็ก–กลาง Scan ใหญ่จะเป็นก้อนอ่านยาก ให้ Export เป็น GEXF แล้วใช้ Gephi (บท 43)

### 5.8 Database จาก Web UI
- ลบ Scan ที่ไม่ใช้ในหน้า Scans เพื่อลดขนาด Database
- Endpoint `/vacuum` สั่ง SQLite VACUUM เพื่อคืนพื้นที่ (บท 56)

## 6. Configuration
### 6.1 ลำดับการใช้ค่า Config
1. ค่า Default ใน Source (`sf.py` สำหรับ Global, `opts` ในแต่ละ Module)
2. ค่าที่บันทึกใน Database (`tbl_config`) ผ่าน Web UI Settings หรือ `sfcli.py set`
3. ค่าจาก Command-line บางตัว (`-d`, `-max-threads`)

> **หมายเหตุ:** `sf.py` แบบ CLI โหลด Config จาก Database ก่อนเริ่ม Scan (`configUnserialize(dbh.configGet(), ...)`) ดังนั้น API Key ที่ตั้งใน Web UI ใช้กับ CLI Scan ได้ทันที **ถ้าใช้ `SPIDERFOOT_DATA` เดียวกัน**

### 6.2 Global Options (4.0.0)
| Option | Default | ความหมาย |
|---|---|---|
| `_debug` | False | Debug |
| `_maxthreads` | 3 | Module ที่รันพร้อมกัน |
| `_useragent` | Firefox UA string | User-Agent สำหรับ HTTP (ใส่ `@/path/file` เพื่อสุ่มจากไฟล์) |
| `_dnsserver` | ว่าง | DNS Resolver ที่ใช้แทนค่าระบบ |
| `_fetchtimeout` | 5 | Timeout (วินาที) ของ HTTP Request |
| `_internettlds` | URL Public Suffix List | รายชื่อ TLD |
| `_internettlds_cache` | 72 | ชั่วโมงที่ Cache รายชื่อ TLD |
| `_genericusers` | จาก Wordlist | Username ทั่วไป (เช่น info, admin) ที่จัดเป็น Generic |
| `_socks1type` | ว่าง | ชนิด Proxy: `4`, `5`, `HTTP`, `TOR` |
| `_socks2addr` | ว่าง | IP ของ Proxy |
| `_socks3port` | ว่าง | Port ของ Proxy |
| `_socks4user` | ว่าง | Username (SOCKS4/5) |
| `_socks5pwd` | ว่าง | Password (SOCKS5) |

### 6.3 Module Options
ทุก Module มี Option ของตัวเอง ดูได้ 3 ทาง:
```bash
# 1) Web UI → Settings → คลิก Module
# 2) Export ออกมาดูทั้งหมด (Server ต้องรันอยู่)
curl -s http://127.0.0.1:5001/optsexport | grep '^sfp_spider:'
# 3) อ่านจาก Source
grep -A12 "    opts = {" modules/sfp_spider.py
```
ผลลัพธ์ (บางส่วน):
```
sfp_spider:maxlevels=3
sfp_spider:maxpages=100
sfp_spider:nosubs=0
sfp_spider:robotsonly=0
```
Option ที่พบซ้ำในหลาย Module และควรรู้ความหมาย:
- `api_key` — API Key ของ Provider
- `verify` — ตรวจว่า Hostname ที่ได้ยัง Resolve ได้ก่อนรายงาน
- `netblocklookup` / `maxnetblock` — ขยายการค้นหาไปทั้ง Netblock ที่ Target เป็นเจ้าของ จำกัดขนาดสูงสุด (เช่น 24 = ไม่เกิน /24)
- `subnetlookup` / `maxsubnet` — ค้นหาใน Subnet เดียวกับ IP
- `checkaffiliates` / `checkcohosts` — ตรวจ Affiliate และ Co-hosted site ด้วย
- `maxcohost` — จำนวน Co-host สูงสุดก่อนหยุดรายงาน (ป้องกัน Shared hosting)
- `delay` / `pause` — หน่วงเวลาระหว่าง Request (ช่วยเรื่อง Rate Limit)
- `age_limit_days` / `maxage` — ไม่รายงานข้อมูลเก่ากว่ากำหนด

### 6.4 ตั้งค่าผ่าน `sfcli.py`
```
sf> set global._maxthreads
global._maxthreads = 3
sf> set global._fetchtimeout = 10
[*] global._fetchtimeout set to 10
sf> set module.sfp_virustotal.api_key = YOUR_API_KEY
sf> set module.sfp_spider.maxpages = 50
```
- ชื่อ Option ใน `sfcli.py` ใช้รูปแบบ `global.<opt>` และ `module.<module>.<opt>`
- ค่าจะถูกบันทึกลง Database ของ Server ทันที

### 6.5 Proxy / TOR
ตั้งใน Web UI → Settings → Global:
```
SOCKS Server Type : 5        (หรือ TOR / 4 / HTTP)
SOCKS Server IP   : 127.0.0.1
SOCKS Server Port : 1080     (TOR มักใช้ 9050)
```
- ใช้เมื่อนโยบายองค์กรกำหนดให้ออกอินเทอร์เน็ตผ่าน Proxy หรือเมื่อ Module ด้าน Onion ต้องใช้ TOR (บท 30)
- ตรวจผลด้วยการรัน Scan เล็ก ๆ แล้วดู Error ใน Log

### 6.6 เปลี่ยน DNS Resolver
ตั้ง `_dnsserver` เป็น Resolver ขององค์กร เพื่อให้การ Query DNS อยู่ภายใต้การ Log และนโยบายของหน่วยงาน:
```
sf> set global._dnsserver = 192.0.2.53
```
ตรวจว่า Resolver ตอบ: `dig @192.0.2.53 example.com +short`

## 7. Modules Architecture
### 7.1 Metadata ที่ทุก Module ประกาศ
ทุกไฟล์ `modules/sfp_*.py` มีโครงสร้างเดียวกัน (ตรวจจาก `sfp_template.py` และ `spiderfoot/plugin.py`):
```python
meta = {
    'name': "...",                 # ชื่อที่แสดงใน UI
    'summary': "...",              # คำอธิบาย
    'flags': ["apikey"],           # คุณสมบัติพิเศษ
    'useCases': ["Passive", ...],  # Use Case ที่ Module นี้อยู่
    'categories': ["DNS"],         # หมวดหมู่ (1 หมวด)
    'dataSource': {'website': ..., 'model': ..., 'apiKeyInstructions': [...]}
}
opts = {...}                       # Option ที่ปรับได้
def watchedEvents(self): ...       # Event ที่รับ (Input)
def producedEvents(self): ...      # Event ที่ผลิต (Output)
```

### 7.2 Categories (ค่าที่ SpiderFoot 4.0 ยอมรับ)
```
Content Analysis        27 modules
Crawling and Scanning   20
DNS                     10
Leaks, Dumps and Breaches 12
Passive DNS             15
Public Registries        7
Real World              10
Reputation Systems      67
Search Engines          47
Secondary Networks       5
Social Media            10
```

### 7.3 Flags
| Flag | ความหมาย | ผลต่อการใช้งาน |
|---|---|---|
| `apikey` | ต้องมี API Key | ไม่มี Key = Module แจ้ง Error แล้วไม่ทำงาน |
| `slow` | ใช้เวลานาน | ตัดออกเมื่อต้องการ Scan เร็ว |
| `invasive` | ติดต่อเป้าหมายแบบเชิงรุก | ใช้เฉพาะระบบที่ได้รับอนุญาต |
| `errorprone` | ผลลัพธ์มี False Positive สูง | ต้องตรวจซ้ำทุกผล |
| `tool` | เรียกโปรแกรมภายนอก | ต้องติดตั้งโปรแกรมและตั้ง Path |
| `tor` | เกี่ยวกับ Onion/TOR | อาจต้องตั้ง Proxy TOR |

Module ที่มี Flag `invasive` ใน 4.0: `sfp_junkfiles`, `sfp_portscan_tcp`, `sfp_tool_nmap`, `sfp_tool_nuclei`

### 7.4 Data Source Model
ค่า `dataSource.model` บอกเงื่อนไขการใช้บริการ (ข้อมูล ณ เวลาที่เขียน Module อาจเปลี่ยนแล้ว):
```
FREE_NOAUTH_UNLIMITED   ฟรี ไม่ต้องสมัคร
FREE_NOAUTH_LIMITED     ฟรี ไม่ต้องสมัคร มีขีดจำกัด
FREE_AUTH_UNLIMITED     ฟรี ต้องสมัคร
FREE_AUTH_LIMITED       ฟรี ต้องสมัคร มีโควตา
COMMERCIAL_ONLY         ต้องจ่ายเงิน
PRIVATE_ONLY            ต้องขอสิทธิ์เฉพาะ
```
ดู Metadata ของ Module ใดก็ได้ด้วย Script ในบท 8.2

### 7.5 Functional Module Map
ตารางนี้จัดกลุ่ม Module ตาม "งาน" ที่ใช้ในคู่มือ (ไม่ใช่ Category ทางการ) ทุกชื่อตรวจจาก `sf.py -M` ของ 4.0.0 เครื่องหมาย `*` = ต้องมี API Key, `!` = Flag `invasive`
```
[Discovery / Core]
  sfp_dnsresolve sfp_spider sfp_crossref sfp_hosting sfp_similar sfp_tldsearch sfp_tool_dnstwist
[DNS]
  sfp_dnsraw sfp_dnscommonsrv sfp_dnsbrute sfp_dnsneighbor sfp_dnszonexfer sfp_opennic
[Passive DNS / Subdomain]
  sfp_crt sfp_certspotter* sfp_dnsdumpster sfp_hackertarget sfp_mnemonic sfp_robtex sfp_crobat_api
  sfp_sublist3r sfp_dnsgrep sfp_threatminer sfp_urlscan sfp_commoncrawl sfp_securitytrails*
  sfp_dnsdb* sfp_projectdiscovery* sfp_zetalytics* sfp_zonefiles* sfp_hostio* sfp_networksdb*
  sfp_spyonweb* sfp_fsecure_riddler* sfp_c99*
[WHOIS / Registry]
  sfp_whois sfp_arin sfp_ripe sfp_bgpview sfp_reversewhois sfp_whoxy* sfp_whoisology*
  sfp_jsonwhoiscom*
[Certificate]
  sfp_sslcert sfp_crt sfp_certspotter* sfp_tool_testsslsh
[Search Engines]
  sfp_googlesearch* sfp_bingsearch* sfp_bingsharedip* sfp_duckduckgo sfp_archiveorg sfp_commoncrawl
  sfp_grep_app sfp_searchcode
[IP / Infrastructure (Internet scan data)]
  sfp_shodan* sfp_censys* sfp_binaryedge* sfp_leakix* sfp_onyphe* sfp_fullhunt* sfp_portscan_tcp!
  sfp_tool_nmap! sfp_tool_nbtscan sfp_tool_onesixtyone
[Email]
  sfp_email sfp_emailformat sfp_hunter* sfp_pgp sfp_gravatar sfp_emailrep* sfp_emailcrawlr*
  sfp_skymem sfp_snov* sfp_debounce sfp_trumail sfp_clearbit* sfp_fullcontact*
[Username / Social]
  sfp_accounts sfp_social sfp_github sfp_keybase sfp_twitter sfp_flickr sfp_slideshare sfp_myspace
  sfp_venmo sfp_socialprofiles* sfp_sociallinks* sfp_wikipediaedits
[Person / Organization]
  sfp_names sfp_company sfp_gleif sfp_opencorporates* sfp_arin sfp_nameapi*
[Phone]
  sfp_phone sfp_numverify* sfp_callername sfp_twilio* sfp_textmagic* sfp_abstractapi*
[Threat Intelligence / Reputation]
  sfp_virustotal* sfp_alienvault* sfp_alienvaultiprep sfp_abuseipdb* sfp_greynoise*
  sfp_greynoise_community* sfp_abusech sfp_threatfox sfp_threatcrowd sfp_pulsedive* sfp_xforce*
  sfp_maltiverse sfp_isc sfp_emergingthreats sfp_blocklistde sfp_cinsscore sfp_greensnow
  sfp_talosintel sfp_botvrij sfp_customfeed sfp_fraudguard* sfp_ipqualityscore* sfp_honeypot*
  sfp_threatjammer* sfp_riskiq*
[Malware-related]
  sfp_abusech sfp_threatfox sfp_vxvault sfp_cybercrimetracker sfp_malwarepatrol*
  sfp_hybrid_analysis* sfp_koodous* sfp_hashes sfp_metadefender* sfp_coinblocker
[Reputation — DNSBL / DNS Filter]
  sfp_spamhaus sfp_sorbs sfp_spamcop sfp_uceprotect sfp_surbl sfp_dronebl sfp_abusix* sfp_fortinet
  sfp_quad9 sfp_opendns sfp_cleanbrowsing sfp_adguard_dns sfp_cloudflaredns sfp_yandexdns
  sfp_comodo sfp_dns_for_family sfp_googlesafebrowsing* sfp_openphish sfp_phishtank sfp_phishstats
[Breach / Leak]
  sfp_haveibeenpwned* sfp_dehashed* sfp_citadel* sfp_leakix* sfp_intelx* sfp_trashpanda* sfp_psbdmp
  sfp_pastebin* sfp_wikileaks sfp_zoneh sfp_openbugbounty sfp_h1nobbdde
[Cloud]
  sfp_s3bucket sfp_azureblobstorage sfp_googleobjectstorage sfp_digitaloceanspace
  sfp_grayhatwarfare*
[Web / Technology]
  sfp_webserver sfp_webframework sfp_strangeheaders sfp_pageinfo sfp_cookie sfp_errors
  sfp_webanalytics sfp_google_tag_manager sfp_builtwith* sfp_whatcms* sfp_tool_whatweb
  sfp_tool_wappalyzer sfp_tool_cmseek sfp_tool_retirejs sfp_tool_wafw00f sfp_tool_snallygaster
  sfp_subdomain_takeover sfp_intfiles sfp_junkfiles!
[Metadata / Content Extraction]
  sfp_filemeta sfp_intfiles sfp_base64 sfp_binstring sfp_hashes sfp_creditcard sfp_iban
  sfp_countryname
[Geolocation]
  sfp_ipapico sfp_ipinfo* sfp_ipstack* sfp_ipapicom* sfp_ipregistry* sfp_googlemaps*
  sfp_openstreetmap
[Cryptocurrency]
  sfp_bitcoin sfp_blockchain sfp_bitcoinabuse* sfp_bitcoinwhoswho* sfp_ethereum sfp_etherscan*
[Dark Web / Onion]
  sfp_ahmia sfp_onionsearchengine sfp_torch sfp_onioncity* sfp_intelx* sfp_torexits
[Other]
  sfp_apple_itunes sfp_crxcavator sfp_iknowwhatyoudownload* sfp_wigle* sfp_multiproxy
  sfp_tool_trufflehog
```
> **หมายเหตุ:** Module เรียกบริการภายนอกที่อาจปิดตัว เปลี่ยน API หรือเปลี่ยนเงื่อนไขหลังจาก SpiderFoot 4.0 ออก Module ที่อยู่ในรายการไม่ได้รับประกันว่าบริการปลายทางยังทำงาน ให้ทดสอบทีละ Module กับ Asset ของตัวเองก่อนใช้งานจริง (บท 8.4)

### 7.6 Module Cards — Module สำคัญ
รูปแบบ Card: Purpose / Input / Output / Configuration / API / Command / Expected / Errors / Rate Limit / Notes

#### sfp_dnsresolve — DNS Resolver
- **Purpose:** Resolve ชื่อ ↔ IP, แยก Domain แม่, ระบุ Affiliate และ Co-host
- **Input:** `INTERNET_NAME`, `IP_ADDRESS`, `IPV6_ADDRESS`, `NETBLOCK_OWNER`, ข้อความดิบหลายชนิด (หา Hostname ในข้อความ)
- **Output:** `IP_ADDRESS`, `IPV6_ADDRESS`, `INTERNET_NAME`, `DOMAIN_NAME`, `INTERNET_NAME_UNRESOLVED`, `AFFILIATE_*`, `CO_HOSTED_SITE_DOMAIN`, `INTERNAL_IP_ADDRESS`
- **Configuration:** `validatereverse`, `skipcommononwildcard`, `netblocklookup`, `maxnetblock` (24), `maxv6netblock` (120)
- **API:** ไม่ต้อง
- **Command:** `python3 sf.py -s example.com -m sfp_dnsresolve -F IP_ADDRESS,IPV6_ADDRESS -q`
- **Expected:** รายการ IP ของ Target และ Name server ที่เกี่ยวข้อง
- **Errors:** DNS Resolver ของเครื่องไม่ตอบ → ตรวจ `dig`
- **Rate Limit:** ไม่มี แต่ Query DNS จำนวนมากเมื่อ Target เป็น Netblock
- **Notes:** เป็นแกนของเกือบทุก Scan ถ้า Target เป็น `203.0.113.0/24` Module นี้จะแตก IP ทั้ง /24 เป็น Target alias (ยืนยันจากการทดสอบ: ได้ 254 IP)

#### sfp_dnsraw — DNS Raw Records
- **Purpose:** ดึง Record ดิบ (MX, NS, TXT, SPF)
- **Input:** `INTERNET_NAME`, `DOMAIN_NAME`, `DOMAIN_NAME_PARENT`
- **Output:** `PROVIDER_MAIL`, `PROVIDER_DNS`, `RAW_DNS_RECORDS`, `DNS_TEXT`, `DNS_SPF`, `INTERNET_NAME`, `AFFILIATE_INTERNET_NAME`
- **Configuration:** `verify`
- **API:** ไม่ต้อง
- **Command:** `python3 sf.py -s example.com -m sfp_dnsraw -o csv -r -q`
- **Expected (ทดสอบจริง รูปแบบ):** `sfp_dnsraw,DNS SPF Record,example.com,v=spf1 -all`
- **Notes:** Query ไปยัง DNS server ที่รับผิดชอบโซนผ่าน Resolver → เป็น Passive ในความหมายของ SpiderFoot

#### sfp_dnsbrute — DNS Brute-forcer
- **Purpose:** เดาชื่อ Host จาก Wordlist
- **Input:** `DOMAIN_NAME` (และ `INTERNET_NAME` ถ้าเปิด `numbersuffix` หรือปิด `domainonly`)
- **Output:** `INTERNET_NAME`
- **Configuration:** `skipcommonwildcard`, `domainonly`, `commons`, `top10000` (False), `numbersuffix`, `numbersuffixlimit`, `_maxthreads` (100)
- **API:** ไม่ต้อง
- **Command:** `python3 sf.py -s example.com -m sfp_dnsbrute -F INTERNET_NAME -q`
- **Errors:** Domain ที่มี Wildcard DNS → ผลปลอมจำนวนมาก (Module มี Option ข้าม Wildcard)
- **Rate Limit:** ส่ง Query จำนวนมาก (`_maxthreads` 100) อาจกระทบ Resolver ขององค์กร
- **Notes:** ไม่อยู่ใน Use Case `Passive` ใช้เฉพาะ Domain ที่ได้รับอนุญาต Correlation `host_only_from_bruteforce` ช่วยชี้ Host ที่พบจากการเดาอย่างเดียว

#### sfp_crt — Certificate Transparency
- **Purpose:** ค้น crt.sh หา Hostname จาก Certificate
- **Input:** `DOMAIN_NAME`, `INTERNET_NAME`
- **Output:** `SSL_CERTIFICATE_RAW`, `INTERNET_NAME`, `INTERNET_NAME_UNRESOLVED`, `DOMAIN_NAME`, `CO_HOSTED_SITE`, `RAW_RIR_DATA`
- **Configuration:** `verify` (ตรวจว่า Resolve ได้), `fetchcerts` (ดึง Certificate เต็ม)
- **API:** ไม่ต้อง (`FREE_NOAUTH_UNLIMITED`)
- **Command:** `python3 sf.py -s example.com -m sfp_crt,sfp_dnsresolve -F INTERNET_NAME,INTERNET_NAME_UNRESOLVED -q`
- **Errors:** crt.sh ตอบช้าหรือ Timeout → เพิ่ม `_fetchtimeout`
- **Notes:** ได้ Subdomain ที่เลิกใช้แล้วด้วย ดูชนิด `INTERNET_NAME_UNRESOLVED`

#### sfp_spider — Web Spider
- **Purpose:** Crawl เว็บไซต์ของ Target
- **Input:** `LINKED_URL_INTERNAL`, `INTERNET_NAME`
- **Output:** `WEBSERVER_HTTPHEADERS`, `HTTP_CODE`, `LINKED_URL_INTERNAL`, `LINKED_URL_EXTERNAL`, `TARGET_WEB_CONTENT`, `TARGET_WEB_CONTENT_TYPE`
- **Configuration:** `robotsonly`, `pausesec` (0), `maxpages` (100), `maxlevels` (3), `usecookies`, `filterfiles`, `filtermime`, `nosubs`, `reportduplicates`
- **Command:** `python3 sf.py -s www.example.com -m sfp_spider,sfp_email,sfp_webanalytics -q`
- **Notes:** Flag `slow` ติดต่อเว็บไซต์เป้าหมายโดยตรง เป็นต้นทางของ Module กลุ่ม Content Analysis (`TARGET_WEB_CONTENT` → Email, Phone, Hash, Bitcoin ฯลฯ) ตั้ง `pausesec` เพื่อลดภาระเว็บไซต์

#### sfp_accounts — Account Finder
- **Purpose:** ตรวจชื่อผู้ใช้บนเว็บไซต์กว่า 500 แห่ง (ตามคำอธิบายของ Module)
- **Input:** `EMAILADDR`, `DOMAIN_NAME`, `HUMAN_NAME`, `USERNAME`
- **Output:** `USERNAME`, `ACCOUNT_EXTERNAL_OWNED`, `SIMILAR_ACCOUNT_EXTERNAL`
- **Configuration:** `ignorenamedict`, `ignoreworddict`, `musthavename`, `userfromemail`, `permutate` (False), `usernamesize` (4), `_maxthreads` (20)
- **Command:** `python3 sf.py -s alice_example -m sfp_accounts -q`
- **Notes:** ส่ง Request ไปยังเว็บไซต์ภายนอกจำนวนมาก ผล `SIMILAR_ACCOUNT_EXTERNAL` เป็นบัญชีชื่อคล้าย ไม่ใช่บัญชีเดียวกัน

#### sfp_virustotal — VirusTotal
- **Purpose:** ตรวจชื่อเสียงของ IP/Host และหา Hostname ที่เกี่ยวข้อง
- **Input:** `IP_ADDRESS`, `AFFILIATE_IPADDR`, `INTERNET_NAME`, `CO_HOSTED_SITE`, `NETBLOCK_OWNER`, `NETBLOCK_MEMBER`
- **Output:** `MALICIOUS_IPADDR`, `MALICIOUS_INTERNET_NAME`, `MALICIOUS_COHOST`, `MALICIOUS_AFFILIATE_*`, `MALICIOUS_NETBLOCK`, `MALICIOUS_SUBNET`, `INTERNET_NAME`, `DOMAIN_NAME`
- **Configuration:** `api_key`, `publicapi` (True = หยุด 15 วินาทีหลังแต่ละ Query เพื่อไม่ให้ Public API ตัด Request), `checkcohosts`, `checkaffiliates`, `netblocklookup`, `subnetlookup`
- **API:** ต้องมี (`FREE_AUTH_LIMITED`)
- **Command:** `python3 sf.py -s 203.0.113.10 -m sfp_virustotal -F MALICIOUS_IPADDR -q`
- **Rate Limit:** Public API มีโควตาต่อนาที/วัน ตั้ง `publicapi` = True เมื่อใช้ Key ฟรี (Scan จะช้าลงมากเมื่อมี IP/Host จำนวนมาก)
- **Notes:** ไม่รับ Hash เป็น Input ใน 4.0 (บท 33)

#### sfp_shodan — SHODAN
- **Purpose:** ดึงข้อมูล Port, Banner, OS, CVE ที่ Shodan สแกนไว้
- **Input:** `IP_ADDRESS`, `NETBLOCK_OWNER`, `DOMAIN_NAME`, `WEB_ANALYTICS_ID`
- **Output:** `TCP_PORT_OPEN`, `TCP_PORT_OPEN_BANNER`, `OPERATING_SYSTEM`, `DEVICE_TYPE`, `GEOINFO`, `VULNERABILITY_CVE_*`, `VULNERABILITY_GENERAL`, `RAW_RIR_DATA`, `IP_ADDRESS`
- **Configuration:** `api_key`, `netblocklookup`, `maxnetblock`
- **Notes:** ข้อมูลมาจากฐานข้อมูลของ Shodan ไม่ใช่การสแกนจากเครื่องเรา CVE ที่ได้เป็นการจับคู่จาก Banner ต้องยืนยันก่อนรายงาน

#### sfp_abusech — abuse.ch
- **Purpose:** ตรวจ IP/Host กับ Feed ของ abuse.ch (Feodo Tracker, SSL Blacklist, URLhaus)
- **Output:** `MALICIOUS_IPADDR`, `MALICIOUS_INTERNET_NAME`, `MALICIOUS_AFFILIATE_*`, `MALICIOUS_SUBNET`, `MALICIOUS_COHOST`, `MALICIOUS_NETBLOCK`
- **Configuration:** `abusefeodoip`, `abusesslblip`, `abuseurlhaus`, `cacheperiod` (18 ชั่วโมง), `checkaffiliates`, `checkcohosts`, `checknetblocks`, `checksubnets`
- **Notes:** Module ดาวน์โหลด Feed มา Cache แล้วเทียบในเครื่อง ไม่ส่ง Target ไปที่ Provider ทีละตัว

#### sfp_haveibeenpwned — HaveIBeenPwned
- **Purpose:** ตรวจว่า Email/Phone อยู่ในเหตุการณ์รั่วไหลที่เปิดเผย
- **Input:** `EMAILADDR`, `PHONE_NUMBER`
- **Output:** `EMAILADDR_COMPROMISED`, `PHONE_NUMBER_COMPROMISED`, `LEAKSITE_CONTENT`, `LEAKSITE_URL`
- **API:** ต้องมี (`COMMERCIAL_ONLY`)
- **Notes:** ผล `EMAILADDR_COMPROMISED` กระตุ้น Correlation `email_in_multiple_breaches`

#### sfp_s3bucket — Amazon S3 Bucket Finder
- **Purpose:** เดาชื่อ Bucket จากชื่อ Domain + Suffix แล้วตรวจว่ามีอยู่/เปิดสาธารณะ
- **Input:** `DOMAIN_NAME`, `LINKED_URL_EXTERNAL`
- **Output:** `CLOUD_STORAGE_BUCKET`, `CLOUD_STORAGE_BUCKET_OPEN`
- **Configuration:** `endpoints`, `suffixes` (เช่น test, dev, web, beta ...), `_maxthreads` (20)
- **Notes:** ส่ง Request ไปยัง Cloud Provider ด้วยชื่อที่เดา ผลที่ได้อาจเป็น Bucket ของบุคคลอื่นที่ชื่อคล้ายกัน (บท 27, 42)

#### Module Cards แบบย่อ (รายละเอียดอยู่ในบทที่อ้างถึง)
| Module | Input → Output | Option สำคัญ | หมายเหตุ |
|---|---|---|---|
| `sfp_sslcert` | `INTERNET_NAME`, `IP_ADDRESS` → `SSL_CERTIFICATE_*` | `ssltimeout` 10, `certexpiringdays` 30 | ติดต่อ Host โดยตรง (บท 18) |
| `sfp_whois` | `DOMAIN_NAME`, `NETBLOCK_OWNER` → `DOMAIN_WHOIS`, `NETBLOCK_WHOIS`, `DOMAIN_REGISTRAR` | — | ข้อความดิบให้ Module อื่นดึง Entity (บท 17) |
| `sfp_ripe` | `IP_ADDRESS`, `BGP_AS_OWNER` → `NETBLOCK_*`, `BGP_AS_*` | — | Module เดียวที่รับ Target แบบ ASN (บท 15) |
| `sfp_bgpview` | `IP_ADDRESS` → `BGP_AS_MEMBER`, `NETBLOCK_MEMBER`, `PHYSICAL_ADDRESS` | — | บท 15 |
| `sfp_hackertarget` | `IP_ADDRESS`, `NETBLOCK_OWNER` → `CO_HOSTED_SITE`, `INTERNET_NAME` | `maxcohost` 100, `netblocklookup` | Shared hosting = Co-host มาก (บท 42) |
| `sfp_alienvault` | IP/Host/Netblock → `MALICIOUS_*`, `CO_HOSTED_SITE` | `api_key`, `threat_score_min` 2, age limit 30 วัน | ต้องใช้ Key (บท 32) |
| `sfp_customfeed` | Host/IP → `MALICIOUS_*` | `url`, `cacheperiod` | Feed ภายในองค์กร (บท 32.4) |

## 8. Module Management
### 8.1 ดู Module ทั้งหมดแบบกรองได้
```bash
python3 sf.py -M 2>/dev/null > ~/cases/$CASE/raw/modules.txt
grep -i "certificate\|ssl" ~/cases/$CASE/raw/modules.txt
```

### 8.2 สร้างตาราง Module จาก Source (Flags, Use Case, API)
SpiderFoot 4.0 ไม่มีคำสั่ง CLI สำหรับแสดง Flag ให้ใช้ Script อ่าน Metadata จาก Source โดยไม่ต้อง Import Module:
```bash
cat > ~/bin/sf-modinfo.py << 'EOF'
#!/usr/bin/env python3
"""อ่าน meta/opts/watchedEvents/producedEvents จากไฟล์ Module ด้วย AST"""
import ast, os, sys, json
moddir = sys.argv[1] if len(sys.argv) > 1 else "modules"
rows = []
for f in sorted(os.listdir(moddir)):
    if not (f.startswith("sfp_") and f.endswith(".py")) or f == "sfp_template.py":
        continue
    tree = ast.parse(open(os.path.join(moddir, f)).read())
    d = {"module": f[:-3]}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id in ("meta", "opts"):
            try:
                d[node.targets[0].id] = ast.literal_eval(node.value)
            except Exception:
                pass
        if isinstance(node, ast.FunctionDef) and node.name in ("watchedEvents", "producedEvents"):
            for r in ast.walk(node):
                if isinstance(r, ast.Return):
                    try:
                        d[node.name] = ast.literal_eval(r.value)
                    except Exception:
                        d[node.name] = "dynamic"
    rows.append(d)
json.dump(rows, sys.stdout, indent=1)
EOF
chmod +x ~/bin/sf-modinfo.py
cd ~/tools/spiderfoot && ~/bin/sf-modinfo.py modules > ~/cases/$CASE/raw/modinfo.json
jq length ~/cases/$CASE/raw/modinfo.json
```
ผลลัพธ์ที่ควรเห็น: `232` (รวม `sfp__stor_db` และ `sfp__stor_stdout`)

ตัวอย่าง Query:
```bash
J=~/cases/$CASE/raw/modinfo.json
# Module ที่ต้องใช้ API Key
jq -r '.[] | select(.meta.flags? // [] | index("apikey")) | .module' $J | wc -l
# Module แบบ invasive
jq -r '.[] | select(.meta.flags? // [] | index("invasive")) | .module' $J
# Module ที่อยู่ใน Passive และไม่ต้องใช้ Key
jq -r '.[] | select((.meta.useCases // []) | index("Passive"))
            | select((.meta.flags // []) | index("apikey") | not) | .module' $J | paste -sd, -
# Module ที่รับ EMAILADDR
jq -r '.[] | select((.watchedEvents|type)=="array" and (.watchedEvents|index("EMAILADDR"))) | .module' $J
```

### 8.3 เปิด/ปิด Module
SpiderFoot ไม่มีสถานะ "ปิด Module ถาวร" ใน 4.0 การเปิด/ปิดทำต่อ Scan:
- CLI: ระบุเฉพาะ Module ที่ต้องการด้วย `-m`
- Web UI: แท็บ **By Module** ติ๊กเฉพาะที่ต้องการ
- ตัด Module ที่ไม่ต้องการจากรายการ Use Case ด้วย Script (บท 9.3)

### 8.4 ทดสอบ Module ทีละตัว
```bash
M=sfp_crt
python3 sf.py -s example.com -m $M -o json 2> ~/cases/$CASE/raw/test-$M.log \
  > ~/cases/$CASE/raw/test-$M.json
jq length ~/cases/$CASE/raw/test-$M.json
grep -E "ERROR|WARNING" ~/cases/$CASE/raw/test-$M.log | head
```
การอ่านผล:
- `jq length` = 2 (มีเพียง Event ของ Target เอง) + ไม่มี Error → Module ทำงานแต่ไม่พบข้อมูล
- มี `ERROR` → ดูข้อความ (Key ผิด, Timeout, HTTP code) แล้วไปบท 68

### 8.5 Module ที่เป็น Tool ภายนอก
Module `sfp_tool_*` เรียกโปรแกรมที่ต้องติดตั้งเอง และต้องตั้ง Path ใน Option ของ Module:

| Module | Option ที่ต้องตั้ง |
|---|---|
| `sfp_tool_whatweb` | `whatweb_path`, `ruby_path` |
| `sfp_tool_wappalyzer` | `wappalyzer_path`, `node_path` |
| `sfp_tool_cmseek` | `cmseekpath`, `pythonpath` |
| `sfp_tool_dnstwist` | `dnstwistpath`, `pythonpath` |
| `sfp_tool_retirejs` | `retirejs_path` |

ตัวอย่าง WhatWeb บน Kali:
```bash
which whatweb || sudo apt install -y whatweb
```

```
sf> set module.sfp_tool_whatweb.whatweb_path = /usr/bin/whatweb
```
> **หมายเหตุ:** ชื่อ Option ของ Tool module อื่นตรวจได้จาก `grep -A10 "    opts = {" modules/sfp_tool_<name>.py` Module `sfp_tool_nmap` และ `sfp_tool_nuclei` มี Flag `invasive` ใช้กับระบบที่ได้รับอนุญาตเท่านั้น

### 8.6 เขียน Module เอง (โครงสร้างขั้นต่ำ)
```bash
cp modules/sfp_template.py modules/sfp_example_lookup.py
grep -n "sfp_template\|class \|def watchedEvents\|def producedEvents\|def handleEvent" modules/sfp_example_lookup.py
```
ขั้นตอน:
1. เปลี่ยนชื่อ Class ให้ตรงกับชื่อไฟล์ (`sfp_example_lookup`)
2. แก้ `meta` (ต้องใช้ Category จากรายการในข้อ 7.2 ไม่งั้นโหลดไม่ผ่าน)
3. กำหนด `watchedEvents()` / `producedEvents()`
4. เขียน `handleEvent()` ให้สร้าง `SpiderFootEvent` แล้ว `self.notifyListeners(evt)`
5. ทดสอบ: `python3 sf.py -M 2>/dev/null | grep example_lookup`

> **หมายเหตุ:** ถ้า `meta.categories` ไม่อยู่ในรายการที่กำหนด `sf.py` จะหยุดตอนเริ่มพร้อม `Module ... has invalid category` ตรวจรายละเอียด API ภายใน Module (`self.sf.fetchUrl`, `SpiderFootEvent`) จาก Module ที่มีอยู่จริง เช่น `modules/sfp_crt.py`

## 9. Scan Profiles
### 9.1 SpiderFoot 4.0 มี Profile แบบไหน
- **Profile ในตัว** = Use Case 4 แบบ: `All`, `Footprint`, `Investigate`, `Passive`
- 4.0 **ไม่มี** ฟีเจอร์ "บันทึก Profile แบบตั้งชื่อ" ใน Web UI หรือ CLI
- วิธีทำ Custom Profile ที่ทำซ้ำได้: เก็บรายชื่อ Module เป็นไฟล์ แล้วส่งให้ `-m` หรือใช้ **Clone** Scan ใน Web UI

### 9.2 ขนาดของ Use Case (4.0.0)
นับจาก `meta.useCases`:
```bash
J=~/cases/$CASE/raw/modinfo.json
for u in Footprint Investigate Passive; do
  printf "%-12s %s\n" $u $(jq --arg u $u '[.[] | select((.meta.useCases // []) | index($u))] | length' $J)
done
```
ผลบน 4.0.0:
```
Footprint    156
Investigate  206
Passive      198
```
ใน 232 Module มี 83 ตัวที่ต้องใช้ API Key และ Use Case `Passive` มี Module ที่ไม่ต้องใช้ Key 116 ตัว ดังนั้น `-u passive` คือการเปิด Module เกือบ 200 ตัว ไม่ใช่ Scan เบา ๆ

### 9.3 Custom Profile เป็นไฟล์
```bash
mkdir -p ~/sf-profiles
printf '%s\n' sfp_dnsresolve sfp_dnsraw sfp_crt sfp_dnsdumpster sfp_hackertarget sfp_mnemonic \
  sfp_robtex sfp_whois sfp_ripe sfp_bgpview sfp_hosting sfp_urlscan sfp_commoncrawl sfp_emailformat \
  sfp_pgp sfp_abusech sfp_threatfox sfp_spamhaus > ~/sf-profiles/domain-passive.txt
# ใช้งาน
python3 sf.py -s example.com -m "$(grep -v '^#' ~/sf-profiles/domain-passive.txt | paste -sd, -)" -o json -q
```
ตรวจว่าทุกชื่อใน Profile มีอยู่จริงในเวอร์ชันที่ติดตั้ง:
```bash
python3 sf.py -M 2>/dev/null | awk '{print $1}' > /tmp/sf-mods.txt
grep -vxFf /tmp/sf-mods.txt ~/sf-profiles/domain-passive.txt || echo "ALL MODULES FOUND"
```

### 9.4 Profile ตามงาน (ชื่อ Module ตรวจแล้วกับ 4.0.0)
```
ip-context.txt
  sfp_dnsresolve sfp_ripe sfp_bgpview sfp_hosting sfp_whois sfp_robtex
  sfp_hackertarget sfp_ipapico sfp_abusech sfp_threatfox sfp_spamhaus sfp_torexits
  (+ API) sfp_shodan sfp_virustotal sfp_alienvault sfp_abuseipdb sfp_greynoise_community

email.txt   (Domain ของ Email ให้ Scan แยกด้วย domain-passive.txt — บท 19.1)
  sfp_pgp sfp_gravatar sfp_accounts
  (+ API) sfp_haveibeenpwned sfp_emailrep sfp_hunter

threat-intel.txt
  sfp_dnsresolve sfp_abusech sfp_threatfox sfp_vxvault sfp_cybercrimetracker
  sfp_openphish sfp_phishtank sfp_phishstats sfp_spamhaus sfp_surbl sfp_blocklistde
  sfp_emergingthreats sfp_cinsscore sfp_greensnow sfp_isc sfp_torexits sfp_customfeed
  (+ API) sfp_virustotal sfp_alienvault sfp_abuseipdb sfp_greynoise_community sfp_pulsedive

corporate.txt  (องค์กรตัวเอง / ได้รับอนุญาต)
  sfp_dnsresolve sfp_dnsraw sfp_crt sfp_whois sfp_spider sfp_email sfp_phone sfp_names
  sfp_company sfp_webanalytics sfp_social sfp_intfiles sfp_filemeta sfp_s3bucket
  sfp_azureblobstorage sfp_googleobjectstorage sfp_digitaloceanspace sfp_sslcert
  sfp_webserver sfp_webframework sfp_gleif

infrastructure.txt
  sfp_dnsresolve sfp_dnsraw sfp_crt sfp_ripe sfp_bgpview sfp_hosting sfp_whois
  sfp_robtex sfp_mnemonic sfp_hackertarget sfp_sslcert sfp_urlscan
  (+ API) sfp_shodan sfp_censys sfp_securitytrails
```

### 9.5 Optimize Profile
1. รัน Profile กับ Asset ของตัวเอง 1 ครั้ง
2. นับ Event ต่อ Module (SQL ในบท 56.2)
3. ตัด Module ที่ให้ 0 Event หลายครั้งติดกัน หรือให้แต่ Noise
4. แยก Module ที่ใช้ API Quota ไปเป็น Profile รอบที่สอง (รันเฉพาะ Entity ที่คัดแล้ว)
5. เก็บ Profile ใน Git พร้อม Version ของ SpiderFoot ที่ทดสอบ

## 10. Target Types
### 10.1 ชนิด Target ที่ SpiderFoot 4.0 รองรับ
ตรวจจาก `SpiderFootHelpers.targetTypeFromString()` (ลำดับการตรวจมีผล):

| Target Type | ตัวอย่าง | รูปแบบที่ต้องใส่ |
|---|---|---|
| `IP_ADDRESS` | `203.0.113.10` | IPv4 |
| `NETBLOCK_OWNER` | `203.0.113.0/24` | IPv4 CIDR |
| `EMAILADDR` | `alice@example.com` | มี `@` |
| `PHONE_NUMBER` | `+6620000000` | `+` ตามด้วยตัวเลขเท่านั้น (ห้ามเว้นวรรค) |
| `HUMAN_NAME` | `"Alice Example"` | อยู่ในเครื่องหมายคำพูด และมีช่องว่าง |
| `USERNAME` | `"alice_example"` | อยู่ในเครื่องหมายคำพูด |
| `BGP_AS_OWNER` | `64496` | ตัวเลขล้วน |
| `IPV6_ADDRESS` | `2001:db8::10` | Hex + `:` |
| `NETBLOCKV6_OWNER` | `2001:db8::/32` | ต้องมี `::/` |
| `INTERNET_NAME` | `example.com`, `test.example.org` | Domain หรือ Hostname |
| `BITCOIN_ADDRESS` | `<BTC_ADDRESS>` | รูปแบบ Bitcoin address |

**ไม่รองรับเป็น Target ใน 4.0:** URL (`https://...`), File Hash, ชื่อองค์กรโดยตรง, Ethereum Address

ผลทดสอบ URL:
```
[ERROR] sf : Could not determine target type. Invalid target: https://www.example.com/x
```

### 10.2 ความต่างระหว่าง `sf.py` CLI กับ Web UI (สำคัญ)
`sf.py` จะเติมเครื่องหมายคำพูดให้ Target อัตโนมัติ ถ้า Target **ไม่มีจุด**, ไม่ขึ้นต้นด้วย `+` และยังไม่มีคำพูด ผลที่ทดสอบได้กับ 4.0.0:

| Input ใน `sf.py -s` | ชนิดที่ได้ |
|---|---|
| `alice_example` | Username ✔ |
| `"Alice Example"` | Human Name ✔ |
| `+6620000000` | Phone Number ✔ |
| `64496` | **Username** ✘ (ควรเป็น ASN) |
| `2001:db8::10` | **Username** ✘ (ควรเป็น IPv6) |

ทางแก้: Target ชนิด ASN และ IPv6 ให้เริ่ม Scan ผ่าน **Web UI** หรือ **`sfcli.py start`** (ส่งค่าไปยัง Server โดยไม่เติมคำพูด)
```
sf> start 64496 -m sfp_ripe -n asn-64496
sf> start 2001:db8::10 -m sfp_dnsresolve,sfp_ripe -n v6-test
```
ใน Web UI ชื่อคนและ Username ต้องใส่คำพูดเอง เช่น `"alice_example"`

### 10.3 Target → Module ที่ควรใช้ต่อ
```
Domain/Hostname  example.com        sfp_dnsresolve sfp_dnsraw sfp_crt sfp_whois sfp_hackertarget sfp_mnemonic sfp_urlscan (บท 11–13)
IP Address       203.0.113.10       sfp_dnsresolve sfp_ripe sfp_bgpview sfp_hosting sfp_robtex sfp_abusech sfp_spamhaus (บท 14, 63)
IPv6*            2001:db8::10       sfp_dnsresolve sfp_ripe sfp_bgpview sfp_robtex sfp_mnemonic sfp_alienvault sfp_abuseipdb
CIDR             203.0.113.0/24     sfp_dnsresolve sfp_ripe sfp_whois sfp_spamhaus sfp_hackertarget (ระวังการขยาย บท 16)
Email            alice@example.com  sfp_pgp sfp_gravatar sfp_accounts sfp_haveibeenpwned(key) sfp_emailrep(key) (Domain: Scan แยก)
Username         "alice_example"    sfp_accounts sfp_github sfp_keybase sfp_wikipediaedits
Person           "Alice Example"    sfp_accounts sfp_arin sfp_ahmia sfp_onionsearchengine sfp_socialprofiles(key)
Phone            +6620000000        sfp_phone sfp_numverify(key) sfp_callername sfp_haveibeenpwned(key)
ASN*             64496              sfp_ripe → NETBLOCK_OWNER → Module ด้าน IP ทำงานต่อ
Bitcoin          <BTC_ADDRESS>      sfp_blockchain sfp_bitcoinabuse(key) sfp_bitcoinwhoswho(key) sfp_intelx(key)
(* เริ่ม Scan จาก Web UI หรือ sfcli ตามข้อ 10.2)
```
ชนิดที่ไม่รองรับโดยตรง:
- **Organization** → ใช้ Domain ขององค์กรเป็น Target แล้วให้ `sfp_company` ดึง `COMPANY_NAME` → `sfp_gleif`, `sfp_opencorporates*`
- **URL** → ใช้ Hostname ของ URL เป็น Target
- **Hash** → ค้น Hash ด้วยบริการอื่นก่อน แล้วนำ Domain/IP ที่ได้มาเป็น Target (บท 33)

### 10.4 ตรวจชนิด Target ก่อน Scan จริง
```bash
python3 sf.py -s "$T" -m sfp_dnsresolve -o json 2>/dev/null | jq -r '.[0].type'
```
- ได้ `Internet Name`, `IP Address`, `Username` ฯลฯ ตามชนิดที่ SpiderFoot เข้าใจ
- ใช้เป็นขั้นตรวจสอบใน Script Automation ก่อนรัน Scan ใหญ่

## 11. Domain Intelligence
Workflow หลักของคู่มือ ทุกขั้นเป็น Scan เล็กที่ควบคุมได้ เก็บใน Database เดียวกัน (Case เดียว) และตั้งชื่อไฟล์ตามขั้น
```
Domain → DNS → Subdomain → IP → ASN → Netblock → Certificate → Website
       → Technology → Reputation → Threat Intelligence → Related Infrastructure
```
เตรียมตัวแปร:
```bash
T=example.com; R=~/cases/$CASE/raw; cd ~/tools/spiderfoot && . .venv/bin/activate
run(){ n=$1; shift; python3 sf.py -s $T "$@" -o json 2>$R/$n.log >$R/$n.json; echo "$n: $(jq length $R/$n.json) events"; }
```

| ขั้น | คำสั่ง |
|---|---|
| 1 DNS | `run 01-dns -m sfp_dnsresolve,sfp_dnsraw` |
| 2 Subdomain | `run 02-subs -m sfp_dnsresolve,sfp_crt,sfp_dnsdumpster,sfp_hackertarget,sfp_mnemonic,sfp_urlscan` |
| 3 IP | `run 03-ip -m sfp_dnsresolve,sfp_crt,sfp_mnemonic,sfp_robtex -F IP_ADDRESS,IPV6_ADDRESS` |
| 4 ASN | `run 04-asn -m sfp_dnsresolve,sfp_ripe,sfp_bgpview` |
| 5 Netblock | `run 05-netblock -m sfp_dnsresolve,sfp_ripe,sfp_whois` |
| 6 Certificate | `run 06-cert -m sfp_dnsresolve,sfp_crt,sfp_sslcert` |
| 7 Website | `run 07-web -m sfp_dnsresolve,sfp_spider,sfp_webserver,sfp_strangeheaders` |
| 8 Technology | `run 08-tech -m sfp_dnsresolve,sfp_spider,sfp_webframework,sfp_webanalytics` |
| 9 Reputation | `run 09-rep -m sfp_dnsresolve,sfp_spamhaus,sfp_surbl,sfp_quad9,sfp_opendns` |
| 10 Threat Intel | `run 10-ti -m sfp_dnsresolve,sfp_abusech,sfp_threatfox,sfp_virustotal,sfp_alienvault` |
| 11 Related Infra | `run 11-related -m sfp_dnsresolve,sfp_hackertarget,sfp_robtex,sfp_webanalytics,sfp_spider` |

อ่านผลแต่ละขั้น:
```bash
# สรุปชนิด Event ต่อขั้น
for f in $R/0*.json $R/1*.json; do echo "== $(basename $f)"; jq -r '.[].type' $f | sort | uniq -c | sort -rn | head -5; done
# Subdomain ที่ยัง Resolve ได้ / ไม่ได้
jq -r '.[] | select(.type=="Internet Name") | .data' $R/02-subs.json | sort -u > $R/hosts.txt
jq -r '.[] | select(.type=="Internet Name - Unresolved") | .data' $R/02-subs.json | sort -u > $R/hosts-unresolved.txt
wc -l $R/hosts*.txt
```
จุดตัดสินใจ:
- ขั้น 3 ใช้ `-m` + `-F` แทน `-t` เพราะ `-t IP_ADDRESS` จะเปิด Module `invasive` ด้วย (บท 4.6)
- ขั้น 7–8 ติดต่อเว็บไซต์เป้าหมายโดยตรง ข้ามได้ถ้า Scope เป็น Passive เท่านั้น
- ขั้น 10 ต้องมี API Key สำหรับ VirusTotal/OTX ถ้าไม่มี ให้ตัดออก
- ขั้น 11 หยุดถ้า `CO_HOSTED_SITE` มากกว่า `maxcohost` = Shared hosting (บท 42)

## 12. DNS Intelligence
```bash
python3 sf.py -s example.com -m sfp_dnsresolve,sfp_dnsraw,sfp_dnscommonsrv -o csv -r -n -q \
  | awk -F, 'NR>1{print $2}' | sort | uniq -c | sort -rn
```
Event Type ด้าน DNS:
```
PROVIDER_DNS (NS)  PROVIDER_MAIL (MX)  DNS_TEXT  DNS_SPF  DNS_SRV  RAW_DNS_RECORDS
INTERNET_NAME  INTERNET_NAME_UNRESOLVED  DOMAIN_NAME  DOMAIN_NAME_PARENT  INTERNAL_IP_ADDRESS
```
- `sfp_dnscommonsrv` (Flag `slow`) หา Host จาก SRV record ที่พบบ่อย
- `INTERNAL_IP_ADDRESS` = ชื่อสาธารณะที่ Resolve เป็น IP ภายใน → Correlation `internal_host` (MEDIUM)
- `sfp_dnszonexfer` ลอง AXFR กับ `PROVIDER_DNS` ถ้าสำเร็จ Correlation `dns_zone_transfer_possible` (HIGH) — ใช้กับ DNS ขององค์กรตนเอง/ได้รับอนุญาตเท่านั้น
- `sfp_dnsneighbor` Reverse-resolve IP ข้างเคียง (`lookasidebits` = 4 → 16 IP รอบ Target)

ตรวจยืนยันนอก SpiderFoot:
```bash
dig +short NS example.com; dig +short MX example.com; dig +short TXT example.com
host -t SRV _sip._tcp.example.com
```

## 13. Subdomain Enumeration
### 13.1 Passive ก่อนเสมอ
```bash
python3 sf.py -s example.com \
  -m sfp_dnsresolve,sfp_crt,sfp_dnsdumpster,sfp_hackertarget,sfp_mnemonic,sfp_robtex,sfp_urlscan,sfp_commoncrawl,sfp_threatminer \
  -F INTERNET_NAME,INTERNET_NAME_UNRESOLVED -o csv -r -q > $R/subs-passive.csv
```

### 13.2 ใครให้ Subdomain อะไร
```bash
awk -F, 'NR>1 && $2=="Internet Name"{print $1}' $R/subs-passive.csv | sort | uniq -c | sort -rn
```
ผลเป็นจำนวน Hostname ต่อ Module ใช้ดูว่า Source ไหนคุ้มค่ากับ Domain ประเภทนี้

### 13.3 Active (เฉพาะที่ได้รับอนุญาต)
```bash
python3 sf.py -s example.com -m sfp_dnsresolve,sfp_dnsbrute -F INTERNET_NAME -o csv -r -q > $R/subs-brute.csv
```

### 13.4 ส่วนต่างระหว่าง Passive กับ Active
```bash
cut -d, -f4 $R/subs-passive.csv | sort -u > /tmp/p.txt
cut -d, -f4 $R/subs-brute.csv   | sort -u > /tmp/b.txt
comm -13 /tmp/p.txt /tmp/b.txt   # พบเฉพาะจาก Brute force
```
Correlation ที่เกี่ยวข้อง: `host_only_from_bruteforce` (LOW), `host_only_from_certificatetransparency` (LOW), `dev_or_test_system` (MEDIUM — ชื่อมี dev/test/uat/internal/staging)

> **หมายเหตุ:** ข้อมูลที่มี Comma ภายใน (เช่น TXT record) ทำให้ `cut -d,` ผิดคอลัมน์ ใช้ `-F INTERNET_NAME` ให้เหลือเฉพาะ Hostname หรือใช้ `csvcut` (บท 55)

## 14. IP Intelligence
```bash
python3 sf.py -s 203.0.113.10 \
  -m sfp_dnsresolve,sfp_ripe,sfp_bgpview,sfp_hosting,sfp_robtex,sfp_ipapico,sfp_abusech,sfp_spamhaus,sfp_torexits \
  -o json -q > $R/ip-203.0.113.10.json
jq -r '.[] | "\(.type)\t\(.data)"' $R/ip-203.0.113.10.json | sort -u
```
สิ่งที่ต้องได้จาก IP หนึ่งตัว:
```
INTERNET_NAME (PTR/Reverse)  BGP_AS_MEMBER  NETBLOCK_MEMBER  PROVIDER_HOSTING
GEOINFO  CO_HOSTED_SITE  MALICIOUS_* / BLACKLISTED_*  TOR_EXIT_NODE
```
- `NETBLOCK_MEMBER` = IP อยู่ใน Netblock นั้น (ไม่ได้บอกว่า Target เป็นเจ้าของ)
- `PROVIDER_HOSTING` จาก `sfp_hosting` บอกว่า IP อยู่ในช่วงของผู้ให้บริการ Hosting/Cloud ที่รู้จัก → สัญญาณ Shared infrastructure
- IP สำหรับเอกสาร (TEST-NET) จะไม่มีข้อมูลจาก Provider ใช้ทดสอบ Pipeline เท่านั้น

## 15. ASN Intelligence
### 15.1 IP → ASN
```bash
python3 sf.py -s 203.0.113.10 -m sfp_ripe,sfp_bgpview -F BGP_AS_MEMBER,NETBLOCK_MEMBER -H -q
```

### 15.2 ASN เป็น Target (ผ่าน sfcli / Web UI)
```
sf> start 64496 -m sfp_ripe,sfp_dnsresolve -n asn-64496
sf> data <sid> -t NETBLOCK_OWNER
```
- `BGP_AS_OWNER` = ASN ที่เป็นของ Target / `BGP_AS_MEMBER` = ASN ที่ IP ของ Target อยู่
- ASN ของ Cloud/CDN มี Prefix มหาศาล อย่าใช้เป็น Target โดยไม่จำกัด Module

ตรวจยืนยัน:
```bash
whois -h whois.cymru.com " -v 203.0.113.10"
whois AS64496 | head -20
```

## 16. Netblock Intelligence
```bash
python3 sf.py -s 203.0.113.0/24 -m sfp_ripe,sfp_whois -F NETBLOCK_OWNER,NETBLOCK_WHOIS,BGP_AS_OWNER -n -q
```
- Target แบบ CIDR ทำให้ `sfp_dnsresolve` ขยายเป็นทุก IP ในช่วง (ทดสอบแล้ว: /24 ได้ 254 IP alias) Module อื่นที่รับ `IP_ADDRESS` จะทำงานกับทุกตัว
- Option `netblocklookup` / `maxnetblock` ในหลาย Module ทำให้ Scan ของ IP เดียวขยายไปทั้ง Netblock ที่ Target **เป็นเจ้าของ**
- ถ้าไม่ต้องการ ให้ตั้ง `netblocklookup = 0` ใน Module ที่ใช้ (เช่น `sfp_shodan`, `sfp_virustotal`, `sfp_spamhaus`)

```
sf> set module.sfp_shodan.netblocklookup = 0
```
คำนวณขนาดก่อน Scan:
```bash
python3 -c "import ipaddress;n=ipaddress.ip_network('203.0.113.0/24');print(n.num_addresses)"
```

## 17. WHOIS
```bash
python3 sf.py -s example.com -m sfp_whois,sfp_email,sfp_names,sfp_phone,sfp_company \
  -F DOMAIN_REGISTRAR,EMAILADDR,HUMAN_NAME,PHONE_NUMBER,COMPANY_NAME -o csv -r -n -q
```
- `sfp_whois` ผลิตข้อความดิบ (`DOMAIN_WHOIS`) แล้ว Module Content Analysis ดึง Entity ออกมา
- Correlation: `email_in_whois` (INFO), `human_name_in_whois` (INFO), `outlier_registrar` (MEDIUM — Registrar ที่ต่างจาก Domain ส่วนใหญ่ขององค์กร)
- Module WHOIS เชิงประวัติ/Reverse WHOIS: `sfp_reversewhois`, `sfp_whoxy*`, `sfp_whoisology*`, `sfp_jsonwhoiscom*`

ตรวจยืนยัน:
```bash
whois example.com | grep -Ei 'registrar|creation|expir|name server'
```
> **หมายเหตุ:** WHOIS ของหลาย TLD ปกปิด Contact แล้ว ถ้า `sfp_email` ได้ Email ของบริการ Privacy อย่า Pivot ต่อ (ตั้งเป็น False Positive)

## 18. Certificate Intelligence
```bash
python3 sf.py -s www.example.com -m sfp_dnsresolve,sfp_sslcert \
  -F SSL_CERTIFICATE_ISSUED,SSL_CERTIFICATE_ISSUER,SSL_CERTIFICATE_EXPIRED,SSL_CERTIFICATE_EXPIRING,SSL_CERTIFICATE_MISMATCH -H -q
```

| Event | ความหมาย |
|---|---|
| `SSL_CERTIFICATE_ISSUED` | Subject ของ Certificate |
| `SSL_CERTIFICATE_ISSUER` | CA ที่ออก |
| `SSL_CERTIFICATE_MISMATCH` | ชื่อ Host ไม่ตรงกับ Certificate |
| `SSL_CERTIFICATE_EXPIRED` / `_EXPIRING` | หมดอายุ / ใกล้หมด (`certexpiringdays` = 30) |
| `SSL_CERTIFICATE_RAW` | Certificate ดิบ (Module อื่นดึง Hostname/Email ต่อได้) |

Correlation: `cert_expired` (MEDIUM), `strong_affiliate_certs` (INFO — Affiliate ที่ใช้ Certificate ร่วมกับ Target)

ตรวจยืนยัน:
```bash
echo | openssl s_client -connect www.example.com:443 -servername www.example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

## 19. Email Intelligence
### 19.1 Workflow: Email → Domain → Breach → Username → Profiles → Infrastructure
> **ขอบเขต:** SpiderFoot ค้นเฉพาะข้อมูลที่บริการภายนอกเปิดเผยหรือให้ผ่าน API ตามสิทธิ์ของ Key ที่คุณมี ไม่สามารถเข้าถึงกล่องจดหมาย บัญชีที่ต้อง Login หรือข้อมูล Private ใด ๆ และไม่ควรพยายามทำเช่นนั้น

```bash
E=alice@example.com; D=${E#*@}
# 1 Email → Domain: SpiderFoot ไม่แยก Domain จาก Email ให้ → ตัดด้วย Shell แล้ว Scan Domain
python3 sf.py -s $D -m sfp_dnsresolve,sfp_dnsraw -F PROVIDER_MAIL,PROVIDER_DNS,IP_ADDRESS -H -q
# 2 Breach (ต้องมี API Key)
python3 sf.py -s $E -m sfp_haveibeenpwned,sfp_emailrep -F EMAILADDR_COMPROMISED,MALICIOUS_EMAILADDR -H -q
# 3 Username + Public Profiles
python3 sf.py -s $E -m sfp_accounts,sfp_gravatar,sfp_pgp -F USERNAME,ACCOUNT_EXTERNAL_OWNED,SOCIAL_MEDIA,PGP_KEY -H -q
```
- ทดสอบแล้ว: Scan Target แบบ Email ด้วย `sfp_dnsresolve`/`sfp_dnsraw` ได้เพียง Event ของ Target เอง Module ที่แปลง `EMAILADDR` → Domain/Host มีเฉพาะแบบ API (เช่น `sfp_securitytrails*`, `sfp_intelx*`, `sfp_binaryedge*`) ซึ่งเป็นการค้นย้อนกลับ ไม่ใช่การตัดส่วนหลัง `@`
- `sfp_accounts` ใช้ `userfromemail` = True ดึงส่วนหน้า `@` เป็น Username แล้วตรวจบัญชี
- `EMAILADDR_GENERIC` = Email แบบ Role (info@, admin@) ตาม `_genericusers`
- Correlation: `email_in_multiple_breaches` (HIGH), `email_only_from_pasteleak_site` (MEDIUM), `outlier_email` (INFO)

### 19.2 หา Email ขององค์กรจาก Domain
```bash
python3 sf.py -s example.com -m sfp_dnsresolve,sfp_emailformat,sfp_pgp,sfp_hunter,sfp_spider,sfp_email \
  -F EMAILADDR,EMAILADDR_GENERIC -o csv -r -q
```

## 20. Username Intelligence
### 20.1 Workflow: Username → Public Accounts → Websites → Profiles → Related Domains → Metadata
```bash
U=alice_example
python3 sf.py -s $U -m sfp_accounts,sfp_github,sfp_keybase -o json -q > $R/user-$U.json
jq -r '.[] | select(.type|test("Account|Social|Code Repo|PGP|Bitcoin")) | "\(.type)\t\(.data)"' $R/user-$U.json
```
ขั้นต่อจากผลลัพธ์:
1. `ACCOUNT_EXTERNAL_OWNED` → เปิดดู Profile ด้วยตนเอง บันทึก Screenshot (บท 60)
2. ลิงก์ Website ใน Profile → ใช้ Hostname เป็น Target ใหม่ (บท 11)
3. `PUBLIC_CODE_REPO` จาก `sfp_github` → Domain ที่ปรากฏใน Repo สาธารณะ
4. Metadata ของไฟล์บนเว็บไซต์ที่เกี่ยวข้อง → บท 40

> **คำเตือน:** เน้นข้อมูลสาธารณะเท่านั้น ห้ามพยายาม Login, เดารหัสผ่าน, Reset password หรือเข้าถึงบัญชีใด ๆ Username ซ้ำกันบนหลายเว็บไม่ได้แปลว่าเป็นคนเดียวกัน (บท 42)

## 21. Person Intelligence
```bash
python3 sf.py -s '"Alice Example"' -m sfp_accounts,sfp_arin -o json -q > $R/person.json
```
- Target ต้องอยู่ใน `"..."` และมีช่องว่าง → `HUMAN_NAME`
- `sfp_names` (Flag `errorprone`) ดึงชื่อคนจากข้อความ มี False Positive สูง
- ทำเฉพาะเมื่อบุคคลอยู่ในขอบเขตงาน (เช่น ผู้บริหารขององค์กรที่ว่าจ้างให้ประเมิน) และเก็บข้อมูลเท่าที่จำเป็น

## 22. Organization Intelligence
SpiderFoot 4.0 ไม่มี Target ชนิดองค์กร ใช้ Domain ขององค์กรเป็นจุดเริ่ม:
```bash
python3 sf.py -s example.com -m sfp_dnsresolve,sfp_whois,sfp_sslcert,sfp_company,sfp_gleif \
  -F COMPANY_NAME,LEI,AFFILIATE_COMPANY_NAME,PHYSICAL_ADDRESS -o csv -r -q
```
- `sfp_company` ดึง `COMPANY_NAME` จาก WHOIS, Certificate และเนื้อหาเว็บ
- `sfp_gleif` ค้นทะเบียน LEI (`LEI`, ที่อยู่), `sfp_opencorporates*` ค้นทะเบียนบริษัท
- ชื่อบริษัทซ้ำกันข้ามประเทศได้ ยืนยันด้วยที่อยู่/เลขทะเบียน

## 23. Website Intelligence
```bash
python3 sf.py -s www.example.com \
  -m sfp_dnsresolve,sfp_spider,sfp_webserver,sfp_strangeheaders,sfp_pageinfo,sfp_cookie,sfp_errors,sfp_intfiles \
  -o json -q > $R/web.json
jq -r '.[].type' $R/web.json | sort | uniq -c | sort -rn
```
ปรับ Spider ก่อน Scan เว็บใหญ่:
```
sf> set module.sfp_spider.maxpages = 50
sf> set module.sfp_spider.maxlevels = 2
sf> set module.sfp_spider.pausesec = 1
sf> set module.sfp_spider.robotsonly = 1
```
- `robotsonly` = ดึงเฉพาะที่ robots.txt อนุญาต
- ผลที่ควรดู: `WEBSERVER_BANNER`, `WEBSERVER_STRANGEHEADER`, `URL_FORM`, `URL_PASSWORD`, `URL_UPLOAD`, `INTERESTING_FILE`, `ERROR_MESSAGE`
- Correlation: `http_errors` (LOW), `root_path_needs_auth` (INFO), `outlier_webserver` (MEDIUM)

## 24. URL Intelligence
URL ไม่ใช่ Target ได้ แต่เป็น Event ที่เกิดระหว่าง Scan:
```
LINKED_URL_INTERNAL  LINKED_URL_EXTERNAL
URL_FORM  URL_PASSWORD  URL_UPLOAD  URL_JAVASCRIPT  URL_WEB_FRAMEWORK  URL_STATIC  URL_FLASH  URL_JAVA_APPLET
*_HISTORIC (จาก sfp_archiveorg)
```

```bash
python3 sf.py -s www.example.com -m sfp_dnsresolve,sfp_spider,sfp_archiveorg,sfp_commoncrawl \
  -F LINKED_URL_INTERNAL,URL_PASSWORD,URL_PASSWORD_HISTORIC,INTERESTING_FILE_HISTORIC -H -q
```
- `sfp_archiveorg` (Flag `slow`) ดู Snapshot ย้อนหลัง (`farback` = 30,60,90 วัน)
- ได้ URL ที่มาจาก Log ของผู้ใช้ (เช่น urlscan) → อาจมี Token/Parameter ส่วนตัว ห้ามเปิดใช้งาน ให้บันทึกเป็นหลักฐานและแจ้งเจ้าของระบบ

## 25. Web Technology Discovery
```bash
python3 sf.py -s www.example.com -m sfp_dnsresolve,sfp_spider,sfp_webserver,sfp_webframework,sfp_webanalytics,sfp_google_tag_manager \
  -F WEBSERVER_BANNER,WEBSERVER_TECHNOLOGY,URL_WEB_FRAMEWORK,WEB_ANALYTICS_ID,SOFTWARE_USED -H -q
```
ขยายด้วย Tool module (ต้องติดตั้งและตั้ง Path ตามบท 8.5): `sfp_tool_whatweb`, `sfp_tool_wappalyzer`, `sfp_tool_cmseek`, `sfp_tool_retirejs`, `sfp_tool_wafw00f`
- `WEB_ANALYTICS_ID` ใช้ Pivot หาเว็บไซต์อื่นที่ใช้ ID เดียวกัน (`sfp_shodan` รับ `WEB_ANALYTICS_ID`, `sfp_spyonweb*`)
- ID เดียวกันเป็นตัวบ่งชี้ว่ามีผู้ดูแลร่วม ไม่ใช่หลักฐานความเป็นเจ้าของ

## 26. Public Infrastructure Discovery
ข้อมูล Port/Service สาธารณะหาได้สองแบบ:

| แบบ | Module | ติดต่อเป้าหมาย |
|---|---|---|
| ฐานข้อมูลของ Provider | `sfp_shodan*`, `sfp_censys*`, `sfp_binaryedge*`, `sfp_leakix*`, `sfp_onyphe*`, `sfp_fullhunt*` | ไม่ |
| สแกนเอง | `sfp_portscan_tcp`, `sfp_tool_nmap` (Flag `invasive`) | ใช่ |

```bash
python3 sf.py -s 203.0.113.10 -m sfp_shodan,sfp_leakix \
  -F TCP_PORT_OPEN,TCP_PORT_OPEN_BANNER,SOFTWARE_USED,VULNERABILITY_CVE_HIGH,VULNERABILITY_CVE_CRITICAL -n -H -q
```
Correlation ที่ได้จากข้อมูลกลุ่มนี้: `database_exposed` (HIGH), `remote_desktop_exposed` (HIGH), `open_port_version` (INFO), `vulnerability_critical` / `vulnerability_high` (HIGH), `vulnerability_mediumlow` (MEDIUM)

> **คำเตือน:** ผล CVE ของ Provider มาจากการจับคู่เวอร์ชันใน Banner ต้องยืนยันกับเจ้าของระบบก่อนรายงาน และ `sfp_portscan_tcp` ใช้กับระบบที่ได้รับอนุญาตเท่านั้น

## 27. Cloud Infrastructure OSINT
```bash
python3 sf.py -s example.com -m sfp_s3bucket,sfp_azureblobstorage,sfp_googleobjectstorage,sfp_digitaloceanspace \
  -F CLOUD_STORAGE_BUCKET,CLOUD_STORAGE_BUCKET_OPEN -o csv -r -q
```
- Module กลุ่มนี้สร้างชื่อ Bucket จากชื่อ Domain + `suffixes` แล้วตรวจกับ Endpoint ของ Cloud Provider
- `CLOUD_STORAGE_BUCKET_OPEN` → Correlation `cloud_bucket_open` (HIGH) ถ้าเป็น Bucket ที่เกี่ยวข้องกับ Target
- `cloud_bucket_open_related` (LOW) = Bucket ที่เปิดแต่ความเกี่ยวข้องอ่อน
- `outlier_cloud` (MEDIUM) = Cloud provider ที่ต่างจากส่วนใหญ่ของ Infrastructure
- `sfp_grayhatwarfare*` ค้นฐานข้อมูล Bucket สาธารณะ

> **คำเตือน:** ชื่อ Bucket ที่ตรงกับ Pattern ไม่ได้แปลว่าเป็นขององค์กร ห้ามดาวน์โหลดเนื้อหาจาก Bucket ของผู้อื่น ให้บันทึกชื่อ/สถานะและแจ้งเจ้าของ (บท 42)

## 28. Search Engine Intelligence
| Module | ต้องใช้ | ผลิต |
|---|---|---|
| `sfp_googlesearch` | `api_key` + `cse_id` (Google Custom Search) | `LINKED_URL_INTERNAL`, `RAW_RIR_DATA` |
| `sfp_bingsearch` | `api_key` | `LINKED_URL_INTERNAL`, `RAW_RIR_DATA` |
| `sfp_bingsharedip` | `api_key` | Co-host บน IP เดียวกัน |
| `sfp_duckduckgo` | ไม่ต้อง | `DESCRIPTION_CATEGORY`, `DESCRIPTION_ABSTRACT` |
| `sfp_pastebin` | Google `api_key` + `cse_id` | ผลค้นหาบน Paste site |

```
sf> set module.sfp_googlesearch.api_key = YOUR_API_KEY
sf> set module.sfp_googlesearch.cse_id = <CSE_ID>
```
- Search Engine API ส่วนใหญ่คิดตามจำนวน Query ใช้กับ Target ที่คัดแล้ว
- `LINKED_URL_INTERNAL` ที่ได้จะไหลต่อไปยัง `sfp_intfiles`, `sfp_filemeta` ถ้าเปิดไว้

## 29. Social Media Intelligence
```bash
python3 sf.py -s www.example.com -m sfp_dnsresolve,sfp_spider,sfp_social,sfp_twitter,sfp_github \
  -F SOCIAL_MEDIA,USERNAME,PUBLIC_CODE_REPO,GEOINFO -H -q
```
- `sfp_social` ระบุลิงก์ Social จาก `LINKED_URL_EXTERNAL` ของเว็บไซต์ → `SOCIAL_MEDIA`, `USERNAME`
- `sfp_twitter` อ่านชื่อ/ตำแหน่งจากหน้า Profile ที่ `sfp_social` พบ
- `sfp_socialprofiles*` หา Profile จาก `HUMAN_NAME` ผ่าน Search API (Flag `slow`, `apikey`)
- แพลตฟอร์ม Social เปลี่ยนหน้าเว็บและนโยบายบ่อย Module อาจคืนผลว่างโดยไม่มี Error ตรวจด้วยตาเสมอ

## 30. Dark Web / Onion Intelligence
| Module | Flags | Input |
|---|---|---|
| `sfp_ahmia` | tor | `DOMAIN_NAME`, `HUMAN_NAME`, `EMAILADDR` |
| `sfp_onionsearchengine` | tor | `DOMAIN_NAME`, `HUMAN_NAME`, `EMAILADDR` |
| `sfp_torch` | errorprone, tor | `DOMAIN_NAME`, `HUMAN_NAME`, `EMAILADDR` |
| `sfp_onioncity` | apikey, tor | `INTERNET_NAME`, `DOMAIN_NAME` |
| `sfp_intelx` | apikey | หลายชนิด → `DARKNET_MENTION_URL`, `LEAKSITE_URL` |

```bash
python3 sf.py -s example.com -m sfp_ahmia,sfp_onionsearchengine -F DARKNET_MENTION_URL -H -q
```
- ผล `DARKNET_MENTION_URL` คือ "มีการกล่าวถึง" ไม่ใช่หลักฐานการรั่วไหล
- Option `fetchlinks` ของ `sfp_ahmia`/`sfp_onionsearchengine` จะดึงเนื้อหาหน้าที่พบ (ต้องผ่าน TOR) ถ้าไม่ต้องการให้เครื่องเข้าถึงหน้าเหล่านั้น ให้ตั้ง `fetchlinks = 0`
- ถ้าต้องใช้ TOR ตั้ง `_socks1type = TOR`, `_socks2addr = 127.0.0.1`, `_socks3port = 9050` (บท 6.5)

> **คำเตือน:** ใช้เพื่อเฝ้าระวังการกล่าวถึงองค์กรของตนเองเท่านั้น ห้ามดาวน์โหลด ซื้อ หรือเผยแพร่ข้อมูลที่รั่วไหล

## 31. Breach Intelligence
| Module | Model | Output สำคัญ |
|---|---|---|
| `sfp_haveibeenpwned` | COMMERCIAL_ONLY | `EMAILADDR_COMPROMISED` |
| `sfp_dehashed` | COMMERCIAL_ONLY | `EMAILADDR_COMPROMISED`, `PASSWORD_COMPROMISED`, `HASH_COMPROMISED` |
| `sfp_citadel` (Leak-Lookup) | apikey | `EMAILADDR_COMPROMISED` |
| `sfp_leakix` | FREE_AUTH_UNLIMITED | `LEAKSITE_CONTENT` ฯลฯ |
| `sfp_psbdmp`, `sfp_pastebin*`, `sfp_trashpanda*` | — | `LEAKSITE_URL`, `LEAKSITE_CONTENT` |

```bash
python3 sf.py -s example.com -m sfp_dnsresolve,sfp_haveibeenpwned,sfp_psbdmp \
  -F EMAILADDR_COMPROMISED,LEAKSITE_URL -H -q
```
> **คำเตือน:** `sfp_dehashed` ผลิต `PASSWORD_COMPROMISED` และ `HASH_COMPROMISED` ซึ่งเป็น Credential ที่รั่ว ถ้าไม่มีอำนาจตามกฎหมาย/สัญญาในการประมวลผลข้อมูลนี้ **อย่าเปิด Module นี้** แม้ใช้ `-F` กรองการแสดงผล ข้อมูลก็ยังถูกบันทึกลง Database ห้ามนำรหัสผ่านไปทดลอง Login ในทุกกรณี

ใช้ผลเพื่อ: บังคับเปลี่ยนรหัสผ่าน, เปิด MFA, Awareness Training ขององค์กรตนเอง

## 32. Threat Intelligence
### 32.1 Output หลักของกลุ่ม Reputation/TI
```
MALICIOUS_IPADDR  MALICIOUS_INTERNET_NAME  MALICIOUS_EMAILADDR  MALICIOUS_ASN  MALICIOUS_NETBLOCK
MALICIOUS_SUBNET  MALICIOUS_COHOST  MALICIOUS_AFFILIATE_IPADDR  MALICIOUS_AFFILIATE_INTERNET_NAME
BLACKLISTED_IPADDR  BLACKLISTED_INTERNET_NAME  BLACKLISTED_SUBNET  BLACKLISTED_NETBLOCK  BLACKLISTED_COHOST
```

### 32.2 Scan แบบ TI บน IOC หนึ่งตัว (Strict)
```bash
python3 sf.py -s 198.51.100.77 -t MALICIOUS_IPADDR,BLACKLISTED_IPADDR -x -o csv -r -q
```

### 32.3 ชั้นของความรุนแรง
- `MALICIOUS_IPADDR` ของ **ตัว Target** = สัญญาณตรง
- `MALICIOUS_SUBNET` / `MALICIOUS_NETBLOCK` = IP อื่นใน Subnet/Netblock เดียวกันถูกรายงาน (อ่อนกว่า)
- `MALICIOUS_COHOST` / `MALICIOUS_AFFILIATE_*` = สิ่งที่อยู่ร่วม/เกี่ยวข้อง (อ่อนที่สุด)
- Correlation `multiple_malicious` (HIGH) กรอง Subnet, Affiliate และ Co-host ออกก่อน แล้วรายงานเมื่อ ≥ 2 แหล่ง

### 32.4 Custom Threat Feed
```bash
mkdir -p ~/feeds && cat > ~/feeds/internal-ioc.txt << 'EOF'
198.51.100.77
update-check.example.net
EOF
(cd ~/feeds && python3 -m http.server 8088 --bind 127.0.0.1) &
```

```
sf> set module.sfp_customfeed.url = http://127.0.0.1:8088/internal-ioc.txt
```

```bash
python3 sf.py -s update-check.example.net -m sfp_dnsresolve,sfp_customfeed -F MALICIOUS_INTERNET_NAME,MALICIOUS_IPADDR -H -q
```
- รูปแบบ Feed: ข้อความธรรมดา 1 รายการต่อบรรทัด เทียบแบบตรงตัวกับ Host/IP (ตรวจจาก `modules/sfp_customfeed.py`)
- Module Cache Feed ตาม `cacheperiod` ถ้าแก้ Feed แล้วผลไม่เปลี่ยน ให้ตั้ง `cacheperiod = 0` ระหว่างทดสอบ

## 33. Malware Intelligence
สิ่งที่ SpiderFoot 4.0 ทำได้และทำไม่ได้:

| ทำได้ | ทำไม่ได้ |
|---|---|
| ตรวจ IP/Domain กับ Feed ที่เกี่ยวกับ Malware (`sfp_abusech`, `sfp_threatfox`, `sfp_vxvault`, `sfp_cybercrimetracker`, `sfp_malwarepatrol*`) | รับ File Hash เป็น Target (ไม่มี Target type และไม่มี Module ที่รับ `HASH`) |
| หา Domain/URL ที่เกี่ยวข้องจาก Sandbox (`sfp_hybrid_analysis*` รับ `IP_ADDRESS`, `DOMAIN_NAME`) | วิเคราะห์ไฟล์ |
| ดึง Hash ที่ปรากฏในเนื้อหา (`sfp_hashes` → `HASH`) | ค้นรายงาน Malware จาก Hash |
| ตรวจแอป Mobile ที่ผูกกับ Domain (`sfp_koodous*`) | |

Workflow สำหรับ Hash:
1. ค้น Hash ด้วยบริการ TI ภายนอก (เช่น VirusTotal Web/API ตามสิทธิ์ของคุณ) → ได้ Domain/IP ที่ Sandbox บันทึก
2. ใช้ Domain/IP เหล่านั้นเป็น Target ของ SpiderFoot (บท 34)
3. ใช้ Hash ไฟล์ทดสอบ EICAR สำหรับฝึก: `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`

```bash
python3 sf.py -s update-check.example.net \
  -m sfp_dnsresolve,sfp_abusech,sfp_threatfox,sfp_vxvault,sfp_cybercrimetracker,sfp_hybrid_analysis \
  -o json -q > $R/malinfra.json
jq -r '.[] | select(.type|startswith("Malicious")) | "\(.module)\t\(.type)\t\(.data)"' $R/malinfra.json
```

## 34. IOC Investigation
### 34.1 IOC List → Scan ละตัว
```bash
cat > $R/iocs.txt << 'EOF'
update-check.example.net
cdn-sync.example.org
198.51.100.77
203.0.113.45
EOF
mkdir -p $R/ioc
while read -r ioc; do
  [ -z "$ioc" ] && continue
  python3 sf.py -s "$ioc" -t MALICIOUS_IPADDR,MALICIOUS_INTERNET_NAME,BLACKLISTED_IPADDR,BLACKLISTED_INTERNET_NAME \
    -x -o json -q > "$R/ioc/$(echo "$ioc" | tr '/:' '__').json"
done < $R/iocs.txt
```

### 34.2 รวมผล
```bash
for f in $R/ioc/*.json; do
  jq -r --arg f "$(basename $f .json)" '.[] | select(.type|test("Malicious|Blacklisted")) | [$f,.module,.type,.data] | @tsv' "$f"
done | sort -u > $R/ioc-hits.tsv
cut -f1 $R/ioc-hits.tsv | sort | uniq -c | sort -rn
```
- `-x` ทำให้แต่ละ Scan ไม่ขยายตัว เหมาะกับ IOC จำนวนมาก
- IOC ที่ไม่มี Hit ≠ ปลอดภัย แปลว่าแหล่งที่เปิดใช้ไม่มีข้อมูล

## 35. Reputation Intelligence
### 35.1 DNSBL และ DNS Filter
| กลุ่ม | Module |
|---|---|
| DNSBL (IP/Domain) | `sfp_spamhaus`, `sfp_sorbs`, `sfp_spamcop`, `sfp_uceprotect`, `sfp_surbl`, `sfp_dronebl`, `sfp_abusix*` |
| DNS Filter (Host ถูก Block หรือไม่) | `sfp_quad9`, `sfp_opendns`, `sfp_cleanbrowsing`, `sfp_adguard_dns`, `sfp_cloudflaredns`, `sfp_yandexdns`, `sfp_comodo`, `sfp_dns_for_family` |
| Phishing | `sfp_openphish`, `sfp_phishtank`, `sfp_phishstats`, `sfp_googlesafebrowsing*` |

```bash
python3 sf.py -s mail.example.com -m sfp_dnsresolve,sfp_spamhaus,sfp_sorbs,sfp_spamcop,sfp_uceprotect \
  -F BLACKLISTED_IPADDR,MALICIOUS_IPADDR -o csv -r -q
```
> **หมายเหตุ:** DNSBL บางรายจำกัดหรือบล็อก Query ที่มาจาก Public DNS Resolver ขนาดใหญ่ ผลอาจว่างหรือผิดพลาด ถ้าองค์กรมี Resolver ของตัวเอง ให้ตั้ง `_dnsserver` (บท 6.6) และตรวจเงื่อนไขการใช้งานของแต่ละ DNSBL

### 35.2 ตรวจยืนยัน DNSBL ด้วยมือ
```bash
IP=203.0.113.25; REV=$(echo $IP | awk -F. '{print $4"."$3"."$2"."$1}')
dig +short $REV.zen.spamhaus.org
```
- ไม่มีคำตอบ = ไม่อยู่ในรายการ
- คำตอบเป็น `127.0.0.x` = อยู่ในรายการ (ความหมายของแต่ละค่าดูเอกสารของ DNSBL)

## 36. Passive DNS
Module ใน Category `Passive DNS` (15 ตัว):
```
sfp_crobat_api sfp_dnsdb* sfp_dnsdumpster sfp_dnsgrep sfp_google_tag_manager sfp_hackertarget
sfp_hostio* sfp_mnemonic sfp_networksdb* sfp_projectdiscovery* sfp_robtex sfp_spyonweb*
sfp_sublist3r sfp_zetalytics* sfp_zonefiles*
```

```bash
python3 sf.py -s 203.0.113.10 -m sfp_mnemonic,sfp_robtex,sfp_hackertarget -F CO_HOSTED_SITE,INTERNET_NAME -o csv -r -q
```
ตัวควบคุมอายุและปริมาณข้อมูล:
- `sfp_mnemonic`: `maxage` (180 วัน), `per_page`, `max_pages`, `maxcohost`
- `sfp_threatminer`: `age_limit_days` (90)
- `sfp_alienvault`: `cohost_age_limit_days` (30)
- `cohostsamedomain` = False → ไม่รายงาน Co-host ที่อยู่ใน Domain เดียวกับ Target

Passive DNS คือ "ประวัติ" ต้องดูอายุข้อมูลก่อนสรุปว่ายังใช้งานอยู่ ตรวจปัจจุบันด้วย `dig`

## 37. Certificate Transparency
```bash
python3 sf.py -s example.com -m sfp_crt,sfp_certspotter -F INTERNET_NAME,INTERNET_NAME_UNRESOLVED,CO_HOSTED_SITE -o csv -r -q
```
- `sfp_crt` = crt.sh (ไม่ต้องใช้ Key), `sfp_certspotter` = SSLMate (ต้องใช้ Key, `max_pages` 20)
- `fetchcerts` ของ `sfp_crt` (Default True) = ดึง Certificate เต็มทีละใบเพื่อให้ Module อื่นวิเคราะห์ต่อ — จากการทดสอบใช้ 4–11 วินาทีต่อใบ Domain ที่มี Certificate หลายร้อยใบจะช้ามาก ตั้ง `0` ถ้าต้องการแค่ Hostname
- `verify` = ตรวจว่าชื่อยัง Resolve ได้ (ไม่ได้ → `INTERNET_NAME_UNRESOLVED`)
- Correlation `host_only_from_certificatetransparency` (LOW) ชี้ชื่อที่พบจาก CT อย่างเดียว

ตรวจยืนยัน:
```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u | head
```

## 38. Geolocation-related Intelligence
```bash
python3 sf.py -s 203.0.113.10 -m sfp_ipapico,sfp_ripe,sfp_bgpview,sfp_countryname -F GEOINFO,PHYSICAL_ADDRESS,COUNTRY_NAME -H -q
```

| Event | ที่มา |
|---|---|
| `GEOINFO` | GeoIP (`sfp_ipapico`, `sfp_ipinfo*`, `sfp_ipstack*`, `sfp_ipapicom*`, `sfp_ipregistry*`), Shodan, GitHub |
| `PHYSICAL_ADDRESS` | Registry (`sfp_bgpview`), WHOIS, GLEIF |
| `PHYSICAL_COORDINATES` | `sfp_googlemaps*`, `sfp_openstreetmap` |
| `COUNTRY_NAME` | `sfp_countryname` (จาก TLD, WHOIS, Phone ฯลฯ) |

- GeoIP = ตำแหน่งโดยประมาณของเครือข่าย ไม่ใช่ตำแหน่งบุคคลหรือเครื่อง
- Correlation `outlier_country` (INFO) ชี้ประเทศที่ต่างจากส่วนใหญ่ของ Infrastructure

## 39. Cryptocurrency-related Intelligence
```bash
# Target เป็น Bitcoin address โดยตรง
python3 sf.py -s <BTC_ADDRESS> -m sfp_blockchain -F BITCOIN_BALANCE -H -q
# หา Address จากเว็บไซต์ของตนเอง/ในขอบเขต
python3 sf.py -s www.example.org -m sfp_dnsresolve,sfp_spider,sfp_bitcoin,sfp_ethereum,sfp_etherscan \
  -F BITCOIN_ADDRESS,ETHEREUM_ADDRESS,ETHEREUM_BALANCE -H -q
```
- `sfp_bitcoin` / `sfp_ethereum` ดึง Address จาก `TARGET_WEB_CONTENT`
- `sfp_blockchain` → `BITCOIN_BALANCE`, `sfp_etherscan*` → `ETHEREUM_BALANCE`
- `sfp_bitcoinabuse*`, `sfp_bitcoinwhoswho*` → `MALICIOUS_BITCOIN_ADDRESS`
- Ethereum address ใช้เป็น Target ไม่ได้ใน 4.0 ต้องได้มาจากเนื้อหาเว็บ
- SpiderFoot ไม่ทำ Transaction tracing หรือ Clustering

## 40. Metadata Intelligence
```bash
python3 sf.py -s www.example.com -m sfp_dnsresolve,sfp_spider,sfp_intfiles,sfp_filemeta,sfp_names,sfp_email \
  -F INTERESTING_FILE,RAW_FILE_META_DATA,SOFTWARE_USED,HUMAN_NAME,EMAILADDR -o json -q > $R/meta.json
jq -r '.[] | select(.type=="Software Used") | .data' $R/meta.json | sort | uniq -c | sort -rn
```
- `sfp_intfiles` หาไฟล์ตามนามสกุล (`doc, docx, ppt, pptx, pdf, xls, xlsx, zip`)
- `sfp_filemeta` ดาวน์โหลดไฟล์ (`fileexts`: docx, pptx, pdf, jpg, jpeg, tiff, tif; `timeout` 300) แล้วดึง Metadata
- Correlation `data_from_docmeta` (INFO) รายงาน Entity ที่มาจาก Metadata

> **หมายเหตุ:** `sfp_filemeta` ดาวน์โหลดไฟล์จากเว็บไซต์เป้าหมาย ใช้กับเว็บไซต์ในขอบเขต และเก็บ Hash ของไฟล์ต้นทางด้วยเครื่องมือแยก (บท 60)

## 41. Event Correlation
### 41.1 โครงสร้างของ Event ในฐานข้อมูล
```
hash               SHA256 ของ Event (ID)
type               Event Type (เช่น IP_ADDRESS)
module             Module ที่สร้าง
data               ค่า
source_event_hash  hash ของ Event แม่ ('ROOT' = Target)
confidence         0–100 (Default 100)
visibility         0–100 (Default 100)
risk               0–100 (Default 0)
false_positive     0/1
generated          Epoch seconds
```
Event Category (คอลัมน์ `event_type` ใน `tbl_event_types`): `ENTITY`, `SUBENTITY`, `DESCRIPTOR`, `DATA`, `INTERNAL`

### 41.2 Correlation Rules ใน 4.0.0 (37 Rule)
```
HIGH   cloud_bucket_open database_exposed dns_zone_transfer_possible email_in_multiple_breaches
       multiple_malicious remote_desktop_exposed stale_host vulnerability_critical vulnerability_high
MEDIUM cert_expired dev_or_test_system egress_ip_from_wikipedia email_only_from_pasteleak_site
       internal_host name_only_from_pasteleak_site outlier_cloud outlier_registrar outlier_webserver
       vulnerability_mediumlow
LOW    cloud_bucket_open_related host_only_from_bruteforce host_only_from_certificatetransparency
       http_errors multiple_malicious_affiliate multiple_malicious_cohost
INFO   data_from_base64 data_from_docmeta email_in_whois human_name_in_whois open_port_version
       outlier_country outlier_email outlier_hostname outlier_ipaddress root_path_needs_auth
       strong_affiliate_certs strong_similardomain_crossref
```

### 41.3 ดูผล Correlation
```
sf> correlations 143B53FF
sf> correlations 143B53FF -c <correlation_id>
```
หรือ Web UI → แท็บ **Correlations** หรือ HTTP:
```bash
curl -s "http://127.0.0.1:5001/scancorrelations?id=143B53FF" | jq -r '.[] | [.[3], .[1], .[7]] | @tsv'
```
ลำดับฟิลด์ของ `scancorrelations`: `[id, title, rule_id, rule_risk, rule_name, rule_descr, rule_logic, event_count]`

### 41.4 โครงสร้าง Rule (YAML)
```yaml
id: <ต้องตรงกับชื่อไฟล์>
version: 1
meta:
  name: ...
  description: ...
  risk: INFO | LOW | MEDIUM | HIGH
collections:
  - collect:
      - method: exact | regex      # method แรก = ดึงจาก DB, ถัดไป = กรอง
        field: type | module | data   # หลัง method แรกใช้ source./child./entity. นำหน้าได้
        value: ...                  # regex ขึ้นต้นด้วย "not " เพื่อกลับเงื่อนไข
aggregation:
  field: data
analysis:
  - method: threshold | outlier | first_collection_only | match_all_to_first_collection
headline: "ข้อความ {data}"
```

### 41.5 เขียน Rule เอง: Host ที่ชื่อมี "vpn" หรือ "remote"
```bash
cat > correlations/remote_access_hostname.yaml << 'EOF'
id: remote_access_hostname
version: 1
meta:
  name: Host with a remote-access style name was found
  description: >
    A hostname containing vpn, remote or rdp was found. Review whether
    it should be exposed to the Internet.
  risk: INFO
collections:
  - collect:
      - method: exact
        field: type
        value: INTERNET_NAME
      - method: regex
        field: data
        value:
          - .*vpn.*
          - .*remote.*
          - .*rdp.*
aggregation:
  field: data
headline: "Remote-access style host found: {data}"
EOF
python3 sf.py -C 143B53FF
```
- ต้อง **รีสตาร์ต** Web UI Server เพื่อโหลด Rule ใหม่
- ถ้า YAML ผิด `sf.py` จะหยุดตอนเริ่มพร้อม `Failure initializing correlation rules`
- `-C` รัน Rule ทั้งหมดกับ Scan เดิม ทดสอบแล้วว่า Rule ใหม่ถูกโหลด: Log เปลี่ยนเป็น `Running 38 correlation rules against scan, 143B53FF.`
- Rule ที่รันซ้ำอาจให้ผลซ้ำ ตรวจใน Correlations tab

### 41.6 Rule แบบ Threshold (ตัวอย่างจากโครงสร้าง `multiple_malicious`)
```yaml
analysis:
  - method: threshold
    field: source.data
    minimum: 2
```
ใช้เมื่อต้องการรายงานเฉพาะ Entity ที่ถูกพบจากอย่างน้อย N แหล่ง ตัวเลือกเพิ่มเติม: `maximum`, `count_unique_only: true`

## 42. False Positive Analysis
### 42.1 สาเหตุที่ทำให้ความสัมพันธ์หลอกตา
| สาเหตุ | อาการใน SpiderFoot | ตรวจอย่างไร |
|---|---|---|
| Shared Hosting | `CO_HOSTED_SITE` จำนวนมาก | นับ Co-host, ดู `PROVIDER_HOSTING` |
| CDN | IP ของ Target เป็นของ CDN, `MALICIOUS_SUBNET` จาก IP อื่นใน CDN | ดู ASN/Netblock owner |
| Cloud | `NETBLOCK_MEMBER` ของ Cloud provider, `outlier_cloud` | ดู `PROVIDER_HOSTING`, WHOIS Netblock |
| Reverse Proxy / WAF | Banner/Technology ของ Proxy แทนของ Origin | ดู `WEBSERVER_BANNER`, Header |
| Shared Certificate | `strong_affiliate_certs` กับ Domain ของผู้ให้บริการ | ดู Issuer และจำนวน SAN |
| Dynamic IP | `MALICIOUS_IPADDR` ที่เกิดก่อน IP ถูกจัดให้ Target | ดูวันที่ในแหล่ง TI |
| Third-party Service | `AFFILIATE_*` ของ SaaS (Email, Analytics) | ดูว่าเป็น Service ที่องค์กร "ใช้" หรือ "เป็นเจ้าของ" |
| DNS Provider | `PROVIDER_DNS` ร่วมกับ Domain นับล้าน | NS ของผู้ให้บริการรายใหญ่ ≠ ความสัมพันธ์ |

> **หลักสำคัญ:** ความสัมพันธ์จาก OSINT ไม่ได้แปลว่า Entity สองตัวเป็นของเจ้าของเดียวกัน ต้องมีหลักฐานที่เจาะจง (เช่น WHOIS Organization เดียวกันและยืนยันได้, Certificate ที่ออกให้องค์กรนั้นโดยเฉพาะ, ประกาศบนเว็บไซต์ทางการ)

### 42.2 ตรวจ Shared Hosting ด้วย SQL
```bash
DB=$SPIDERFOOT_DATA/spiderfoot.db
sqlite3 -header -column $DB "
SELECT s.data AS ip, COUNT(*) AS cohosts
FROM tbl_scan_results c JOIN tbl_scan_results s
  ON c.source_event_hash = s.hash AND c.scan_instance_id = s.scan_instance_id
WHERE c.scan_instance_id='143B53FF' AND c.type='CO_HOSTED_SITE'
GROUP BY s.data ORDER BY cohosts DESC LIMIT 10;"
```
IP ที่มี Co-host เกิน ~20–50 (ขึ้นกับบริบท) ให้ถือว่าเป็น Shared infrastructure และไม่ใช้ Co-host เป็นหลักฐานความเกี่ยวข้อง

### 42.3 ตรวจ CDN / Cloud
```bash
jq -r '.[] | select(.type=="Hosting Provider") | .data' $R/ip-203.0.113.10.json | sort -u
whois -h whois.cymru.com " -v 203.0.113.10"
curl -sI https://www.example.com | grep -iE '^(server|via|x-cache|cf-|x-served-by)'
```

### 42.4 ตั้ง False Positive
Web UI: Browse → เลือกแถว → ปุ่ม **Set/Unset False Positive flag** → เลือก Set

HTTP (ต้องการ `hash` ของ Event เป็น JSON list):
```bash
curl -s "http://127.0.0.1:5001/resultsetfp" \
  --data-urlencode "id=143B53FF" \
  --data-urlencode 'resultids=["<EVENT_HASH>"]' \
  --data-urlencode "fp=1"
```
- ผลที่ถูกต้อง: `["SUCCESS", ""]` และคอลัมน์ F/P ของ Event เปลี่ยนเป็น `1`
- Event ลูกทั้งหมดของ Event ที่ตั้ง FP จะถูกตั้ง FP ตามไปด้วย / ใช้ `fp=0` เพื่อยกเลิก
- Export ที่มีคอลัมน์ `F/P` / `false_positive` ใช้กรองออกได้
- ตรวจรายการที่ตั้ง FP แล้ว:

```bash
sqlite3 $DB "SELECT type, data FROM tbl_scan_results WHERE scan_instance_id='143B53FF' AND false_positive=1;"
```

### 42.5 Module ที่ควรสงสัยเป็นพิเศษ
- Flag `errorprone`: `sfp_names`, `sfp_creditcard`, `sfp_iban`, `sfp_binstring`, `sfp_junkfiles`, `sfp_torch`, `sfp_stackoverflow`
- `sfp_accounts` → `SIMILAR_ACCOUNT_EXTERNAL` (ชื่อคล้าย ไม่ใช่บัญชีเดียวกัน)
- `sfp_similar`, `sfp_tldsearch`, `sfp_tool_dnstwist` → `SIMILARDOMAIN` (ชื่อคล้าย ไม่ใช่ของ Target)

## 43. Graph-Oriented Analysis
### 43.1 Graph ใน Web UI
Scan → แท็บ **Graph** → ใช้ **Force Layout** แล้ว **Save Image** สำหรับ Scan เล็ก

### 43.2 Export GEXF → Gephi
```bash
curl -s "http://127.0.0.1:5001/scanviz?id=143B53FF&gexf=1" -o ~/cases/$CASE/exports/143B53FF.gexf
# หลาย Scan
curl -s "http://127.0.0.1:5001/scanvizmulti?ids=143B53FF,53AC5D63&gexf=1" -o ~/cases/$CASE/exports/multi.gexf
```
หรือ `sf> export 143B53FF -t gexf -f /home/kali/cases/CASE-2026-010-example/exports/143B53FF.gexf` (sfcli ไม่แปลงตัวแปร Shell ต้องใส่ Path เต็ม)

### 43.3 ไล่ Lineage ของ Event ด้วย SQL (Recursive CTE)
ตอบคำถาม "Event นี้มาจากไหน" ย้อนกลับไปถึง Target:
```bash
sqlite3 -header -column $DB "
WITH RECURSIVE chain(hash, type, data, module, parent, depth) AS (
  SELECT hash, type, data, module, source_event_hash, 0 FROM tbl_scan_results
   WHERE scan_instance_id='143B53FF' AND data='203.0.113.10' AND type='IP_ADDRESS'
  UNION ALL
  SELECT r.hash, r.type, r.data, r.module, r.source_event_hash, c.depth+1
    FROM tbl_scan_results r JOIN chain c ON r.hash = c.parent
   WHERE r.scan_instance_id='143B53FF'
)
SELECT depth, type, module, substr(data,1,60) AS data FROM chain;"
```
ผลลัพธ์ (รูปแบบ):
```
depth  type           module          data
0      IP_ADDRESS     sfp_dnsresolve  203.0.113.10
1      INTERNET_NAME  sfp_crt         www.example.com
2      DOMAIN_NAME    SpiderFoot UI   example.com
3      ROOT                           example.com
```
ถ้าค่าเดียวกันถูกพบจากหลาย Source จะเห็นหลายเส้นทาง (Event ซ้ำคนละ `source_event_hash`) ซึ่งเป็นข้อมูลที่มีประโยชน์: ยิ่งหลายเส้นทางอิสระ ยิ่งน่าเชื่อถือ

การส่งต่อไป Maltego ดูบท 61.3

## 44. Investigation Workflow
```
Collection   → Scan เล็กหลายรอบ (Profile ตามงาน)
Processing   → Export JSON/CSV, Normalize, Dedupe (บท 57)
Correlation  → Correlation Rules + Rule ที่เขียนเอง (บท 41)
Validation   → dig/whois/openssl/curl + ดูด้วยตา, ตั้ง FP (บท 42)
Analysis     → SQL/jq/Graph ตอบคำถามของงาน
Reporting    → IOC list, Infrastructure list, Timeline, Executive Summary (บท 59)
```
Template บันทึกต่อรอบ Scan:
```bash
cat >> ~/cases/$CASE/notes/scan-log.md << EOF
## $(date -u +%FT%TZ) scan=<SCAN_ID> target=example.com
- purpose: หา Subdomain แบบ Passive
- modules: $(cat ~/sf-profiles/domain-passive.txt | paste -sd, -)
- result: <จำนวน Event> / notable: <สรุป>
- next: <ขั้นถัดไป หรือเหตุผลที่หยุด>
EOF
```

## 45. Advanced Scan Configuration
| มิติ | ควบคุมด้วย |
|---|---|
| Target | `-s` (ชนิดตามบท 10) |
| Modules | `-m` (แม่นยำ), `-u` (กว้าง) |
| Required Data | `-t` (+ `-f` แสดงเฉพาะที่ขอ) — ต้องคู่กับ `-x` หรือตรวจ Dry-run ก่อน (บท 46.2) |
| Scope/ความลึก | `-x` Strict mode, Option ของ Module (`maxnetblock`, `maxcohost`, `maxlevels`, `maxpages`, `checkaffiliates`, `checkcohosts`) |
| Event Types ที่แสดง | `-F` |
| Correlation | อัตโนมัติหลัง Scan / `-C` |
| API | Settings / `sfcli set module.<m>.api_key` |
| Output | `-o`, `-r`, `-n`, `-S`, `-H`, `-D` |
| Performance | `-max-threads` / `_maxthreads`, `_maxthreads` ของบาง Module |
| Timeout | `_fetchtimeout`, `timeout`/`ssltimeout` ของ Module |
| Rate Limit | `delay`, `pause`, `publicapi` ของ Module |

> **หมายเหตุ:** SpiderFoot 4.0 ไม่มี Option ระดับ Scan ชื่อ "Scan Depth" ความลึกถูกกำหนดโดยชุด Module ที่เปิด, Strict mode และ Option ขยายขอบเขตของแต่ละ Module

### 45.1 ตัวอย่าง Scan ที่ปรับครบ
```bash
python3 sf.py -s example.com \
  -m "$(paste -sd, ~/sf-profiles/domain-passive.txt)" \
  -max-threads 2 -o json 2> $R/scan.log > $R/scan.json
grep -E "Modules enabled|ERROR" $R/scan.log | head
```
ก่อนรัน ปรับ Option ที่มีผลต่อการขยาย:
```
sf> set module.sfp_hackertarget.maxcohost = 20
sf> set module.sfp_hackertarget.netblocklookup = 0
sf> set module.sfp_mnemonic.maxage = 90
sf> set global._fetchtimeout = 10
```

## 46. Module Dependency Analysis
### 46.1 การเลือก Module ด้วย `-t` ทำงานอย่างไร
จาก `start_scan()` ใน `sf.py`:
1. หา Module ทุกตัวที่ **ผลิต** Event Type ที่ขอ
2. สำหรับ Module เหล่านั้น หา Event Type ที่มัน **รับ**
3. หา Module ที่ผลิต Event Type เหล่านั้น → วนซ้ำจนไม่มี Module ใหม่

ผลคือ `-t` หนึ่งชนิดอาจดึง Module จำนวนมาก (4.0.0: `-t IP_ADDRESS,IPV6_ADDRESS` = 148 Module, `-t MALICIOUS_IPADDR` = 181 Module รวม Module `invasive`)

### 46.2 Dry-run ดูว่า `-t` จะเปิด Module อะไร (ไม่เริ่ม Scan)
Script นี้เรียก Logic เดียวกับ `start_scan()` ของ `sf.py` แต่ไม่สร้าง Scan:

```bash
cat > ~/bin/sf-dryrun.py << 'EOF'
#!/usr/bin/env python3
"""ใช้: cd ~/tools/spiderfoot && .venv/bin/python ~/bin/sf-dryrun.py IP_ADDRESS,IPV6_ADDRESS"""
import os, sys
sys.path.insert(0, os.getcwd())   # ต้องรันจากโฟลเดอร์ spiderfoot
from spiderfoot import SpiderFootHelpers
from sflib import SpiderFoot
mods = SpiderFootHelpers.loadModulesAsDict('modules/', ['sfp_template.py'])
sf = SpiderFoot({'__modules__': mods, '_debug': False, '__logging': False})
modlist = sf.modulesProducing(sys.argv[1].split(','))
new = list(modlist)
while new:
    added = []
    for etype in sf.eventsToModules(new):
        for m in sf.modulesProducing([etype]):
            if m not in modlist:
                modlist.append(m)
                added.append(m)
    new = added
print(len(modlist), "modules")
print("invasive:", [m for m in modlist if 'invasive' in (mods[m]['labels'] or [])])
print("apikey  :", sum(1 for m in modlist if 'apikey' in (mods[m]['labels'] or [])))
EOF
cd ~/tools/spiderfoot && .venv/bin/python ~/bin/sf-dryrun.py IP_ADDRESS,IPV6_ADDRESS 2>/dev/null
```
ผลลัพธ์บน 4.0.0 (สองบรรทัดแรก):
```
148 modules
invasive: ['sfp_tool_nuclei', 'sfp_tool_nmap', 'sfp_portscan_tcp']
```
เทียบกับ Strict mode (`-x`) ซึ่งเลือกเฉพาะ Module ที่รับ Target โดยตรง: Target เป็น IP + `-t MALICIOUS_IPADDR,BLACKLISTED_IPADDR -x` = 49 Module และไม่มี Module `invasive`

### 46.3 หา Producer / Consumer จาก modinfo.json
```bash
J=~/cases/$CASE/raw/modinfo.json
# ใครผลิต MALICIOUS_IPADDR
jq -r '.[] | select((.producedEvents|type)=="array" and (.producedEvents|index("MALICIOUS_IPADDR"))) | .module' $J | wc -l
# sfp_filemeta ต้องการอะไร และใครผลิตสิ่งนั้น
jq -r '.[] | select(.module=="sfp_filemeta") | .watchedEvents[]' $J | while read t; do
  echo "== $t <- $(jq -r --arg t $t '.[] | select((.producedEvents|type)=="array" and (.producedEvents|index($t))) | .module' $J | paste -sd' ' -)"
done
```
ผลลัพธ์ (รูปแบบ):
```
== LINKED_URL_INTERNAL <- sfp_alienvault sfp_bingsearch sfp_commoncrawl sfp_googlesearch sfp_spider ...
== INTERESTING_FILE <- sfp_intfiles
```
ข้อสรุป: ถ้าเปิด `sfp_filemeta` โดยไม่มี Module ที่ผลิต `LINKED_URL_INTERNAL` (เช่น `sfp_spider`) Module จะไม่มีข้อมูลให้ทำงาน

### 46.4 Dependency Chain ที่ใช้บ่อย
```
sfp_spider → TARGET_WEB_CONTENT → sfp_email / sfp_phone / sfp_bitcoin / sfp_hashes / sfp_webanalytics
sfp_spider → LINKED_URL_INTERNAL → sfp_intfiles → INTERESTING_FILE → sfp_filemeta
sfp_whois  → DOMAIN_WHOIS → sfp_email / sfp_names / sfp_phone / sfp_company
sfp_dnsraw → PROVIDER_DNS → sfp_dnszonexfer
sfp_ripe   → NETBLOCK_OWNER → Module Reputation แบบ netblock
sfp_social → SOCIAL_MEDIA → sfp_twitter / sfp_github
```

## 47. API Integration
### 47.1 Provider ที่ใช้บ่อย (ชื่อ Option ตรวจจาก 4.0.0)
| Provider | Module | Option | Model |
|---|---|---|---|
| VirusTotal | `sfp_virustotal` | `api_key` | FREE_AUTH_LIMITED |
| Shodan | `sfp_shodan` | `api_key` | FREE_AUTH_LIMITED |
| SecurityTrails | `sfp_securitytrails` | `api_key` | FREE_AUTH_LIMITED |
| Censys | `sfp_censys` | `censys_api_key_uid`, `censys_api_key_secret` | FREE_AUTH_LIMITED |
| AlienVault OTX | `sfp_alienvault` | `api_key` | FREE_AUTH_LIMITED |
| AbuseIPDB | `sfp_abuseipdb` | `api_key` | FREE_AUTH_LIMITED |
| GreyNoise Community | `sfp_greynoise_community` | `api_key` | FREE_AUTH_LIMITED |
| HaveIBeenPwned | `sfp_haveibeenpwned` | `api_key` | COMMERCIAL_ONLY |
| Hunter.io | `sfp_hunter` | `api_key` | FREE_AUTH_LIMITED |
| CertSpotter | `sfp_certspotter` | `api_key` | FREE_AUTH_LIMITED |
| IPInfo | `sfp_ipinfo` | `api_key` | FREE_AUTH_LIMITED |
| LeakIX | `sfp_leakix` | `api_key` | FREE_AUTH_UNLIMITED |
| IntelligenceX | `sfp_intelx` | `api_key`, `base_url` | FREE_AUTH_LIMITED |
| BinaryEdge | `sfp_binaryedge` | `binaryedge_api_key` | FREE_AUTH_LIMITED |
| Hybrid Analysis | `sfp_hybrid_analysis` | `api_key` | FREE_AUTH_UNLIMITED |
| Google Custom Search | `sfp_googlesearch` | `api_key`, `cse_id` | FREE_AUTH_LIMITED |
| Etherscan | `sfp_etherscan` | `api_key` | FREE_NOAUTH_UNLIMITED (แต่ Module มี Flag `apikey`) |

ดู Option ที่เกี่ยวกับ Key ของทุก Module:
```bash
jq -r '.[] | .module as $m | (.opts // {} | keys[]) | select(test("key|secret|uid|cse|token|user|pass"; "i")) | "\($m).\(.)"' \
  ~/cases/$CASE/raw/modinfo.json | head -30
```

### 47.2 ขั้นตอนต่อ Provider
1. **Registration** — สมัคร Account ที่เว็บไซต์ของ Provider เอง (ผู้ใช้ต้องทำเอง อ่าน Terms ก่อน) ขั้นตอนของแต่ละ Provider อยู่ใน `meta.dataSource.apiKeyInstructions`:

```bash
jq -r '.[] | select(.module=="sfp_shodan") | .meta.dataSource.apiKeyInstructions[]' ~/cases/$CASE/raw/modinfo.json
```
2. **Configuration** — Web UI Settings หรือ `sfcli`:

```
sf> set module.sfp_shodan.api_key = YOUR_API_KEY
```
3. **Test** — Scan เล็กด้วย Module เดียวกับ Asset ของตัวเอง แล้วดู Log:

```bash
python3 sf.py -s 203.0.113.10 -m sfp_shodan -o json 2> /tmp/t.log > /tmp/t.json
grep -iE "error|key|limit|denied|40[13]|429" /tmp/t.log | head
```
4. **Failure / Troubleshooting** — ดูตารางข้อ 47.3 และบท 68

### 47.3 ข้อความที่พบบ่อยและความหมาย
| ใน Log | ความหมาย | ทำอะไรต่อ |
|---|---|---|
| `You enabled sfp_xxx but did not set an API key!` | ยังไม่ได้ใส่ Key | ตั้งค่า Key หรือตัด Module ออก |
| `... API key seems to have been rejected or you have exceeded usage limits.` (เช่น Shodan, GreyNoise) | Key ผิดหรือหมดโควตา | ตรวจ Dashboard ของ Provider |
| HTTP 401 / 403 | Key ผิด / Plan ไม่มีสิทธิ์ | ตรวจ Key ที่หน้า Dashboard ของ Provider |
| HTTP 429 | เกิน Rate limit | ลด Concurrency, เพิ่ม `delay` (บท 49) |
| Timeout | Provider ช้า | เพิ่ม `_fetchtimeout` |
| HTTP 5xx | Provider มีปัญหา | รอ/รันใหม่ภายหลัง |

> **หมายเหตุ:** ข้อความ Error ที่แน่นอนแตกต่างกันในแต่ละ Module ค้นใน Source ของ Module ได้ด้วย `grep -n "self.error" modules/sfp_<name>.py`

## 48. API Key Management
### 48.1 Key อยู่ที่ไหนบ้าง (ต้องปกป้องทุกจุด)
1. `tbl_config` ใน `spiderfoot.db` — ค่าปัจจุบัน
2. `tbl_scan_config` ใน `spiderfoot.db` — **สำเนา Config ทั้งหมดของทุก Scan** (ทดสอบแล้ว: 614 แถวต่อ Scan รวม Option `api_key` ของทุก Module)
3. ไฟล์ Export จากปุ่ม **Export API Keys** (`SpiderFoot.cfg`)
4. History ของ Shell และ `~/.spiderfoot_history` ของ `sfcli.py`

ผล: **ห้ามส่งไฟล์ `spiderfoot.db` ให้ผู้อื่น** ถ้าต้องส่งผล ให้ Export CSV/JSON แทน

### 48.2 เก็บ Key เป็นไฟล์สำหรับ Import
```bash
mkdir -p ~/.config/spiderfoot && chmod 700 ~/.config/spiderfoot
cat > ~/.config/spiderfoot/keys.cfg << 'EOF'
sfp_virustotal:api_key=YOUR_API_KEY
sfp_shodan:api_key=YOUR_API_KEY
sfp_censys:censys_api_key_uid=<API_ID>
sfp_censys:censys_api_key_secret=<API_SECRET>
EOF
chmod 600 ~/.config/spiderfoot/keys.cfg
```
Import: Web UI → Settings → **Import API Keys** → เลือกไฟล์ → Save (Server รวมค่าจากไฟล์เข้ากับ Config ปัจจุบัน)

### 48.3 ปิดช่องรั่ว
```bash
# sfcli ไม่เก็บ History
python3 sfcli.py -n
# ลบ History เดิม
shred -u ~/.spiderfoot_history 2>/dev/null
# ตรวจว่ามี Key หลุดในโฟลเดอร์ Case
grep -rInE "api_key=.{8,}|apikey|secret=" ~/cases/$CASE --include=*.{cfg,txt,md,log} | head
```

### 48.4 Rotation
1. สร้าง Key ใหม่ที่ Provider
2. Import ไฟล์ Key ใหม่
3. Revoke Key เก่า
4. ถ้า Key เก่าอยู่ใน `tbl_scan_config` ของ Scan เก่า และ Database เคยออกนอกเครื่อง ให้ถือว่า Key เก่ารั่วแล้ว

## 49. Rate Limits
### 49.1 ปัจจัยที่กำหนดอัตรา Request
- `_maxthreads` (Global) — Module ที่ทำงานพร้อมกัน
- `_maxthreads` ของบาง Module — Thread ภายใน Module (`sfp_dnsbrute` 100, `sfp_accounts` 20, Cloud bucket finder 20)
- Option หน่วงเวลาของ Module (ตัวอย่างจาก 4.0.0):

```
sfp_censys.delay = 3          sfp_hybrid_analysis.delay = 1
sfp_leakix.delay = 1          sfp_crobat_api.delay
sfp_etherscan.pause = 1       sfp_dehashed.pause = 1
sfp_grayhatwarfare.pause = 1  sfp_virustotal.publicapi = True (หยุด 15 วินาที/Query)
sfp_spider.pausesec = 0
```
หา Option หน่วงเวลาทั้งหมด:
```bash
jq -r '.[] | .module as $m | (.opts // {} | to_entries[]) | select(.key|test("delay|pause|sleep")) | "\($m).\(.key)=\(.value)"' \
  ~/cases/$CASE/raw/modinfo.json
```

### 49.2 เมื่อเจอ 429 / Quota หมด
1. ลด Concurrency: `-max-threads 1`
2. เพิ่ม `delay`/`pause` ของ Module นั้น
3. แยก Module ที่ใช้ Quota ไปรันรอบที่สองเฉพาะ Entity ที่คัดแล้ว
4. นับจำนวน Event ที่จะส่งเข้า Module ก่อน (เช่นจำนวน IP) เพื่อประเมิน Quota

```bash
jq '[.[] | select(.type=="IP Address")] | length' $R/scan.json
```

## 50. OPSEC
### 50.1 ใครเห็นอะไรเมื่อคุณ Scan
| Action | ใครเห็น |
|---|---|
| DNS Query | Resolver ที่ใช้, Authoritative DNS ของ Target |
| Module แบบ API | Provider เห็น Target ที่คุณค้น + Account/API Key ของคุณ |
| `sfp_spider`, `sfp_sslcert`, `sfp_filemeta` | Web server ของ Target เห็น IP และ User-Agent |
| Bucket finder | Cloud Provider เห็นชื่อ Bucket ที่เดา |
| Port scan (invasive) | Target เห็นชัดเจน และอาจถูกนับเป็นการโจมตี |

### 50.2 แนวปฏิบัติ
- ใช้ Account/API Key ขององค์กร ไม่ใช้ Account ส่วนตัวกับงานขององค์กร
- ตั้ง `_useragent` ให้ระบุตัวตนของทีมอย่างเหมาะสมตามนโยบายองค์กร เมื่อทำงานกับระบบที่ได้รับอนุญาต
- ใช้ `_dnsserver` ของหน่วยงาน เพื่อให้ Query อยู่ในระบบ Log ขององค์กร
- เปิดเฉพาะ Module ที่จำเป็น (Data minimization) ลดข้อมูลที่ส่งออกไปภายนอก
- Target ที่อ่อนไหว (เช่น Email บุคคล) ส่งไปให้ Provider เท่าที่จำเป็น เพราะ Provider อาจเก็บ Log คำค้น
- เก็บบันทึกว่า Scan ไหนใช้ Module ใด (`scaninfo <sid> -c`) เพื่อตอบคำถามภายหลังได้

> **หมายเหตุ:** คู่มือนี้ไม่ครอบคลุมเทคนิคหลบเลี่ยงการตรวจจับ เป้าหมายของ OPSEC ที่นี่คือการลดข้อมูลที่ไม่จำเป็นและทำงานภายใต้การอนุญาตอย่างโปร่งใส

## 51. Automation
```
[Target list] → [Validate target type] → [sf.py per target] → [JSON per scan]
      → [jq/python normalize] → [dedupe + merge] → [diff กับรอบก่อน] → [report/alert]
```
หลักการ:
- **Repeatable** — Profile เป็นไฟล์, Version ของ SpiderFoot คงที่, Output ตั้งชื่อตามวันที่
- **Idempotent** — รันซ้ำแล้วไม่ทับผลเดิม
- **Observable** — เก็บ stderr เป็น Log ทุกครั้ง
- **Bounded** — ใช้ `-x` หรือ Profile ขนาดเล็ก และ `timeout`

## 52. CLI Automation
### 52.1 Batch Scan
```bash
cat > ~/bin/sf-batch.sh << 'EOF'
#!/usr/bin/env bash
# ใช้: sf-batch.sh targets.txt profile.txt outdir
set -uo pipefail
TARGETS=$(realpath "$1"); PROFILE=$(realpath "$2"); OUT=$(realpath -m "$3"); SF=~/tools/spiderfoot
mkdir -p "$OUT"   # realpath: Script จะ cd ไปโฟลเดอร์ SpiderFoot
MODS=$(grep -v '^#' "$PROFILE" | paste -sd, -)
cd "$SF" && . .venv/bin/activate
while read -r t; do
  [ -z "$t" ] && continue
  safe=$(echo "$t" | tr '/:"@ ' '_____')
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  timeout 2h python3 sf.py -s "$t" -m "$MODS" -max-threads 2 -o json \
    > "$OUT/$safe-$ts.json" 2> "$OUT/$safe-$ts.log"
  echo "$t exit=$? events=$(jq length "$OUT/$safe-$ts.json" 2>/dev/null)"
done < "$TARGETS"
EOF
chmod +x ~/bin/sf-batch.sh
~/bin/sf-batch.sh ~/cases/$CASE/raw/targets.txt ~/sf-profiles/domain-passive.txt ~/cases/$CASE/raw/batch
```
- `timeout 2h` กัน Scan ค้าง ถ้าถูกตัดกลางทาง JSON จะไม่สมบูรณ์ (ไม่มี `]` ปิดท้าย) — ตรวจด้วย `jq length`
- Exit code 0 = Scan จบปกติ

### 52.2 Scheduled Scan (cron)
```bash
crontab -e
```

```
# ทุกวันจันทร์ 02:15 UTC
15 2 * * 1 SPIDERFOOT_DATA=/home/kali/sfmon/data /home/kali/bin/sf-batch.sh /home/kali/sfmon/targets.txt /home/kali/sf-profiles/domain-passive.txt /home/kali/sfmon/out >> /home/kali/sfmon/cron.log 2>&1
```

### 52.3 Diff ระหว่างสองรอบ
```bash
A=$(ls -1 ~/sfmon/out/example.com-*.json | tail -2 | head -1); B=$(ls -1 ~/sfmon/out/example.com-*.json | tail -1)
jq -r '.[] | select(.type=="Internet Name") | .data' "$A" | sort -u > /tmp/a
jq -r '.[] | select(.type=="Internet Name") | .data' "$B" | sort -u > /tmp/b
echo "NEW:"; comm -13 /tmp/a /tmp/b
echo "GONE:"; comm -23 /tmp/a /tmp/b
```

## 53. Scripting
### 53.1 Python + Web UI HTTP Endpoint (ตรวจกับ 4.0.0)
Endpoint ที่ใช้ใน Script (ตอบ JSON):
```
GET/POST /startscan      scanname, scantarget, modulelist|typelist|usecase  (ต้องส่ง Accept: application/json)
GET      /scanstatus?id=   → [name, target, created, started, ended, status, riskmatrix]
GET      /scanlist         → [[id, name, target, created, started, finished, status, total, riskmatrix], ...]
GET      /scaneventresults?id=&eventType=   → [[lastseen, data, source, module, conf, vis, risk, hash, fp, parent_fp, type], ...]
GET      /scaneventresultsunique?id=&eventType=
GET      /scansummary?id=&by=type|module|entity
GET      /scancorrelations?id=
GET      /search?id=&eventType=&value=      (value ใช้ * เป็น wildcard หรือ /regex/)
GET      /scanexportjsonmulti?ids=a,b
POST     /query            query=SELECT ...
GET      /stopscan?id=     /scandelete?id=     /ping
```
- `modulelist` ใส่ชื่อ Module คั่นด้วย Comma (Prefix `module_` ใส่หรือไม่ใส่ก็ได้ Server ตัดออกให้)
- `usecase` ต้องเป็น `all`, `Footprint`, `Investigate` หรือ `Passive` (ตรงตัว)
- ถ้าตั้ง Authentication ไว้ (บท 69) ต้องใช้ HTTP Digest Auth

### 53.2 Script ครบวงจร
```python
#!/usr/bin/env python3
"""sf_api.py: start scan -> wait -> export JSON  (requests อยู่ใน requirements.txt ของ SpiderFoot 4.0)"""
import sys, time, json, requests
from requests.auth import HTTPDigestAuth

BASE = "http://127.0.0.1:5001"
AUTH = None  # HTTPDigestAuth("analyst", "<PASSWORD>") ถ้าเปิด passwd
H = {"Accept": "application/json"}

def start(name, target, modules):
    r = requests.post(f"{BASE}/startscan", headers=H, auth=AUTH, data={
        "scanname": name, "scantarget": target,
        "modulelist": ",".join(modules), "typelist": "", "usecase": ""})
    status, value = r.json()
    if status != "SUCCESS":
        raise SystemExit(f"start failed: {value}")
    return value

def wait(sid, poll=10):
    while True:
        st = requests.get(f"{BASE}/scanstatus", params={"id": sid}, auth=AUTH).json()
        if st and st[5] in ("FINISHED", "ABORTED", "ERROR-FAILED"):
            return st[5]
        time.sleep(poll)

if __name__ == "__main__":
    sid = start("api-" + sys.argv[1], sys.argv[1], ["sfp_dnsresolve", "sfp_dnsraw", "sfp_crt"])
    print("scan", sid, wait(sid))
    data = requests.get(f"{BASE}/scanexportjsonmulti", params={"ids": sid}, auth=AUTH).json()
    json.dump(data, open(f"{sid}.json", "w"), indent=1)
    print(len(data), "events ->", f"{sid}.json")
```
รัน: `python3 sf_api.py example.com` → พิมพ์ `scan <SCAN_ID> FINISHED` และ `<N> events -> <SCAN_ID>.json` (ทดสอบแล้วกับ 4.0.0 — `sfp_crt` ที่เปิด `fetchcerts` ทำให้รอนาน ดูบท 37)

### 53.3 อ่าน SQLite โดยตรงด้วย Python
```python
import sqlite3, os
db = sqlite3.connect(os.path.expanduser(os.environ.get("SPIDERFOOT_DATA", "~/.spiderfoot")) + "/spiderfoot.db")
for t, n in db.execute("SELECT type, COUNT(*) FROM tbl_scan_results WHERE scan_instance_id=? GROUP BY type ORDER BY 2 DESC", ("143B53FF",)):
    print(f"{n:6} {t}")
```
> **หมายเหตุ:** อ่านอย่างเดียวขณะ Scan กำลังรัน การเขียนลง Database โดยตรงอาจชนกับ SpiderFoot (Database locked)

## 54. JSON Output
### 54.1 สอง Format ที่ต่างกัน (ทดสอบแล้ว)
**A. `sf.py -o json`** — JSON Array, Field `type` เป็น **คำอธิบาย** ไม่ใช่รหัส:

```json
[{"generated": 1790367920, "type": "Internet Name", "data": "example.com", "module": "SpiderFoot UI", "source": "example.com"},
{"generated": 1790367920, "type": "Name Server (DNS NS Records)", "data": "ns1.example.net", "module": "sfp_dnsraw", "source": "example.com"}]
```
**B. Web UI / `sfcli export -t json` / `/scanexportjsonmulti`** — Field `event_type` เป็น **รหัส**:

```json
[{"data": "203.0.113.10", "event_type": "IP_ADDRESS", "module": "sfp_dnsresolve", "source_data": "example.com",
  "false_positive": 0, "last_seen": "2026-09-25 20:27:02", "scan_name": "api-test", "scan_target": "example.com"}]
```

### 54.2 jq Recipes (Format A)
```bash
F=$R/scan.json
jq length $F                                                       # จำนวน Event
jq -r '.[].type' $F | sort | uniq -c | sort -rn                    # Count ตามชนิด
jq -r '.[] | select(.type=="IP Address") | .data' $F | sort -u     # Extract + Dedupe
jq -r '.[] | select(.data|test("vpn|remote"; "i")) | [.type,.data] | @tsv' $F   # Search
jq -r '.[] | [.module,.type,.source,.data] | @csv' $F > $R/scan-flat.csv        # Export CSV
jq -r '.[] | select(.type|startswith("Malicious")) | "\(.data) <- \(.module)"' $F
jq -r 'group_by(.module)[] | "\(.[0].module)\t\(length)"' $F | sort -k2 -nr    # Group by module
```

### 54.3 jq Recipes (Format B)
```bash
F=~/cases/$CASE/exports/dns-baseline.json
jq -r '.[] | select(.false_positive==0 and .event_type=="INTERNET_NAME") | .data' $F | sort -u
jq -r '[.[] | .event_type] | group_by(.) | map({t:.[0], n:length}) | sort_by(-.n)[] | "\(.n)\t\(.t)"' $F
```
> **หมายเหตุ:** ถ้า `sf.py` ถูกหยุดกลางทาง ไฟล์ Format A จะไม่มี `]` ปิดท้าย ซ่อมชั่วคราวด้วย `{ sed '$ s/,$//' f.json; echo "]"; } > f-fixed.json` แล้วตรวจด้วย `jq length f-fixed.json`

## 55. CSV Output
### 55.1 สอง Format
**A. `sf.py -o csv -r`** (ต้องใส่ `-r` ตามบท 4.8):

```
Source,Type,Source Data,Data
sfp_dnsraw,Name Server (DNS NS Records),example.com,ns1.example.net
```
**B. Web UI Export / `/scaneventresultexport`**:

```
Updated,Type,Module,Source,F/P,Data
2026-09-25 20:27:02,IP_ADDRESS,sfp_dnsresolve,example.com,0,203.0.113.10
```
Multi-scan (`/scaneventresultexportmulti`) เพิ่มคอลัมน์ `Scan Name` ด้านหน้า

### 55.2 จัดการ CSV ที่มี Comma/Newline
`sf.py -o csv` ไม่ได้ Quote ข้อมูล ข้อมูลที่มี Comma (เช่น TXT record, Banner) จะทำให้คอลัมน์เลื่อน ทางเลือก:
```bash
# 1) ใช้ Delimiter ที่ไม่น่าจะอยู่ในข้อมูล + ตัด Newline
python3 sf.py -s example.com -m sfp_dnsraw -o csv -r -n -D '|' -q > $R/dns.psv
awk -F'|' 'NR>1{print $2}' $R/dns.psv | sort | uniq -c
# 2) ใช้ JSON แล้วแปลงเป็น CSV ที่ Quote ถูกต้อง
jq -r '.[] | [.module,.type,.source,.data] | @csv' $R/scan.json > $R/scan.csv
# 3) CSV จาก Web UI (Quote ถูกต้องแล้ว) → ใช้ csvkit
csvcut -c Type,Data SpiderFoot.csv | csvgrep -c Type -m IP_ADDRESS | csvformat -T
```

## 56. Database / Storage
### 56.1 ตำแหน่งและตาราง
```bash
ls -lh $SPIDERFOOT_DATA/spiderfoot.db
sqlite3 $SPIDERFOOT_DATA/spiderfoot.db ".tables"
```

```
tbl_config  tbl_event_types  tbl_scan_config  tbl_scan_correlation_results
tbl_scan_correlation_results_events  tbl_scan_instance  tbl_scan_log  tbl_scan_results
```

| ตาราง | เก็บอะไร | หน่วยเวลา |
|---|---|---|
| `tbl_scan_instance` | guid, name, seed_target, created, started, ended, status | มิลลิวินาที |
| `tbl_scan_results` | Event ทั้งหมด (ดูบท 41.1) | `generated` = วินาที |
| `tbl_scan_log` | Log ของ Scan | มิลลิวินาที |
| `tbl_scan_config` | Config ทั้งหมดต่อ Scan (รวม API Key) | — |
| `tbl_scan_correlation_results(_events)` | ผล Correlation และ Event ที่เกี่ยวข้อง | — |
| `tbl_event_types` | รหัส, คำอธิบาย, Category | — |
| `tbl_config` | Config ปัจจุบัน | — |

### 56.2 Query ที่ใช้บ่อย
```bash
DB=$SPIDERFOOT_DATA/spiderfoot.db
# รายการ Scan
sqlite3 -header -column $DB "SELECT guid,name,seed_target,status,datetime(started/1000,'unixepoch') AS started FROM tbl_scan_instance ORDER BY started DESC LIMIT 10;"
# Event ต่อ Module (ใช้ Optimize Profile)
sqlite3 -header -column $DB "SELECT module, COUNT(*) n FROM tbl_scan_results WHERE scan_instance_id='143B53FF' GROUP BY module ORDER BY n DESC;"
# Timeline ของ Event
sqlite3 -header -column $DB "SELECT datetime(generated,'unixepoch') t, type, substr(data,1,50) d FROM tbl_scan_results WHERE scan_instance_id='143B53FF' ORDER BY generated LIMIT 20;"
# Error ของ Scan
sqlite3 $DB "SELECT datetime(generated/1000,'unixepoch'), component, message FROM tbl_scan_log WHERE scan_instance_id='143B53FF' AND type='ERROR';"
```
จาก `sfcli`: `query SELECT ...` / จาก HTTP: `POST /query` (รับเฉพาะ `SELECT`)

### 56.3 ข้อจำกัดความยาวข้อมูล
`sfp__stor_db` มี Option `maxstorage` = **1024 ไบต์** — ข้อมูลที่ยาวกว่านี้ (เช่น `TARGET_WEB_CONTENT`, `RAW_RIR_DATA`) จะถูกตัดก่อนเก็บ ถ้าต้องการข้อมูลดิบเต็ม ตั้ง `0` (ไม่จำกัด) โดยยอมให้ Database โตเร็วขึ้น
```
sf> set module.sfp__stor_db.maxstorage = 0
```

### 56.4 Backup / Maintenance
```bash
# Backup แบบปลอดภัยขณะ Server ไม่เขียน
sqlite3 $DB ".backup '$HOME/backup/sf-$(date +%F).db'"
# ลบ Scan ที่ไม่ใช้ (sfcli) แล้ว Vacuum
curl -s http://127.0.0.1:5001/scandelete?id=<SCAN_ID>
curl -s http://127.0.0.1:5001/vacuum
ls -lh $DB
```

## 57. Data Processing
```bash
F=$R/scan.json
# Normalize: ตัวพิมพ์เล็ก ตัดจุดท้ายชื่อ Host
jq -r '.[] | select(.type=="Internet Name") | .data | ascii_downcase | rtrimstr(".")' $F | sort -u > $R/hosts.norm
# Enrich: เติม IP ปัจจุบันด้วย dig
while read h; do echo "$h,$(dig +short A $h | grep -E '^[0-9.]+$' | paste -sd' ' -)"; done < $R/hosts.norm > $R/hosts-ip.csv
# Merge หลาย Scan (Format B)
curl -s "http://127.0.0.1:5001/scanexportjsonmulti?ids=143B53FF,53AC5D63" | \
  jq -r '.[] | select(.false_positive==0) | [.scan_target,.event_type,.data] | @tsv' | sort -u > $R/merged.tsv
# Entity ที่พบใน ≥ 2 Scan (จุดร่วม)
cut -f2,3 $R/merged.tsv | sort | uniq -c | awk '$1>=2' | sort -rn | head
```

## 58. Export
| ต้องการ | วิธี |
|---|---|
| ผลทั้ง Scan (JSON) | Web UI Export / `sfcli export <sid> -t json -f file` / `/scanexportjsonmulti?ids=` |
| ผลทั้ง Scan (CSV) | `sfcli export <sid> -t csv -f file` / `/scaneventresultexport?id=&type=ALL&filetype=csv` |
| Excel | `/scaneventresultexport?id=&type=ALL&filetype=xlsx` |
| เฉพาะชนิด | `/scaneventresultexport?id=&type=IP_ADDRESS&filetype=csv` |
| หลาย Scan | `/scaneventresultexportmulti?ids=a,b&filetype=csv` |
| ผลค้นหา | `/scansearchresultexport?id=&eventType=&value=&filetype=csv` |
| Correlation | `/scancorrelationsexport?id=&filetype=csv` (Header: `Rule Name,Correlation,Risk,Description`) |
| Log | `/scanexportlogs?id=` (Header: `Date,Component,Type,Event,Event ID`) |
| Graph | `/scanviz?id=&gexf=1` / `sfcli export <sid> -t gexf` |
| Config | Settings → Export API Keys (มี Key! ดูบท 48) |

```bash
S=143B53FF; O=~/cases/$CASE/exports; B=http://127.0.0.1:5001
curl -s "$B/scanexportjsonmulti?ids=$S" -o $O/$S.json
curl -s "$B/scaneventresultexport?id=$S&type=ALL&filetype=csv" -o $O/$S.csv
curl -s "$B/scancorrelationsexport?id=$S&filetype=csv" -o $O/$S-correlations.csv
curl -s "$B/scanexportlogs?id=$S" -o $O/$S-log.csv
curl -s "$B/scanviz?id=$S&gexf=1" -o $O/$S.gexf
sha256sum $O/$S* > $O/$S.SHA256SUMS
```

## 59. Reporting
### 59.1 สร้างรายการจาก Export (Format B)
```bash
F=~/cases/$CASE/exports/143B53FF.json; O=~/cases/$CASE/exports/report; mkdir -p $O
q(){ jq -r --arg t "$1" '.[] | select(.false_positive==0 and .event_type==$t) | .data' $F | sort -u; }
q INTERNET_NAME > $O/domain-list.txt
{ q IP_ADDRESS; q IPV6_ADDRESS; } > $O/ip-list.txt
{ q EMAILADDR; q EMAILADDR_GENERIC; } > $O/email-list.txt
jq -r '.[] | select(.false_positive==0 and (.event_type|test("^(MALICIOUS|BLACKLISTED)_"))) | [.event_type,.data,.module] | @tsv' $F | sort -u > $O/ioc-list.tsv
jq -r '.[] | select(.false_positive==0 and (.event_type|test("NETBLOCK|BGP_AS|PROVIDER_"))) | [.event_type,.data] | @tsv' $F | sort -u > $O/infrastructure-list.tsv
jq -r '.[] | [.last_seen,.event_type,.data] | @tsv' $F | sort > $O/timeline.tsv
wc -l $O/*
```

### 59.2 โครงรายงาน
```
1. Executive Summary      — ข้อค้นพบสำคัญ 3–5 ข้อ + ระดับความเสี่ยง (จาก Correlation ที่ Validate แล้ว)
2. Scope & Method         — Target, วันที่, Scan ID, Module/Profile, ข้อจำกัด (API ที่ไม่มี, Module ที่ปิด)
3. Findings               — แต่ละข้อ: หลักฐาน (Event + Source), การ Validate, ผลกระทบ, คำแนะนำ
4. Infrastructure         — domain-list, ip-list, infrastructure-list
5. IOC List               — ioc-list (Defang ก่อนแนบ)
6. Timeline               — timeline
7. Evidence List          — ไฟล์ + SHA256 (บท 60)
8. False Positives        — รายการที่ตัดออกและเหตุผล
```
Defang ก่อนใส่รายงาน:
```bash
sed -e 's/\./[.]/g' -e 's/http/hxxp/g' $O/ioc-list.tsv > $O/ioc-list-defanged.tsv
```
> **หมายเหตุ:** ใส่ในรายงานเฉพาะข้อค้นพบที่ Validate แล้ว ผลจาก Module แบบ `errorprone` หรือ Correlation ระดับ INFO ต้องระบุว่าเป็น "ข้อบ่งชี้" ไม่ใช่ "ข้อเท็จจริง"

## 60. Evidence Handling
SpiderFoot เป็นเครื่องมือ OSINT Automation ไม่ใช่ Digital Forensics Platform การจัดการหลักฐานต้องทำเพิ่มเอง

### 60.1 สิ่งที่ต้องเก็บต่อ Finding
| รายการ | แหล่ง |
|---|---|
| Timestamp | `last_seen` / `generated` (ระบุว่าเป็นเวลาที่ SpiderFoot พบ ไม่ใช่เวลาที่เกิดเหตุ) |
| Source | `module` + Provider |
| Event | `event_type`, `data`, `source_data` |
| Raw Result | Export JSON ของ Scan + `RAW_*` Event |
| Screenshot | ถ่ายหน้าจอ Web UI/แหล่งต้นทาง (ด้วยมือ) |
| Export | ไฟล์ Export + SHA256 |
| Config | `scaninfo <sid> -c` (ลบ Key ออกก่อนแนบ) |

### 60.2 Chain of Custody ระดับพื้นฐาน
```bash
EV=~/cases/$CASE/evidence; mkdir -p $EV
cp ~/cases/$CASE/exports/143B53FF.* $EV/
( cd $EV && sha256sum * > SHA256SUMS && chmod 444 * )
cat >> ~/cases/$CASE/notes/custody.log << EOF
$(date -u +%FT%TZ) | collected by <analyst> | scan 143B53FF | files: $(ls $EV | paste -sd' ' -) | host: $(hostname)
EOF
sha256sum -c $EV/SHA256SUMS
```
- บันทึก Version ของ SpiderFoot (`sf.py -V`) และ Commit (`git -C ~/tools/spiderfoot log -1 --format=%H`)
- ห้ามแก้ไฟล์ใน `evidence/` ทำงานกับสำเนาเสมอ

## 61. Integration with Other OSINT Tools
ไม่มีการจัดอันดับ แต่ละเครื่องมือเหมาะกับงานต่างกัน
```
Tool A (theHarvester / Amass / Sherlock / Recon-ng)
   ↓  รายชื่อ Host / Email / Username
SpiderFoot (Scan ต่อ Target + Correlation)
   ↓  Export CSV/JSON
Validation (dig / whois / openssl / curl / Shodan / Censys / VirusTotal Web)
   ↓
Maltego (Import Graph from Table) → Graph Analysis
```

| เครื่องมือ | ใช้คู่กับ SpiderFoot อย่างไร |
|---|---|
| theHarvester | รวบรวม Email/Host เร็ว → ใช้เป็น Target list ของ `sf-batch.sh` |
| Amass | Subdomain เชิงลึก → เทียบกับ `INTERNET_NAME` ของ SpiderFoot (บท 13.4) |
| Sherlock | ตรวจ Username → เทียบกับ `ACCOUNT_EXTERNAL_OWNED` ของ `sfp_accounts` |
| Recon-ng | Workspace แบบ Module → ส่งออก Host/Contact มาเป็น Target |
| Shodan / Censys / VirusTotal | ผ่าน Module ของ SpiderFoot (API) หรือตรวจ Finding สำคัญซ้ำผ่านหน้าเว็บของบริการ |
| WHOIS / DNS tools | Validation อิสระ |
| Maltego | วิเคราะห์ Graph จาก Export |

### 61.1 Amass / theHarvester → SpiderFoot
```bash
amass enum -passive -d example.com -o $R/amass.txt
theHarvester -d example.com -b crtsh -f $R/harvester
cat $R/amass.txt | sort -u > $R/targets.txt
~/bin/sf-batch.sh $R/targets.txt ~/sf-profiles/infrastructure.txt $R/batch-infra
```
> **หมายเหตุ:** Option ของ Amass, theHarvester และ Sherlock เปลี่ยนตามเวอร์ชัน ตรวจด้วย `-h`/`--help` ก่อนใช้

### 61.2 Sherlock ↔ sfp_accounts
```bash
sherlock alice_example --print-found > $R/sherlock.txt
python3 sf.py -s alice_example -m sfp_accounts -F ACCOUNT_EXTERNAL_OWNED -H -q | awk -F'\t' '{print $3}' > $R/sf-accounts.txt
grep -Eo 'https?://[^ ]+' $R/sherlock.txt | sort -u > /tmp/sh; sort -u $R/sf-accounts.txt > /tmp/sf
comm -12 /tmp/sh /tmp/sf     # พบทั้งสองเครื่องมือ = น่าเชื่อถือกว่า
```

### 61.3 SpiderFoot → Maltego
```bash
F=~/cases/$CASE/exports/143B53FF.json
echo "source,source_type,target,target_type" > $R/maltego.csv
jq -r '.[] | select(.false_positive==0 and (.event_type|test("^(IP_ADDRESS|INTERNET_NAME|DOMAIN_NAME|EMAILADDR)$")))
        | [.source_data, "?", .data, .event_type] | @csv' $F >> $R/maltego.csv
```
ใน Maltego: Import Graph from Table → Map `source` และ `target` เป็น Entity ตามชนิด (`INTERNET_NAME` → DNS Name, `IP_ADDRESS` → IPv4 Address, `EMAILADDR` → Email Address) และสร้าง Link จาก source → target

## 62. Threat Intelligence Workflow
```
IOC
 ↓  ตรวจชนิด Target (บท 10.4)
SpiderFoot  (-t MALICIOUS_*,BLACKLISTED_* -x  หรือ Profile threat-intel.txt)
 ↓
Multiple Intelligence Sources (abuse.ch, ThreatFox, DNSBL, VirusTotal*, OTX*, AbuseIPDB*)
 ↓
Correlation (multiple_malicious ≥ 2 แหล่ง)
 ↓
Analysis (แยก Target vs Subnet vs Co-host, ดูอายุข้อมูล)
 ↓
Report (IOC list + ระดับความเชื่อมั่น)
```

```bash
python3 sf.py -s 198.51.100.77 -m "$(paste -sd, ~/sf-profiles/threat-intel.txt)" -o json 2>$R/ti.log >$R/ti.json
jq -r '.[] | select(.type|test("^(Malicious|Blacklisted)")) | [.module,.type,.data] | @tsv' $R/ti.json | sort -u
```
ระดับความเชื่อมั่นที่แนะนำ:
- **High** — `MALICIOUS_IPADDR`/`MALICIOUS_INTERNET_NAME` ของตัว IOC จาก ≥ 2 แหล่งอิสระ และข้อมูลไม่เก่ากว่าช่วงที่สนใจ
- **Medium** — 1 แหล่ง หรือเป็น Netblock/Subnet
- **Low** — Co-host/Affiliate เท่านั้น

## 63. Infrastructure Investigation
```
IP → Reverse DNS → WHOIS → ASN → Netblock → Reputation → Related Domains → Certificates → Passive DNS → Threat Intelligence
```

| ขั้น | Module | Event ที่ดู |
|---|---|---|
| Reverse DNS | `sfp_dnsresolve` | `INTERNET_NAME` |
| WHOIS | `sfp_ripe`, `sfp_whois` (Netblock) | `NETBLOCK_WHOIS`, `RAW_RIR_DATA` |
| ASN | `sfp_ripe`, `sfp_bgpview` | `BGP_AS_MEMBER` |
| Netblock | `sfp_ripe`, `sfp_bgpview` | `NETBLOCK_MEMBER` |
| Reputation | `sfp_spamhaus`, `sfp_abusech`, `sfp_threatfox` | `BLACKLISTED_*`, `MALICIOUS_*` |
| Related Domains | `sfp_hackertarget`, `sfp_robtex` | `CO_HOSTED_SITE` |
| Certificates | `sfp_sslcert` | `SSL_CERTIFICATE_ISSUED` |
| Passive DNS | `sfp_mnemonic` | `INTERNET_NAME`, `CO_HOSTED_SITE` |
| Threat Intel | `sfp_virustotal*`, `sfp_alienvault*` | `MALICIOUS_*` |

```bash
python3 sf.py -s 203.0.113.10 \
  -m sfp_dnsresolve,sfp_ripe,sfp_bgpview,sfp_whois,sfp_hosting,sfp_spamhaus,sfp_abusech,sfp_threatfox,sfp_hackertarget,sfp_robtex,sfp_sslcert,sfp_mnemonic \
  -max-threads 2 -o json 2>$R/infra.log >$R/infra.json
jq -r '.[].type' $R/infra.json | sort | uniq -c | sort -rn
```
**เริ่มจากไหน:** เริ่มจากข้อมูลที่เป็นข้อเท็จจริงและถูก (Reverse DNS, ASN, Netblock owner) ก่อนเสมอ เพราะคำตอบ "IP นี้เป็นของใคร" กำหนดว่าขั้นต่อไปมีความหมายหรือไม่

**หยุดตรงไหน:**

- `PROVIDER_HOSTING` ระบุว่าเป็น Cloud/CDN หรือ `CO_HOSTED_SITE` เกิน `maxcohost` → หยุดขั้น Related Domains
- ASN เป็นของ ISP/Cloud ขนาดใหญ่ → ไม่ Scan ทั้ง Netblock
- Passive DNS เก่ากว่าช่วงเวลาที่สนใจ → ไม่ใช้เป็นหลักฐานปัจจุบัน

## 64. Corporate OSINT Workflow
ใช้กับองค์กรของตนเองหรือองค์กรที่ว่าจ้างเป็นลายลักษณ์อักษร
1. Scope: Domain หลัก, Netblock ที่เป็นเจ้าของ (จากเอกสารขององค์กร)
2. Footprint: `corporate.txt` (บท 9.4) กับแต่ละ Domain
3. Exposure: Correlation `dev_or_test_system`, `cloud_bucket_open`, `internal_host`, `cert_expired`, `stale_host`
4. People exposure: `EMAILADDR`, `HUMAN_NAME` จากเว็บ/WHOIS/Metadata → ใช้ทำ Awareness ไม่เก็บข้อมูลส่วนตัวเกินจำเป็น
5. Brand: `sfp_similar`, `sfp_tool_dnstwist` → `SIMILARDOMAIN` (Domain ที่อาจใช้หลอกลวง) ตรวจด้วยมือ
6. Report: Asset ที่ไม่มีเจ้าของ, Exposure ที่ต้องแก้, Timeline ติดตามรอบถัดไป

```bash
for d in example.com example.org; do
  python3 sf.py -s $d -m "$(paste -sd, ~/sf-profiles/corporate.txt)" -max-threads 2 -o json 2>$R/corp-$d.log >$R/corp-$d.json
done
python3 sf.py -s example.com -m sfp_similar -F SIMILARDOMAIN -H -q | head
```

## 65. Digital Investigation Workflow
เน้นความสามารถในการอธิบายย้อนหลัง (Traceability)
1. เปิด Case ใหม่ด้วย `SPIDERFOOT_DATA` แยก (บท 2.3) และ `script` บันทึก Terminal
2. Scan ด้วย Profile ที่ระบุชัด บันทึก Scan ID ใน `scan-log.md`
3. Export JSON/CSV/Log/Correlation ทันทีหลังจบ + SHA256 (บท 58, 60)
4. Validate Finding สำคัญด้วยเครื่องมืออิสระ เก็บ Output ดิบ
5. ตั้ง FP พร้อมเหตุผลใน Notes
6. รายงานแยก "ข้อเท็จจริงที่ยืนยันแล้ว" กับ "ข้อบ่งชี้"

```bash
script -q -a ~/cases/$CASE/notes/terminal-$(date +%F).log
```

## 66. Large-Scale Investigation
### 66.1 ประเมินก่อนเริ่ม
```bash
wc -l $R/targets.txt                                   # จำนวน Target
jq '[.[] | select((.meta.flags//[]) | index("apikey"))] | length' ~/cases/$CASE/raw/modinfo.json
```
คำนวณคร่าว ๆ: `จำนวน Target × จำนวน Module ที่ใช้ API × Request ต่อ Event` เทียบกับ Quota รายวันของแต่ละ Provider

### 66.2 แนวทาง
- **Scope:** ทุก Target ต้องอยู่ในรายการที่ได้รับอนุญาต ห้ามขยายไป Netblock ของบุคคลที่สาม (`netblocklookup = 0`, `checkaffiliates = 0` ใน Module ที่ใช้)
- **Two-pass:** รอบแรก Module ฟรี/เร็ว กับทุก Target → คัด → รอบสอง Module ที่ใช้ Quota เฉพาะที่คัดแล้ว
- **Strict mode:** IOC จำนวนมากใช้ `-t ... -x`
- **Concurrency:** `-max-threads 1–2` ต่อ Scan และรัน Scan พร้อมกันไม่เกินที่ CPU/RAM รับได้
- **Storage:** แยก `SPIDERFOOT_DATA` ต่อชุดงาน, ตรวจขนาด DB, ลบ Scan ที่ Export แล้ว + `/vacuum`
- **Duplicate:** Event ซ้ำข้าม Scan เป็นเรื่องปกติ → Dedupe ตอน Processing (บท 57)
- **Noise/False Positive:** ปิด Module `errorprone` ในรอบแรก

### 66.3 รันหลาย Scan พร้อมกันแบบจำกัดจำนวน
```bash
mkdir -p $R/ls && export R
xargs -P 2 -I{} sh -c 'cd ~/tools/spiderfoot && .venv/bin/python sf.py -s "$1" \
  -m "$(paste -sd, ~/sf-profiles/domain-passive.txt)" -max-threads 1 -o json -q \
  > "$R/ls/$(echo "$1" | tr "/:@" "___").json"' _ {} < $R/targets.txt
```
- `-P 2` = รันพร้อมกันสูงสุด 2 Scan
- SQLite เป็นไฟล์เดียว การเขียนพร้อมกันมากเกินไปทำให้เกิด `database is locked` (บท 68)

## 67. Performance Optimization
| ปัจจัย | ปรับอย่างไร | เหตุผล |
|---|---|---|
| Module Selection | ใช้ Profile แทน `-u` | จำนวน Module คือปัจจัยใหญ่ที่สุด |
| Scan Scope | `-x`, ปิด `netblocklookup`/`checkaffiliates`/`checkcohosts` | ลด Event ที่เกิดต่อเนื่อง |
| API Usage | แยกรอบ Quota | ลด Error และเวลารอ |
| Rate Limits | `delay`/`pause`/`publicapi` | ลด 429 ซึ่งทำให้ Scan ช้าลงอีก |
| Concurrency | `-max-threads` (Default 3) | เพิ่มเมื่อ Module ส่วนใหญ่รอ Network; ลดเมื่อ CPU/RAM เต็มหรือเจอ 429 |
| Timeout | `_fetchtimeout` (Default 5) | เพิ่มเมื่อ Provider ช้า; ลดเมื่อหลาย Endpoint ไม่ตอบแล้วทำให้ Scan ค้าง |
| Database | `maxstorage`, ลบ Scan, `/vacuum` | ลด I/O และขนาดไฟล์ |
| Memory/CPU | ปิด `sfp_spider` หรือลด `maxpages`, ไม่ใช้ `fetchcerts` เมื่อไม่จำเป็น | Content ขนาดใหญ่ใช้ RAM/CPU |
| Logging | `-q` เมื่อ Pipeline นิ่งแล้ว, ไม่ใช้ `-d` ในงานจริง | Debug log ใหญ่มาก |

วัดผล:
```bash
/usr/bin/time -v python3 sf.py -s example.com -m "$(paste -sd, ~/sf-profiles/domain-passive.txt)" -o json -q > /tmp/x.json 2> /tmp/time.txt
grep -E "Elapsed|Maximum resident" /tmp/time.txt
```

## 68. Troubleshooting
### 68.1 Installation Error
- **อาการ/สาเหตุ:** `git clone` หรือ `pip install` ล้มเหลว — Network/Proxy, Python เก่ากว่า 3.7
- **ตรวจ:** `python3 --version; pip --version; curl -I https://github.com`
- **แก้:** ใช้ venv, อัปเดต pip (`pip install -U pip`), ตั้ง Proxy ของ pip

### 68.2 Python Dependency Error
- **อาการ:** `ModuleNotFoundError: No module named 'cherrypy'` (หรือ lxml ฯลฯ)
- **ตรวจ:** `which python3` ชี้ไป venv หรือไม่
- **แก้:** `. .venv/bin/activate && pip install -r requirements.txt` ถ้า lxml build ไม่ผ่าน: `sudo apt install -y libxml2-dev libxslt1-dev python3-dev`

### 68.3 Module Error
- **อาการ:** `Module ... has invalid category` หรือ Scan ไม่เริ่ม หลังเพิ่ม Module เอง
- **ตรวจ:** `python3 sf.py -M 2>&1 | tail -5`
- **แก้:** แก้ `meta.categories` ให้อยู่ในรายการบท 7.2, ชื่อ Class = ชื่อไฟล์

### 68.4 API Error
- **อาการ:** `You enabled sfp_xxx but did not set an API key!`
- **ตรวจ:** `curl -s http://127.0.0.1:5001/optsexport | grep '^sfp_xxx:api_key'`
- **แก้:** ตั้ง Key (บท 47) หรือตัด Module ออกจาก Profile

### 68.5 Authentication Error (Web UI / sfcli)
- **อาการ:** Browser ขอ Login ซ้ำ, `sfcli` ได้ 401
- **สาเหตุ:** มีไฟล์ `passwd` ใน Data dir แต่ Username/Password ไม่ตรง
- **ตรวจ:** `ls -l $SPIDERFOOT_DATA/passwd`
- **แก้:** แก้ `passwd` (รูปแบบ `user:password` บรรทัดละคน) แล้วรีสตาร์ต, `sfcli.py -u user -P passfile`

### 68.6 Rate Limit
- **อาการ:** Log มี 429 / `exceeded usage limits` / ผลขาดเป็นช่วง
- **ตรวจ:** `grep -iE "429|limit" $R/scan.log`
- **แก้:** `-max-threads 1`, เพิ่ม `delay`/`pause`, แยกรอบ Quota (บท 49)

### 68.7 Network Error
- **อาการ:** Timeout เกือบทุก Module
- **ตรวจ:** `ip route; ping -c 3 1.1.1.1; curl -I https://crt.sh`
- **แก้:** แก้ Network/Proxy, ตั้ง `_socks*` ถ้าองค์กรบังคับ Proxy, เพิ่ม `_fetchtimeout`

### 68.8 DNS Error
- **อาการ:** ไม่มี `IP_ADDRESS` เลย, `INTERNET_NAME_UNRESOLVED` จำนวนมากผิดปกติ
- **ตรวจ:** `cat /etc/resolv.conf; dig example.com +short`
- **แก้:** แก้ Resolver ของระบบ หรือตั้ง `_dnsserver`

### 68.9 Database Error
- **อาการ:** `database is locked`, `Failed to initialize database`
- **สาเหตุ:** หลายโปรเซสเขียน DB พร้อมกัน, ไฟล์เสีย, ดิสก์เต็ม
- **ตรวจ:** `df -h $SPIDERFOOT_DATA; sqlite3 $SPIDERFOOT_DATA/spiderfoot.db "PRAGMA integrity_check;"`
- **แก้:** ลด Scan พร้อมกัน, แยก `SPIDERFOOT_DATA`, กู้จาก Backup

### 68.10 Permission Error
- **อาการ:** `Could not read passwd file. Permission denied.` / เขียน Log ไม่ได้
- **ตรวจ:** `ls -la $SPIDERFOOT_DATA $SPIDERFOOT_LOGS`
- **แก้:** `chown -R $USER:$USER` โฟลเดอร์ Data/Logs/Cache อย่ารัน SpiderFoot ด้วย sudo

### 68.11 Port Error
- **อาการ:** Web UI เปิดไม่ได้เพราะ Port ถูกใช้
- **ตรวจ:** `ss -ltnp | grep 5001`
- **แก้:** ปิดโปรเซสเดิม หรือใช้ Port อื่น `-l 127.0.0.1:5002`

### 68.12 Web UI Error
- **อาการ:** หน้าเว็บค้าง/ว่าง, Browser เข้าจากเครื่องอื่นไม่ได้
- **ตรวจ:** `curl -s http://127.0.0.1:5001/ping`, ดู `spiderfoot.error.log`
- **แก้:** Bind อยู่ที่ 127.0.0.1 ตั้งใจให้เข้าจากเครื่องอื่นไม่ได้ ใช้ SSH tunnel (บท 69.3)

### 68.13 CLI Error
- **อาการ:** `-x can only be used with -t`, `-r can only be used when your output format is tab or csv.`, `-D can only be used when using the csv output format.`
- **แก้:** ใช้ Option ตามกฎในบท 4.7–4.8 / `sfcli -e` crash → ส่งคำสั่งทาง stdin (บท 4.16)

### 68.14 Scan Failure
- **อาการ:** สถานะ `ERROR-FAILED`
- **ตรวจ:** `sf> logs <sid> -l 50` หรือ SQL Error ในบท 56.2
- **แก้:** แก้ตามข้อความ Error แล้ว Re-run

### 68.15 Empty Results
- **อาการ:** มีแค่ Event ของ Target
- **สาเหตุ:** Target เป็นค่าสงวน/ไม่มีข้อมูลจริง, ชนิด Target ผิด (บท 10.2), Module ไม่มี Input ที่ต้องการ (บท 46), ไม่มี API Key
- **ตรวจ:** `jq -r '.[0].type' out.json`, `grep "Modules enabled"`

### 68.16 Duplicate Results
- **อาการ:** ค่าเดียวกันหลายแถว
- **สาเหตุ:** ปกติของ SpiderFoot — Event เดียวกันจากคนละ Source/Module
- **แก้:** ใช้ Unique Data View, `data <sid> -u`, `/scaneventresultsunique`, หรือ `sort -u` ตอน Processing

### 68.17 Slow Scan
- **สาเหตุ:** Module `slow`, `publicapi` ของ VirusTotal (15 วินาที/Query), Spider เว็บใหญ่, Netblock ใหญ่
- **ตรวจ:** `sf> logs <sid> -w` ดูว่า Module ใดทำงานนาน
- **แก้:** ตาม บท 67

### 68.18 High CPU
- **สาเหตุ:** Content Analysis กับ `TARGET_WEB_CONTENT` จำนวนมาก, Scan พร้อมกันหลายตัว
- **ตรวจ:** `top -o %CPU`
- **แก้:** ลด `maxpages`, ลด `-max-threads`, ลดจำนวน Scan พร้อมกัน

### 68.19 High RAM
- **สาเหตุ:** Scan ขนาดใหญ่, `maxstorage = 0`, `fetchcerts`, Graph ใหญ่ใน Browser
- **ตรวจ:** `free -h; ps -o rss,cmd -C python3 | sort -rn | head`
- **แก้:** แบ่ง Scan, คืนค่า `maxstorage` 1024, ใช้ GEXF + Gephi แทน Graph ใน Browser

### 68.20 Database Growth
- **ตรวจ:** `ls -lh $SPIDERFOOT_DATA/spiderfoot.db`; `sqlite3 $DB "SELECT scan_instance_id, COUNT(*) FROM tbl_scan_results GROUP BY 1 ORDER BY 2 DESC LIMIT 5;"`
- **แก้:** Export แล้วลบ Scan เก่า, `/vacuum`, แยก DB ต่อ Case

## 69. Security Hardening
### 69.1 Local Binding + Firewall
```bash
python3 sf.py -l 127.0.0.1:5001
sudo apt install -y ufw && sudo ufw default deny incoming && sudo ufw enable
ss -ltnp | grep 5001        # ต้องเห็น 127.0.0.1:5001 ไม่ใช่ 0.0.0.0:5001
```

### 69.2 Authentication (HTTP Digest)
```bash
umask 077
printf 'analyst:%s\n' "$(openssl rand -base64 24)" > $SPIDERFOOT_DATA/passwd
chmod 600 $SPIDERFOOT_DATA/passwd
python3 sf.py -l 127.0.0.1:5001 2>&1 | grep -i auth     # Ctrl+C เมื่อเห็นข้อความ แล้วเปิด Server ตามปกติ
cut -d: -f2- $SPIDERFOOT_DATA/passwd                     # ดูรหัสผ่านที่สร้าง (เก็บใน Password manager)
```
- ผลที่ควรเห็น: `Enabling authentication based on supplied passwd file.`
- ถ้าไม่มีไฟล์ จะเห็นคำเตือน `passwd file contains no passwords. Authentication disabled.`
- ไฟล์เก็บรหัสผ่านแบบ Plain text ป้องกันด้วยสิทธิ์ไฟล์

### 69.3 TLS และการเข้าถึงจากระยะไกล
```bash
cd $SPIDERFOOT_DATA && ~/tools/spiderfoot/generate-certificate   # สร้าง spiderfoot.key/.crt (CN=localhost)
```
- เมื่อมี `spiderfoot.key` และ `spiderfoot.crt` ใน Data dir SpiderFoot จะเปิด HTTPS อัตโนมัติ
- เข้าจากเครื่องอื่นให้ใช้ SSH tunnel แทนการเปิด Port:

```bash
ssh -L 5001:127.0.0.1:5001 analyst@sf-host.example.net
```

### 69.4 ปกป้อง Credential, Log และ Database
```bash
chmod 700 $SPIDERFOOT_DATA $SPIDERFOOT_LOGS $SPIDERFOOT_CACHE
chmod 600 $SPIDERFOOT_DATA/spiderfoot.db
```
- `spiderfoot.db` มี API Key (บท 48.1) → เข้ารหัสดิสก์, ไม่ Sync ขึ้น Cloud ส่วนตัว
- Log อาจมี URL ที่มี Token ของ Provider → ตั้งสิทธิ์ 600
- Docker: ผูก Port ที่ `127.0.0.1` เสมอ และแก้ `docker-compose.yml` จาก `"5001:5001"` เป็น `"127.0.0.1:5001:5001"`

> **คำเตือน:** อย่าเปิด Web UI ออกอินเทอร์เน็ต Web UI สั่ง Scan, อ่าน API Key (Settings) และรัน SQL `SELECT` กับ Database ได้

## 70. Practical Case Studies
ข้อมูลทั้งหมดเป็นสถานการณ์สมมติ ใช้ Reserved Domain/IP

### Case 1 — Subdomain ที่ถูกลืม
```
Initial Indicator : example.com (องค์กรตนเอง)
SpiderFoot Scan   : domain-passive.txt
Module Results    : sfp_crt พบ test.example.org, old-crm.example.com → 192.0.2.50
Correlation       : dev_or_test_system (MEDIUM), host_only_from_certificatetransparency (LOW)
Analysis          : 192.0.2.50 อยู่คนละ ASN กับ Infrastructure หลัก, ไม่อยู่ใน Asset list
Conclusion        : Host เก่าที่ยังเปิดอยู่ → ส่งทีม IT ตรวจและปิด
Export            : correlations CSV + hosts list + SHA256
```

### Case 2 — IP ต้องสงสัยใน Firewall log
```
Initial Indicator : 198.51.100.20
SpiderFoot Scan   : -t MALICIOUS_IPADDR,BLACKLISTED_IPADDR -x
Module Results    : sfp_spamhaus BLACKLISTED_IPADDR, sfp_threatfox MALICIOUS_IPADDR
Correlation       : multiple_malicious (HIGH)
Analysis          : 2 แหล่งอิสระ, ASN เป็น Hosting, ไม่มี Co-host ขององค์กร
Conclusion        : Block ระดับ IP + เฝ้าระวัง /24 (ไม่ Block ทั้ง ASN)
Export            : ioc-list-defanged.tsv
```

### Case 3 — Email พนักงาน (ยินยอม)
```
Initial Indicator : alice@example.com
SpiderFoot Scan   : sfp_haveibeenpwned, sfp_accounts, sfp_gravatar, sfp_pgp
Module Results    : EMAILADDR_COMPROMISED ×3, ACCOUNT_EXTERNAL_OWNED ×4, PGP_KEY ×1
Correlation       : email_in_multiple_breaches (HIGH)
Analysis          : บัญชีภายนอก 2 ใน 4 ยืนยันด้วยตา (Bio ลิงก์ไป example.com)
Conclusion        : บังคับเปลี่ยนรหัสผ่าน + เปิด MFA + Awareness
Export            : รายการชื่อเหตุการณ์ (ไม่เก็บข้อมูลที่รั่ว)
```

### Case 4 — Certificate เชื่อม Host แปลก
```
Initial Indicator : www.example.com
SpiderFoot Scan   : sfp_sslcert, sfp_crt, sfp_dnsresolve
Module Results    : SSL_CERTIFICATE_ISSUED ครอบคลุม pay-example.net
Correlation       : strong_affiliate_certs (INFO)
Analysis          : WHOIS ของ pay-example.net เป็นผู้ให้บริการ Payment ที่องค์กรใช้ (Third-party)
Conclusion        : ความสัมพันธ์ทางธุรกิจ ไม่ใช่ Asset ขององค์กร → FP สำหรับ Attack surface
Export            : หมายเหตุ FP ในรายงาน
```

### Case 5 — Shared Hosting หลอกตา
```
Initial Indicator : 203.0.113.10
SpiderFoot Scan   : ip-context.txt
Module Results    : CO_HOSTED_SITE ×100 (ถึง maxcohost), MALICIOUS_COHOST ×6
Correlation       : multiple_malicious_cohost (LOW)
Analysis          : PROVIDER_HOSTING = ผู้ให้บริการ Shared hosting, IP ตัวเองไม่มี MALICIOUS_IPADDR
Conclusion        : ไม่มีหลักฐานว่า Target เป็นอันตราย → บันทึกเป็นข้อบ่งชี้ระดับต่ำ
Export            : SQL นับ Co-host (บท 42.2) แนบเป็นหลักฐาน
```

### Case 6 — Bucket ชื่อเหมือน
```
Initial Indicator : example.com
SpiderFoot Scan   : sfp_s3bucket, sfp_azureblobstorage, sfp_googleobjectstorage
Module Results    : CLOUD_STORAGE_BUCKET_OPEN: example-dev (ชื่อสมมติ)
Correlation       : cloud_bucket_open (HIGH)
Analysis          : ทีม Cloud ยืนยันว่า Bucket ไม่ใช่ของบริษัท (ไม่มีในบัญชี Cloud)
Conclusion        : FP เรื่องความเป็นเจ้าของ แต่เป็นความเสี่ยงด้าน Brand → เฝ้าระวัง ไม่เข้าถึงเนื้อหา
Export            : Finding + หลักฐานการยืนยันจากทีม Cloud
```

### Case 7 — Metadata เผยชื่อผู้ใช้ภายใน
```
Initial Indicator : www.example.com
SpiderFoot Scan   : sfp_spider, sfp_intfiles, sfp_filemeta, sfp_names
Module Results    : RAW_FILE_META_DATA ×12, SOFTWARE_USED ×3, HUMAN_NAME ×5
Correlation       : data_from_docmeta (INFO)
Analysis          : Author 3 ค่าตรงกับรูปแบบ Username ภายใน
Conclusion        : เสนอกระบวนการล้าง Metadata ก่อนเผยแพร่เอกสาร
Export            : รายการไฟล์ + SHA256 ของไฟล์ต้นฉบับ
```

### Case 8 — Username ในโจทย์ CTF
```
Initial Indicator : "demo_user01" (ข้อมูลโจทย์ที่สร้างขึ้น)
SpiderFoot Scan   : sfp_accounts, sfp_github, sfp_keybase (ผ่าน sfcli start)
Module Results    : ACCOUNT_EXTERNAL_OWNED ×2, PUBLIC_CODE_REPO ×1
Correlation       : ไม่มี (Rule ส่วนใหญ่เน้น Infrastructure)
Analysis          : Repo มีลิงก์ไป test.example.org → Scan ต่อด้วย Domain profile
Conclusion        : พบ Flag ในหน้าเว็บของ test.example.org
Export            : JSON + GEXF สำหรับเขียน Write-up
```

## 71. Advanced Workflows
Workflow ส่วนใหญ่ใช้คำสั่งและ Profile ที่อธิบายแล้ว บทนี้สรุปเป็นรูปแบบที่ทำซ้ำได้ (Objective · Input · Modules · Commands · Expected Output · Analysis · Export)

### WF-01 Domain Intelligence
- **Objective:** แผนที่ Infrastructure สาธารณะของ Domain · **Input:** `example.com`
- **Modules/Commands:** บท 11 ขั้น 1–11 (`run 01-dns` … `run 11-related`)
- **Expected Output:** Host, IP, ASN, Netblock, Certificate, Technology, Reputation
- **Analysis:** เทียบ Asset list, ตัด Shared infra · **Export:** domain-list, ip-list, infrastructure-list

### WF-02 Infrastructure Intelligence
- **Objective:** เข้าใจเจ้าของและบริบทของ Netblock · **Input:** `203.0.113.0/24`
- **Modules:** `sfp_ripe,sfp_whois,sfp_dnsresolve,sfp_spamhaus`
- **Commands:** `python3 sf.py -s 203.0.113.0/24 -m sfp_ripe,sfp_whois,sfp_dnsresolve,sfp_spamhaus -max-threads 2 -o json -q > $R/wf02.json`
- **Expected/Analysis:** `NETBLOCK_OWNER`, `BGP_AS_OWNER`, PTR ของแต่ละ IP, `BLACKLISTED_NETBLOCK` · **Export:** CSV + GEXF

### WF-03 IP Investigation
- **Objective:** ตอบว่า IP เป็นของใครและมีประวัติอะไร · **Input:** `203.0.113.10`
- **Modules/Commands:** `ip-context.txt` (บท 9.4) / บท 63
- **Analysis:** ลำดับ ASN → Hosting → Reputation → Co-host · **Export:** Finding + SQL Co-host

### WF-04 Email Intelligence
- **Objective:** Exposure ของ Email ที่ได้รับอนุญาต · **Input:** `alice@example.com`
- **Modules/Commands:** บท 19.1 (3 ขั้น)
- **Expected:** `EMAILADDR_COMPROMISED`, `ACCOUNT_EXTERNAL_OWNED`, `PGP_KEY`
- **Analysis:** ยืนยันบัญชีด้วยตา · **Export:** ชื่อเหตุการณ์ Breach + บัญชีที่ยืนยัน

### WF-05 Username Intelligence
- **Objective:** บัญชีสาธารณะของ Username · **Input:** `alice_example`
- **Commands:** บท 20.1 + Sherlock ↔ sfp_accounts (บท 61.2)
- **Analysis:** ตัด `SIMILAR_ACCOUNT_EXTERNAL`, ใช้ผลที่พบทั้งสองเครื่องมือ · **Export:** รายการบัญชี + Screenshot

### WF-06 Corporate Intelligence
- **Objective:** Exposure ขององค์กรตนเอง · **Input:** Domain list
- **Commands:** บท 64 · **Expected:** Correlation ระดับ HIGH/MEDIUM
- **Analysis:** แยก Asset/Third-party · **Export:** รายงานตามบท 59.2

### WF-07 Certificate Intelligence
- **Objective:** Host ที่เชื่อมผ่าน Certificate · **Input:** `example.com`
- **Commands:** `python3 sf.py -s example.com -m sfp_dnsresolve,sfp_crt,sfp_sslcert -F INTERNET_NAME,SSL_CERTIFICATE_ISSUED,SSL_CERTIFICATE_EXPIRED -o csv -r -q`
- **Analysis:** CT history vs Cert ที่ใช้อยู่จริง, `cert_expired` · **Export:** CSV

### WF-08 Threat Intelligence
- **Objective:** ประเมินความเป็นอันตรายของ Indicator · **Input:** `198.51.100.77`
- **Commands:** บท 62 · **Expected:** `MALICIOUS_*`, `BLACKLISTED_*`, `multiple_malicious`
- **Analysis:** ระดับความเชื่อมั่น High/Medium/Low · **Export:** ioc-list-defanged

### WF-09 IOC Investigation (Batch)
- **Objective:** Triage IOC จำนวนมาก · **Input:** `iocs.txt`
- **Commands:** บท 34.1–34.2 (Strict mode ต่อ IOC)
- **Analysis:** นับ Hit ต่อ IOC, จุดร่วม · **Export:** `ioc-hits.tsv`

### WF-10 Malware Infrastructure Investigation
- **Objective:** Infrastructure รอบ Domain/IP ที่ได้จากรายงาน Malware · **Input:** `update-check.example.net`
- **Commands:** บท 33 (Module abuse.ch/ThreatFox/VXVault/CyberCrime-Tracker/Hybrid Analysis)
- **Analysis:** ASN/Registrar/Certificate ที่ใช้ร่วมกัน (บท 42 ก่อนสรุป) · **Export:** JSON + Timeline

### WF-11 Cloud Infrastructure OSINT
- **Objective:** Cloud storage และ Cloud hosting ที่เกี่ยวข้อง · **Input:** `example.com`
- **Commands:** บท 27 + `sfp_hosting` กับ IP ทั้งหมด
- **Expected:** `CLOUD_STORAGE_BUCKET(_OPEN)`, `PROVIDER_HOSTING`, `outlier_cloud`
- **Analysis:** ยืนยันความเป็นเจ้าของกับทีม Cloud · **Export:** Finding list

### WF-12 Web Technology Intelligence
- **Objective:** Technology stack และ Header ที่ผิดปกติ · **Input:** `www.example.com`
- **Commands:** บท 23 + 25 (+ Tool module ถ้าติดตั้ง)
- **Expected:** `WEBSERVER_BANNER`, `WEBSERVER_TECHNOLOGY`, `URL_WEB_FRAMEWORK`, `WEB_ANALYTICS_ID`
- **Analysis:** แยก Proxy/CDN ออกจาก Origin · **Export:** CSV

### WF-13 Breach Intelligence
- **Objective:** Exposure จากเหตุการณ์รั่วไหลของ Domain ตนเอง · **Input:** `example.com`
- **Commands:** `python3 sf.py -s example.com -m sfp_dnsresolve,sfp_emailformat,sfp_pgp,sfp_haveibeenpwned,sfp_psbdmp -F EMAILADDR,EMAILADDR_COMPROMISED,LEAKSITE_URL -o csv -r -q`
- **Analysis:** นับ Email ต่อเหตุการณ์ (ไม่เก็บ Credential) · **Export:** สรุปต่อเหตุการณ์

### WF-14 Multi-Target Investigation
- **Objective:** หลาย Domain/IP ในงานเดียว · **Input:** `targets.txt`
- **Commands:** `sf-batch.sh` (บท 52.1) หรือ `xargs -P 2` (บท 66.3)
- **Analysis:** Merge + หา Entity ที่พบใน ≥ 2 Target (บท 57) · **Export:** `merged.tsv`

### WF-15 Cross-Source Correlation
- **Objective:** ยืนยัน Finding ด้วยหลายแหล่ง · **Input:** Scan ID ที่จบแล้ว
- **Commands:**

```bash
sqlite3 -header -column $DB "SELECT data, COUNT(DISTINCT module) AS sources, GROUP_CONCAT(DISTINCT module) AS modules
FROM tbl_scan_results WHERE scan_instance_id='143B53FF' AND type='INTERNET_NAME' AND false_positive=0
GROUP BY data HAVING sources >= 2 ORDER BY sources DESC;"
```
- **Analysis:** Host ที่ยืนยันจาก ≥ 2 Module อิสระน่าเชื่อถือกว่า + เขียน Correlation Rule แบบ Threshold (บท 41.6) · **Export:** ผล Query เป็น CSV (`sqlite3 -csv`)

## 72. Command Reference
### Installation / Update / Version / Help
```bash
sudo apt install -y spiderfoot                                   # Kali package
git clone https://github.com/smicallef/spiderfoot.git && cd spiderfoot
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
git pull && pip install -r requirements.txt                      # update
python3 sf.py -V                                                 # version
python3 sf.py --help                                             # help
python3 sfcli.py -b                                              # CLI client banner
```

### CLI Scan
```bash
python3 sf.py -s example.com -m sfp_dnsresolve,sfp_dnsraw         # modules
python3 sf.py -s example.com -u passive                           # use case
python3 sf.py -s <AUTHORIZED> -t INTERNET_NAME -f                 # by type (เปิด Module จำนวนมาก บท 46)
python3 sf.py -s 203.0.113.10 -t MALICIOUS_IPADDR -x              # strict
python3 sf.py -s '"Alice Example"' -m sfp_accounts                # person
python3 sf.py -s alice_example -m sfp_accounts                    # username
python3 sf.py -s +6620000000 -m sfp_phone                         # phone
python3 sf.py -C <SCAN_ID>                                        # correlate
python3 sf.py -M ; python3 sf.py -T                               # modules / types
python3 sf.py -s example.com -m sfp_crt -max-threads 2 -q         # concurrency, quiet
```

### Output
Option ของ Output ทั้งหมดดูบท 4.8 (`-o json|csv|tab`, `-r`, `-n`, `-D`, `-F`, `-H`, `-S`)

### Web UI / sfcli
```bash
python3 sf.py -l 127.0.0.1:5001
python3 sfcli.py -s http://127.0.0.1:5001 -n
python3 sfcli.py -s https://127.0.0.1:5001 -i -u analyst -P ~/.sfpass
python3 sfcli.py -s http://127.0.0.1:5001 -n -k < cmds.txt
```

```
start example.com -m sfp_crt,sfp_dnsresolve -n name     start 64496 -m sfp_ripe
start example.com -u Passive                             scans -x
data <sid> -t IP_ADDRESS -u                              summary <sid> -t
find "*example*" -s <sid>                                correlations <sid>
export <sid> -t json|csv|gexf -f /full/path              logs <sid> -w
set global._maxthreads = 2                               set module.sfp_shodan.api_key = YOUR_API_KEY
query SELECT type,COUNT(*) FROM tbl_scan_results GROUP BY type
```

### HTTP / API
```bash
B=http://127.0.0.1:5001
curl -s $B/ping
curl -s -H 'Accept: application/json' -d scanname=t -d scantarget=example.com -d modulelist=sfp_crt -d typelist= -d usecase= $B/startscan
curl -s "$B/scanstatus?id=<SID>"; curl -s $B/scanlist
curl -s "$B/scaneventresults?id=<SID>&eventType=IP_ADDRESS"
curl -s "$B/scanexportjsonmulti?ids=<SID>" -o out.json
curl -s "$B/scaneventresultexport?id=<SID>&type=ALL&filetype=csv" -o out.csv
curl -s --data-urlencode "query=SELECT COUNT(*) FROM tbl_scan_results" $B/query
curl -s "$B/stopscan?id=<SID>"; curl -s "$B/scandelete?id=<SID>"; curl -s $B/vacuum
```

### Configuration / API Keys
```bash
curl -s $B/optsexport | grep api_key            # ดู Key ที่ตั้ง (ระวังหน้าจอ)
chmod 600 ~/.config/spiderfoot/keys.cfg         # ไฟล์ Import
export SPIDERFOOT_DATA=... SPIDERFOOT_LOGS=... SPIDERFOOT_CACHE=...
```

### JSON / CSV
```bash
jq length out.json
jq -r '.[].type' out.json | sort | uniq -c | sort -rn
jq -r '.[] | select(.type=="IP Address") | .data' out.json | sort -u
jq -r '.[] | select(.event_type=="IP_ADDRESS" and .false_positive==0) | .data' export.json
jq -r '.[] | [.module,.type,.source,.data] | @csv' out.json
csvcut -c Type,Data SpiderFoot.csv | csvgrep -c Type -m IP_ADDRESS
```

### Linux / DNS / Network (Validation)
```bash
dig +short A example.com; dig +short NS example.com; dig -x 203.0.113.10 +short
host -t MX example.com; nslookup example.com
whois example.com; whois -h whois.cymru.com " -v 203.0.113.10"
curl -sI https://www.example.com
echo | openssl s_client -connect www.example.com:443 -servername www.example.com 2>/dev/null | openssl x509 -noout -subject -dates
ss -ltnp | grep 5001; ip route; ping -c 3 1.1.1.1
```

### Automation / Troubleshooting
```bash
~/bin/sf-batch.sh targets.txt profile.txt outdir
.venv/bin/python ~/bin/sf-dryrun.py MALICIOUS_IPADDR               # Module ที่ -t จะเปิด
grep -E "Modules enabled|ERROR" scan.log
tail -f $SPIDERFOOT_LOGS/spiderfoot.error.log
sqlite3 $DB "PRAGMA integrity_check;"
sqlite3 $DB "SELECT component,message FROM tbl_scan_log WHERE scan_instance_id='<SID>' AND type='ERROR';"
```

## 73. Final Checklist
### Before Scan
- [ ] มี Scope/หนังสืออนุญาต หรือเป็น Lab/CTF/ระบบตนเอง
- [ ] ตั้ง `SPIDERFOOT_DATA/LOGS/CACHE` ของ Case
- [ ] ตรวจ Version (`-V`) และชื่อ Module ใน Profile (`-M`)
- [ ] ตรวจชนิด Target (บท 10.4) — ASN/IPv6 ใช้ Web UI หรือ sfcli
- [ ] ไม่มี Module `invasive` ถ้า Scope ไม่อนุญาต / ไม่รัน `sf.py -s` แบบไม่ระบุ Module
- [ ] ไม่ใช้ `-t` หรือแท็บ By Required Data โดยไม่มี `-x` หรือไม่ได้ Dry-run (บท 46.2)
- [ ] API Key ครบสำหรับ Module ที่ต้องใช้ และประเมิน Quota แล้ว

### During Scan
- [ ] ดู `Modules enabled (N)` ตรงกับที่ตั้งใจ
- [ ] เฝ้าดู Error/429 (`logs <sid> -w`)
- [ ] หยุดเมื่อพบ Shared infrastructure ขยายตัว

### After Scan
- [ ] ตรวจ Correlations และสถานะ `FINISHED`
- [ ] Export JSON/CSV/Log/Correlation + SHA256
- [ ] บันทึก Scan ID และ Profile ใน `scan-log.md`

### Before Export / Reporting
- [ ] ตั้ง False Positive พร้อมเหตุผล
- [ ] ไม่มี API Key ในไฟล์ส่งมอบ ไม่ส่ง `spiderfoot.db`
- [ ] Defang IOC
- [ ] แยก "ยืนยันแล้ว" กับ "ข้อบ่งชี้"

### Threat Intelligence
- [ ] แยก `MALICIOUS_IPADDR` ของ Target ออกจาก Subnet/Netblock/Co-host/Affiliate
- [ ] ≥ 2 แหล่งอิสระสำหรับระดับ High
- [ ] ดูอายุข้อมูล (age limit ของ Module)

### Infrastructure
- [ ] ทุก IP มี ASN/Netblock owner
- [ ] ระบุ CDN/Cloud/Shared hosting แล้ว
- [ ] Passive DNS ยืนยันด้วย `dig` ปัจจุบัน

### Corporate OSINT
- [ ] Asset ที่พบเทียบกับ Inventory
- [ ] ข้อมูลบุคคลเก็บเท่าที่จำเป็น
- [ ] Third-party แยกจาก Asset ขององค์กร

### IOC
- [ ] Refang ก่อน Scan, Defang ก่อนรายงาน
- [ ] ใช้ Strict mode กับ IOC จำนวนมาก
- [ ] "ไม่มี Hit" ไม่ถูกเขียนว่า "ปลอดภัย"

### False Positive
- [ ] ตรวจ Shared hosting / CDN / Cloud / Reverse proxy / Shared cert / Dynamic IP / Third-party / DNS provider
- [ ] ผลจาก Module `errorprone` ถูกตรวจด้วยตาทุกรายการ

### Evidence
- [ ] Timestamp + Source + Event + Raw result ครบต่อ Finding
- [ ] Screenshot ของแหล่งต้นทางสำคัญ
- [ ] `SHA256SUMS` + `custody.log` + Version/Commit ของ SpiderFoot
