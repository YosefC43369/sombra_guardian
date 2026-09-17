# คู่มือการใช้งาน SpiderFoot บน Kali Linux (WSL) สำหรับสืบค้นข้อมูลจากอีเมล (Email OSINT)

> **สรุปสั้น ๆ:** คู่มือนี้อธิบายวิธีติดตั้งและใช้งาน **SpiderFoot** บน Kali Linux ที่รันผ่าน
> **WSL (Windows Subsystem for Linux)** แบบเป็นขั้นเป็นตอน โดยเน้นการใช้งานเพื่อ
> **สืบค้นข้อมูลที่เปิดเผยต่อสาธารณะ (OSINT) จากอีเมล** ในเชิง **ป้องกันและถูกกฎหมาย**
> (เช่น ตรวจสอบว่าอีเมลของตัวเอง/องค์กรตัวเองรั่วไหลหรือไม่) ไม่ใช่การคุกคามหรือละเมิดผู้อื่น

---

## สารบัญ

1. [ข้อควรทราบด้านกฎหมายและจริยธรรม (อ่านก่อน)](#1-ข้อควรทราบด้านกฎหมายและจริยธรรม-อ่านก่อน)
2. [ภาพรวม: มีอีเมลอย่างเดียว จะค้นหาอะไรได้บ้าง](#2-ภาพรวม-มีอีเมลอย่างเดียว-จะค้นหาอะไรได้บ้าง)
3. [เครื่องมือ Email OSINT บน Kali Linux (ภาพรวมสั้น ๆ)](#3-เครื่องมือ-email-osint-บน-kali-linux-ภาพรวมสั้น-ๆ)
4. [SpiderFoot คืออะไร](#4-spiderfoot-คืออะไร)
5. [ขั้นตอนที่ 1 — เตรียม WSL บน Windows](#5-ขั้นตอนที่-1--เตรียม-wsl-บน-windows)
6. [ขั้นตอนที่ 2 — ติดตั้ง Kali Linux บน WSL](#6-ขั้นตอนที่-2--ติดตั้ง-kali-linux-บน-wsl)
7. [ขั้นตอนที่ 3 — อัปเดตระบบและติดตั้ง dependency](#7-ขั้นตอนที่-3--อัปเดตระบบและติดตั้ง-dependency)
8. [ขั้นตอนที่ 4 — ติดตั้ง SpiderFoot](#8-ขั้นตอนที่-4--ติดตั้ง-spiderfoot)
9. [ขั้นตอนที่ 5 — เปิดใช้งาน Web UI ครั้งแรก](#9-ขั้นตอนที่-5--เปิดใช้งาน-web-ui-ครั้งแรก)
10. [ขั้นตอนที่ 6 — ตั้งค่า API Key (เพิ่มความสามารถ)](#10-ขั้นตอนที่-6--ตั้งค่า-api-key-เพิ่มความสามารถ)
11. [ขั้นตอนที่ 7 — สแกนอีเมลผ่าน Web UI](#11-ขั้นตอนที่-7--สแกนอีเมลผ่าน-web-ui)
12. [ขั้นตอนที่ 8 — สแกนอีเมลผ่าน Command Line (CLI)](#12-ขั้นตอนที่-8--สแกนอีเมลผ่าน-command-line-cli)
13. [การอ่านและตีความผลลัพธ์](#13-การอ่านและตีความผลลัพธ์)
14. [โมดูลที่เกี่ยวกับอีเมลที่ควรรู้จัก](#14-โมดูลที่เกี่ยวกับอีเมลที่ควรรู้จัก)
15. [การส่งออกรายงาน (Export)](#15-การส่งออกรายงาน-export)
16. [ตัวอย่างเวิร์กโฟลว์แบบครบวงจร (สรุปคำสั่งทั้งหมด)](#16-ตัวอย่างเวิร์กโฟลว์แบบครบวงจร-สรุปคำสั่งทั้งหมด)
17. [การแก้ปัญหาที่พบบ่อย (Troubleshooting)](#17-การแก้ปัญหาที่พบบ่อย-troubleshooting)
18. [ทางเลือก: รันด้วย Docker](#18-ทางเลือก-รันด้วย-docker)
19. [แหล่งอ้างอิง](#19-แหล่งอ้างอิง)

---

## 1. ข้อควรทราบด้านกฎหมายและจริยธรรม (อ่านก่อน)

OSINT (Open-Source Intelligence) คือการรวบรวมข้อมูลจากแหล่ง **ที่เปิดเผยต่อสาธารณะ**
อยู่แล้ว แต่ "ถูกเปิดเผย" ไม่ได้แปลว่า "ทำอะไรก็ได้" กรุณาปฏิบัติตามหลักต่อไปนี้เสมอ:

- ✅ **ทำได้:** ตรวจสอบอีเมลของ **ตัวเอง** หรืออีเมลของ **องค์กรที่คุณได้รับอนุญาตเป็นลายลักษณ์อักษร**
  (เช่น งาน pentest ที่มี Scope และสัญญา, การตรวจสุขภาพความปลอดภัยของบริษัทตัวเอง,
  การสอบสวนเหตุการณ์ภายในองค์กร)
- ✅ **ทำได้:** ใช้เพื่อการเรียนรู้/วิจัยด้านความปลอดภัย ในสภาพแวดล้อมทดสอบ
- ❌ **ห้าม:** สืบค้น ติดตาม สะกดรอย หรือรวบรวมข้อมูลบุคคลอื่นโดยไม่ได้รับอนุญาต
  (อาจเข้าข่ายการคุกคาม/สตอล์กกิ้ง และผิดกฎหมาย เช่น พ.ร.บ. คุ้มครองข้อมูลส่วนบุคคล PDPA,
  พ.ร.บ. คอมพิวเตอร์ฯ, GDPR)
- ❌ **ห้าม:** นำข้อมูลที่ได้ไปข่มขู่ แบล็กเมล์ ปลอมตัว หรือเข้าถึงบัญชีผู้อื่น
- ⚠️ **ระวัง:** โมดูลบางตัวของ SpiderFoot จะ "ติดต่อเป้าหมายจริง" (active) เช่น สแกนพอร์ต
  หรือ query เว็บไซต์ ควรใช้โหมด **Passive** เมื่อไม่ต้องการให้เป้าหมายรู้ตัว และเมื่อไม่ได้รับอนุญาต

> **หลักการทอง:** ก่อนสแกนทุกครั้ง ให้ถามตัวเองว่า *"ฉันมีสิทธิ์ตามกฎหมายที่จะสืบค้นเป้าหมายนี้หรือไม่?"*
> ถ้าคำตอบไม่ชัดเจนว่า "ใช่" — ให้หยุด

---

## 2. ภาพรวม: มีอีเมลอย่างเดียว จะค้นหาอะไรได้บ้าง

จากอีเมลเพียงรายการเดียว (เช่น `someone@example.com`) เครื่องมือ OSINT สามารถ
**เชื่อมโยง (correlate)** ไปยังข้อมูลสาธารณะได้หลายประเภท เช่น:

| ประเภทข้อมูล | ตัวอย่างสิ่งที่พบได้ | ใช้ประโยชน์เชิงป้องกันอย่างไร |
|---|---|---|
| **Data breach / รั่วไหล** | อีเมลนี้เคยอยู่ในเหตุการณ์ข้อมูลรั่วไหลใดบ้าง | รู้ว่าควรเปลี่ยนรหัสผ่าน/เปิด 2FA |
| **บัญชีที่ผูกไว้** | อีเมลนี้ถูกใช้สมัครแพลตฟอร์มใดบ้าง (บางแหล่ง) | ประเมิน footprint ของตัวเอง |
| **โดเมนที่เกี่ยวข้อง** | โดเมนของอีเมล, ระเบียน DNS, MX, SPF/DMARC | ประเมินความปลอดภัยอีเมลองค์กร |
| **ชื่อ/โปรไฟล์สาธารณะ** | ชื่อที่ปรากฏคู่กับอีเมลในเว็บสาธารณะ | ประเมินข้อมูลที่เปิดเผยเกินจำเป็น |
| **การรั่วในโค้ด** | อีเมลปรากฏในโค้ดสาธารณะ (GitHub/Pastebin) | หา credential/PII ที่หลุดโดยไม่ตั้งใจ |
| **Gravatar / รูปโปรไฟล์** | รูปที่ผูกกับ hash ของอีเมล | ประเมิน footprint |

> ⚠️ ข้อมูลที่ได้เป็นเพียง **เบาะแส** ต้องตรวจสอบยืนยัน (verify) เสมอ เพราะอาจมี
> false positive (ชื่อ/บัญชีซ้ำ, ข้อมูลเก่า, การเดา pattern) ได้บ่อย

---

## 3. เครื่องมือ Email OSINT บน Kali Linux (ภาพรวมสั้น ๆ)

Kali Linux มีเครื่องมือหลายตัวที่ใช้กับอีเมลได้ คู่มือนี้เน้น **SpiderFoot** แต่ควรรู้จักตัวอื่นไว้
เพื่อใช้ยืนยันผลข้ามกัน (cross-check):

| เครื่องมือ | เหมาะกับ | หมายเหตุด้านจริยธรรม |
|---|---|---|
| **SpiderFoot** | แพลตฟอร์มรวมศูนย์ 200+ โมดูล (ครอบคลุมที่สุด) | มีทั้งโหมด passive/active — เลือกให้เหมาะ |
| **theHarvester** | เก็บอีเมล/subdomain/host จากโดเมน | passive เป็นหลัก |
| **holehe** | เช็กว่าอีเมลถูกใช้สมัครเว็บใดบ้าง | ควรใช้กับอีเมลตัวเองเท่านั้น |
| **Maigret / Sherlock** | ค้นหา username ข้ามแพลตฟอร์ม | เน้น username ไม่ใช่อีเมลโดยตรง |
| **h8mail / Mosint** | ตรวจ data breach ของอีเมล | ต้องมี API key บางแหล่ง |
| **Have I Been Pwned (เว็บ/API)** | เช็กการรั่วไหลของอีเมล | มาตรฐานที่เชื่อถือได้ |

> คู่มือฉบับนี้จะลงลึกที่ **SpiderFoot** ตามที่ร้องขอ ส่วนตัวอื่นสามารถทำเป็นคู่มือแยกได้

---

## 4. SpiderFoot คืออะไร

**SpiderFoot** เป็นเครื่องมือ OSINT อัตโนมัติแบบโอเพนซอร์ส เขียนด้วย Python ทำงานเป็น
**เว็บแอปในเครื่อง (local web server)** หรือสั่งผ่าน **command line** ก็ได้ จุดเด่นคือ:

- มี **โมดูล (modules) กว่า 200 ตัว** ที่ดึงข้อมูลจากแหล่งสาธารณะและ API ต่าง ๆ
- รับ **"เป้าหมาย (target)" ได้หลายชนิด**: อีเมล, โดเมน, IP, ชื่อโดเมนย่อย, เบอร์โทร, ชื่อบุคคล, Bitcoin address ฯลฯ
- **เชื่อมโยงข้อมูลอัตโนมัติ** — ผลลัพธ์จากโมดูลหนึ่งกลายเป็น input ให้อีกโมดูลต่อ (correlation)
- เลือกได้ว่าจะทำงานแบบ **Passive** (ไม่แตะเป้าหมาย) หรือรวม **Active** ด้วย

> **หมายเหตุเรื่องเวอร์ชัน:** SpiderFoot เวอร์ชันโอเพนซอร์สหลักคือ **v4.0** โครงสร้างคำสั่งใน
> คู่มือนี้อ้างอิงตาม v4.x หากคุณติดตั้งจาก `apt` ของ Kali อาจได้เวอร์ชันที่ต่างเล็กน้อย
> ให้ยึด `sf.py --help` / `sfcli.py --help` ในเครื่องคุณเป็นหลัก

---

## 5. ขั้นตอนที่ 1 — เตรียม WSL บน Windows

> ทำขั้นตอนในหัวข้อนี้บน **PowerShell (Run as Administrator)** ของ Windows

### 5.1 ตรวจสอบเวอร์ชัน Windows
ต้องเป็น Windows 10 (build 19041 ขึ้นไป) หรือ Windows 11

```powershell
winver
```

### 5.2 ติดตั้ง WSL (วิธีง่ายที่สุด)
คำสั่งเดียวจะเปิดฟีเจอร์ที่จำเป็นและติดตั้ง WSL2 ให้เอง:

```powershell
wsl --install
```

จากนั้น **รีสตาร์ตเครื่อง** หนึ่งครั้ง

### 5.3 ตั้งค่าให้ใช้ WSL2 เป็นค่าเริ่มต้น
WSL2 เร็วกว่าและเข้ากันได้ดีกว่า WSL1:

```powershell
wsl --set-default-version 2
```

### 5.4 อัปเดต kernel ของ WSL (ถ้าจำเป็น)

```powershell
wsl --update
wsl --status
```

> **ถ้า `wsl --install` ใช้ไม่ได้** (Windows เก่า) ให้เปิดฟีเจอร์ด้วยตนเอง:
> ```powershell
> dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
> dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
> ```
> แล้วรีสตาร์ต จากนั้นติดตั้ง "WSL2 Linux kernel update package" จากเว็บ Microsoft และ
> รัน `wsl --set-default-version 2`

---

## 6. ขั้นตอนที่ 2 — ติดตั้ง Kali Linux บน WSL

### 6.1 ดูรายชื่อดิสโทรที่ติดตั้งได้

```powershell
wsl --list --online
```

คุณจะเห็น `kali-linux` อยู่ในรายการ

### 6.2 ติดตั้ง Kali Linux

```powershell
wsl --install -d kali-linux
```

### 6.3 ตั้งค่าผู้ใช้ครั้งแรก
เมื่อ Kali เปิดหน้าต่างขึ้นมาครั้งแรก ให้ตั้ง **username** และ **password**
(password นี้ใช้กับ `sudo` — จำให้ดี)

### 6.4 ตรวจสอบว่ารันด้วย WSL2

กลับไปที่ PowerShell:

```powershell
wsl --list --verbose
```

คอลัมน์ `VERSION` ของ `kali-linux` ควรเป็น `2` ถ้าเป็น `1` ให้แปลง:

```powershell
wsl --set-version kali-linux 2
```

### 6.5 เข้าสู่ Kali
ต่อจากนี้ทุกคำสั่งจะทำ **ภายใน Kali (WSL)** เปิดได้โดย:

```powershell
wsl -d kali-linux
```

หรือค้นหา "Kali Linux" ใน Start Menu

---

## 7. ขั้นตอนที่ 3 — อัปเดตระบบและติดตั้ง dependency

> ต่อจากนี้ทุกคำสั่งรัน **ใน Kali (WSL)** ทั้งหมด

### 7.1 อัปเดตรายชื่อแพ็กเกจและอัปเกรดระบบ

```bash
sudo apt update && sudo apt -y full-upgrade
```

### 7.2 ติดตั้งเครื่องมือพื้นฐานที่จำเป็น

```bash
sudo apt -y install python3 python3-pip python3-venv git curl
```

### 7.3 ตรวจสอบเวอร์ชัน Python (ควร ≥ 3.9)

```bash
python3 --version
```

---

## 8. ขั้นตอนที่ 4 — ติดตั้ง SpiderFoot

มี 3 วิธี เลือกวิธีใดวิธีหนึ่ง — **แนะนำวิธี B (จาก GitHub + virtualenv)** เพราะได้เวอร์ชันใหม่ที่สุดและสะอาดที่สุด

### วิธี A — ติดตั้งจาก apt ของ Kali (ง่ายที่สุด)

```bash
sudo apt -y install spiderfoot
```

เมื่อติดตั้งแล้ว มักเรียกใช้ผ่านคำสั่ง `spiderfoot` ได้เลย (ตรวจด้วย `which spiderfoot`)

> ข้อดี: ง่าย / ข้อเสีย: เวอร์ชันอาจเก่ากว่าใน GitHub

### วิธี B — ติดตั้งจาก GitHub ด้วย virtualenv (แนะนำ)

```bash
# 1) โคลนซอร์สโค้ด
cd ~
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot

# 2) สร้าง virtual environment แยกไว้ (ไม่ปนกับ Python ระบบ)
python3 -m venv venv
source venv/bin/activate

# 3) ติดตั้ง dependency ทั้งหมดของ SpiderFoot
pip install -r requirements.txt
```

> ทุกครั้งที่จะใช้งานในเทอร์มินัลใหม่ อย่าลืม `cd ~/spiderfoot && source venv/bin/activate` ก่อน

### วิธี C — ใช้ pipx (ติดตั้งแบบแยก environment อัตโนมัติ)

```bash
sudo apt -y install pipx
pipx ensurepath
pipx install spiderfoot
```

### 8.1 ทดสอบว่าติดตั้งสำเร็จ

- ถ้าใช้ **วิธี B**:
  ```bash
  python3 sf.py --help
  ```
- ถ้าใช้ **วิธี A/C**:
  ```bash
  spiderfoot --help
  ```

ถ้าเห็นข้อความ help/usage แสดงว่าติดตั้งสำเร็จ ✅

---

## 9. ขั้นตอนที่ 5 — เปิดใช้งาน Web UI ครั้งแรก

SpiderFoot ทำงานเป็นเว็บเซิร์ฟเวอร์ในเครื่อง ต้องระบุ IP:port ที่จะให้ฟัง

### 9.1 เปิดเซิร์ฟเวอร์ (bind กับ localhost เท่านั้น — ปลอดภัย)

```bash
# วิธี B (จาก GitHub):
python3 sf.py -l 127.0.0.1:5001

# วิธี A/C:
spiderfoot -l 127.0.0.1:5001
```

- `-l 127.0.0.1:5001` = ให้ฟังเฉพาะเครื่องตัวเอง (localhost) ที่พอร์ต 5001

> ⚠️ **ความปลอดภัย:** อย่า bind กับ `0.0.0.0` โดยไม่จำเป็น เพราะ SpiderFoot **ไม่มีระบบล็อกอิน**
> ในตัว การเปิดออกสู่เครือข่ายเท่ากับให้ใครก็ได้สั่งสแกนผ่านเครื่องคุณ ให้ใช้ `127.0.0.1` เสมอ

### 9.2 เปิดเบราว์เซอร์บน Windows

WSL2 ส่งต่อพอร์ต `localhost` ให้ Windows อัตโนมัติ เปิดเบราว์เซอร์แล้วไปที่:

```
http://127.0.0.1:5001
```

> ถ้าเปิดไม่ได้ ให้ลองหา IP ของ WSL ด้วย `ip addr | grep eth0` แล้วเข้าผ่าน IP นั้น
> หรือดูหัวข้อ [Troubleshooting](#17-การแก้ปัญหาที่พบบ่อย-troubleshooting)

### 9.3 (ทางเลือก) รันแบบ background
ถ้าไม่อยากให้เทอร์มินัลค้าง:

```bash
nohup python3 sf.py -l 127.0.0.1:5001 > ~/spiderfoot.log 2>&1 &
```

หยุดการทำงานภายหลังด้วย: `pkill -f sf.py`

---

## 10. ขั้นตอนที่ 6 — ตั้งค่า API Key (เพิ่มความสามารถ)

โมดูลจำนวนมากทำงานได้โดย **ไม่ต้องมี API key** แต่โมดูลสำคัญบางตัว (โดยเฉพาะที่เกี่ยวกับ
data breach) จะให้ผลดีขึ้นมากเมื่อใส่ key ตัวอย่างที่เกี่ยวกับอีเมล:

| แหล่ง | ใช้ทำอะไร | ต้องมี key ไหม |
|---|---|---|
| **HaveIBeenPwned (HIBP)** | ตรวจว่าอีเมลอยู่ใน data breach ใด | ต้องมี key (เสียเงิน) |
| **Hunter.io** | หา pattern อีเมลของโดเมน | ฟรีแบบจำกัดโควตา |
| **EmailRep** | ประเมิน reputation ของอีเมล | มี free tier |
| **Shodan** | ข้อมูล host/บริการที่เปิดสาธารณะ | ฟรีแบบจำกัด |

### วิธีตั้งค่า (ผ่าน Web UI)
1. ที่แถบเมนูบน เลือก **Settings**
2. เลือกโมดูลที่ต้องการ (เช่น `sfp_haveibeenpwned`)
3. วาง API key ในช่องที่กำหนด แล้วกด **Save Changes**

> ไม่มี key ก็เริ่มใช้งานได้ทันที — เพียงแต่ผลลัพธ์บางส่วนจะน้อยลง ค่อยเพิ่ม key ทีหลังได้

---

## 11. ขั้นตอนที่ 7 — สแกนอีเมลผ่าน Web UI

1. เปิด `http://127.0.0.1:5001`
2. คลิก **New Scan**
3. กรอกข้อมูล:
   - **Scan Name:** ตั้งชื่อ เช่น `check-my-email-2026`
   - **Seed Target:** ใส่อีเมลที่ได้รับอนุญาต เช่น `yourname@example.com`
     (SpiderFoot จะตรวจจับชนิดเป้าหมายเป็น *Email Address* ให้อัตโนมัติ)
4. เลือก **โหมดการสแกน** อย่างใดอย่างหนึ่ง:

   | ตัวเลือก | ความหมาย | แนะนำเมื่อ |
   |---|---|---|
   | **By Use Case → All** | เปิดทุกโมดูล | ต้องการข้อมูลครบสุด (แต่ช้าและมี active) |
   | **By Use Case → Footprint** | เก็บ footprint ทั่วไป | งานทั่วไป |
   | **By Use Case → Investigate** | เน้นเบาะแสเชิงสืบสวน | สอบสวนเหตุการณ์ |
   | **By Use Case → Passive** | ไม่แตะเป้าหมายเลย | ✅ ต้องการความ "เงียบ" และปลอดภัยที่สุด |
   | **By Required Data** | เลือกตามชนิดข้อมูลที่ต้องการ | เจาะจง เช่น เอาแค่ "Email"/"Breach" |
   | **By Module** | เลือกโมดูลเอง | ผู้ใช้ขั้นสูง |

   > สำหรับ Email OSINT เชิงป้องกันแบบปลอดภัย แนะนำเริ่มด้วย **Passive**

5. กด **Run Scan Now**
6. ระหว่างสแกน ดูผลแบบเรียลไทม์ได้ที่แท็บ:
   - **Status** — ความคืบหน้าและสถานะแต่ละโมดูล
   - **Browse** — ผลลัพธ์แยกตามชนิดข้อมูล
   - **Graph** — แผนภาพความเชื่อมโยงระหว่างข้อมูล
   - **Correlations** — ความสัมพันธ์เด่นที่ SpiderFoot ไฮไลต์ให้

---

## 12. ขั้นตอนที่ 8 — สแกนอีเมลผ่าน Command Line (CLI)

CLI เหมาะกับการทำสคริปต์อัตโนมัติหรือรันบนเซิร์ฟเวอร์ที่ไม่มี GUI

> คำสั่งด้านล่างใช้รูปแบบของ **วิธี B** (`python3 sf.py`) — ถ้าติดตั้งด้วย apt/pipx
> ให้แทน `python3 sf.py` ด้วย `spiderfoot`

### 12.1 ดูวิธีใช้ทั้งหมด

```bash
python3 sf.py --help
```

### 12.2 ดูรายชื่อโมดูลทั้งหมด

```bash
python3 sf.py -M
```

### 12.3 ดูชนิดข้อมูล (data types) ที่ SpiderFoot รู้จัก

```bash
python3 sf.py -T
```

### 12.4 สแกนอีเมลแบบพื้นฐาน (แสดงผลบนหน้าจอ)

```bash
python3 sf.py -s "yourname@example.com"
```

- `-s` = ระบุ seed target (เป้าหมายเริ่มต้น)

### 12.5 สแกนแบบ Passive เท่านั้น (ปลอดภัยที่สุด — ไม่แตะเป้าหมาย)

```bash
python3 sf.py -s "yourname@example.com" -u passive
```

- `-u passive` = เลือก use case เป็น passive

### 12.6 เลือกเฉพาะบางโมดูลที่เกี่ยวกับอีเมล

```bash
python3 sf.py -s "yourname@example.com" \
  -m sfp_haveibeenpwned,sfp_emailrep,sfp_hunter,sfp_gravatar
```

- `-m` = ระบุรายชื่อโมดูลคั่นด้วย comma (ไม่มีช่องว่าง)

### 12.7 บันทึกผลเป็นไฟล์ (CSV / JSON)

```bash
# CSV
python3 sf.py -s "yourname@example.com" -u passive -o csv > ~/result.csv

# JSON
python3 sf.py -s "yourname@example.com" -u passive -o json > ~/result.json
```

- `-o csv|json|tab` = รูปแบบผลลัพธ์

### 12.8 กรองผลเฉพาะชนิดข้อมูลที่สนใจ

```bash
# เอาเฉพาะข้อมูลที่เป็น "อีเมลที่เกี่ยวข้อง" และ "การรั่วไหล"
python3 sf.py -s "yourname@example.com" -u passive \
  -t EMAILADDR,EMAILADDR_COMPROMISED,ACCOUNT_EXTERNAL_OWNED
```

- `-t` = filter ตาม data type (ดูชื่อชนิดได้จาก `-s ... -T` หรือเอกสาร)

### 12.9 ตารางสรุปแฟล็ก CLI ที่ใช้บ่อย

| แฟล็ก | ความหมาย |
|---|---|
| `-s <target>` | ระบุเป้าหมาย (อีเมล/โดเมน/IP ฯลฯ) |
| `-l <ip:port>` | เปิดโหมด Web UI |
| `-m <mods>` | ระบุโมดูลที่จะใช้ (คั่นด้วย comma) |
| `-u <usecase>` | เลือก use case: `all`, `footprint`, `investigate`, `passive` |
| `-t <types>` | กรองตามชนิดข้อมูล |
| `-o <format>` | รูปแบบ output: `tab`, `csv`, `json` |
| `-M` | แสดงรายชื่อโมดูลทั้งหมด |
| `-T` | แสดงชนิดข้อมูลทั้งหมด |
| `-q` | โหมดเงียบ (ลด log) |
| `-x` | strict mode (ใช้เฉพาะโมดูลที่รับ target ชนิดนั้นตรง ๆ) |

### 12.10 ใช้ `sfcli.py` (interactive CLI client)
SpiderFoot มีไคลเอนต์แบบโต้ตอบ เชื่อมกับเซิร์ฟเวอร์ที่รันอยู่:

```bash
# ต้องเปิดเซิร์ฟเวอร์ไว้ก่อน (python3 sf.py -l 127.0.0.1:5001)
python3 sfcli.py -s http://127.0.0.1:5001
```

ในโหมดนี้พิมพ์ `help` เพื่อดูคำสั่งย่อย เช่น `scans`, `data`, `query`

---

## 13. การอ่านและตีความผลลัพธ์

เมื่อสแกนอีเมล ให้โฟกัสชนิดข้อมูล (Data Type) เหล่านี้เป็นพิเศษ:

| Data Type ที่พบ | ความหมาย | สิ่งที่ควรทำต่อ (เชิงป้องกัน) |
|---|---|---|
| `EMAILADDR_COMPROMISED` | อีเมลปรากฏใน data breach | เปลี่ยนรหัสผ่านทันที + เปิด 2FA |
| `PASSWORD_COMPROMISED` | รหัสผ่านที่ผูกกับอีเมลหลุด | เลิกใช้รหัสนั้นทุกที่ |
| `ACCOUNT_EXTERNAL_OWNED` | บัญชีบนแพลตฟอร์มภายนอกที่ผูกอีเมล | ทบทวนว่าจำเป็นหรือไม่ |
| `EMAILADDR` | อีเมลที่เกี่ยวข้องเพิ่มเติม | ตรวจว่าเป็นของเราจริงหรือ typo |
| `HUMAN_NAME` | ชื่อบุคคลที่เชื่อมโยง | ประเมิน PII ที่เปิดเผย |
| `SOCIAL_MEDIA` | โปรไฟล์โซเชียลที่เชื่อมโยง | ตรวจสอบ privacy setting |
| `DOMAIN_NAME` / `INTERNET_NAME` | โดเมนที่เกี่ยวข้อง | ประเมิน DNS/อีเมลซีเคียวริตี้ |

**ข้อควรระวังในการตีความ:**
- ผลลัพธ์เป็น **เบาะแส ไม่ใช่ข้อสรุป** — ต้อง verify ก่อนเชื่อ
- ระวัง **false positive**: ชื่อซ้ำ, ข้อมูลเก่า, การเดา pattern อีเมล
- แยกให้ชัดระหว่าง **confirmed** (ยืนยันได้จริง) กับ **candidate** (แค่ผลจาก CT log/การเดา)

---

## 14. โมดูลที่เกี่ยวกับอีเมลที่ควรรู้จัก

รายชื่อโมดูล (ชื่ออาจต่างเล็กน้อยตามเวอร์ชัน — ตรวจด้วย `python3 sf.py -M`):

| โมดูล | หน้าที่ | Passive/Active |
|---|---|---|
| `sfp_haveibeenpwned` | ตรวจ data breach ผ่าน HIBP | Passive (ต้อง key) |
| `sfp_emailrep` | reputation ของอีเมล | Passive |
| `sfp_hunter` | pattern อีเมลของโดเมน | Passive (ต้อง key) |
| `sfp_gravatar` | รูปโปรไฟล์ที่ผูกกับ hash อีเมล | Passive |
| `sfp_email` | ดึง/ตรวจอีเมลจากเนื้อหาที่พบ | Passive |
| `sfp_dnsresolve` | resolve โดเมนของอีเมล | Passive |
| `sfp_whois` | ข้อมูล WHOIS ของโดเมน | Passive |
| `sfp_spider` | เก็บข้อมูลจากเว็บไซต์เป้าหมาย | **Active** |
| `sfp_pgp` | หา PGP key ที่ผูกกับอีเมล | Passive |

> เคล็ดลับ: ถ้าต้องการ "เงียบ" ให้หลีกเลี่ยงโมดูลที่เป็น Active (เช่น `sfp_spider`,
> โมดูลที่ทำ port scan) โดยเลือก use case `passive`

---

## 15. การส่งออกรายงาน (Export)

### ผ่าน Web UI
1. เปิดหน้า **Browse** ของสแกนที่ต้องการ
2. กดปุ่ม **Export** เลือกเป็น **CSV / JSON / GEXF** (GEXF เปิดใน Gephi เพื่อดูกราฟ)

### ผ่าน CLI

```bash
python3 sf.py -s "yourname@example.com" -u passive -o csv > ~/email_report.csv
```

### ข้อมูลถูกเก็บที่ไหน
SpiderFoot เก็บผลใน SQLite database ที่ `~/.spiderfoot/spiderfoot.db`
(สำรองไฟล์นี้เพื่อเก็บประวัติสแกน หรือ query เพิ่มเองด้วย `sqlite3` ได้)

```bash
ls -lh ~/.spiderfoot/
```

---

## 16. ตัวอย่างเวิร์กโฟลว์แบบครบวงจร (สรุปคำสั่งทั้งหมด)

รวมทุกขั้นตอนตั้งแต่ศูนย์ สำหรับตรวจสอบ **อีเมลของตัวเอง** อย่างปลอดภัย:

```powershell
# ===== บน Windows PowerShell (Admin) =====
wsl --install                       # ติดตั้ง WSL
# (รีสตาร์ตเครื่อง)
wsl --set-default-version 2         # ใช้ WSL2
wsl --install -d kali-linux         # ติดตั้ง Kali
# (ตั้ง username/password ครั้งแรก)
wsl -d kali-linux                   # เข้าสู่ Kali
```

```bash
# ===== ใน Kali (WSL) =====
# 1) อัปเดตระบบ
sudo apt update && sudo apt -y full-upgrade
sudo apt -y install python3 python3-pip python3-venv git curl

# 2) ติดตั้ง SpiderFoot (วิธี B)
cd ~
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3) ทดสอบ
python3 sf.py --help

# 4a) ใช้งานแบบ Web UI (เปิดเบราว์เซอร์ที่ http://127.0.0.1:5001)
python3 sf.py -l 127.0.0.1:5001

# 4b) หรือใช้งานแบบ CLI — สแกน passive แล้วเซฟเป็น CSV
python3 sf.py -s "yourname@example.com" -u passive -o csv > ~/email_report.csv

# 5) ดูผล
cat ~/email_report.csv
```

---

## 17. การแก้ปัญหาที่พบบ่อย (Troubleshooting)

| อาการ | สาเหตุ / วิธีแก้ |
|---|---|
| เปิด `http://127.0.0.1:5001` ไม่ได้จาก Windows | ตรวจว่าเซิร์ฟเวอร์ยังรันอยู่; ลองใช้ IP ของ WSL: `ip addr show eth0`; ตรวจ Windows Firewall |
| `pip install -r requirements.txt` ล้มเหลว | รัน `sudo apt install build-essential libssl-dev libffi-dev python3-dev` แล้วลองใหม่ |
| `command not found: python3` | `sudo apt -y install python3 python3-pip` |
| WSL เป็นเวอร์ชัน 1 | `wsl --set-version kali-linux 2` (บน PowerShell) |
| โมดูล breach ไม่คืนผล | ต้องใส่ API key (เช่น HIBP) ใน Settings |
| สแกนช้ามาก | เลี่ยง use case `all`; ใช้ `passive` หรือเลือกเฉพาะโมดูลด้วย `-m` |
| พอร์ต 5001 ถูกใช้แล้ว | เปลี่ยนพอร์ต เช่น `-l 127.0.0.1:5002` |
| เวลาใน WSL เพี้ยน (ทำ API หมดอายุ) | `sudo hwclock -s` หรือรีสตาร์ต WSL: `wsl --shutdown` แล้วเปิดใหม่ |

---

## 18. ทางเลือก: รันด้วย Docker

ถ้าไม่อยากติดตั้ง dependency ในเครื่อง สามารถรัน SpiderFoot ในคอนเทนเนอร์:

```bash
# ติดตั้ง docker ใน Kali (ถ้ายังไม่มี)
sudo apt -y install docker.io
sudo service docker start

# ดึงและรัน SpiderFoot
sudo docker run -p 127.0.0.1:5001:5001 spiderfoot/spiderfoot

# เปิดเบราว์เซอร์ที่ http://127.0.0.1:5001
```

> Docker เหมาะกับการทดลองแบบสะอาด (ลบทิ้งง่าย) แต่การเก็บผลถาวรต้อง mount volume เพิ่ม

---

## 19. แหล่งอ้างอิง

- SpiderFoot — เว็บทางการ: <https://www.spiderfoot.net/>
- SpiderFoot — ซอร์สโค้ด (GitHub): <https://github.com/smicallef/spiderfoot>
- SpiderFoot — เอกสาร/Documentation: <https://github.com/smicallef/spiderfoot/wiki>
- Microsoft WSL — คู่มือทางการ: <https://learn.microsoft.com/windows/wsl/>
- Kali Linux บน WSL: <https://www.kali.org/docs/wsl/>
- Have I Been Pwned: <https://haveibeenpwned.com/>
- OWASP Web Security Testing Guide (Information Gathering): <https://owasp.org/www-project-web-security-testing-guide/>
- MITRE ATT&CK — Reconnaissance (TA0043): <https://attack.mitre.org/tactics/TA0043/>

---

## ⚡ ความเสี่ยงที่ยังเหลืออยู่ (Residual Risks) — ต้องเข้าใจก่อนใช้งาน

> ตามหลักการด้านความปลอดภัย: ไม่มีเครื่องมือใด "ปลอดภัยสมบูรณ์" ต่อไปนี้คือความเสี่ยงที่ยังคงอยู่

1. **ความเสี่ยงทางกฎหมาย** — แม้ข้อมูลจะเปิดสาธารณะ การรวบรวมข้อมูลบุคคลอื่นโดยไม่ได้รับอนุญาต
   อาจผิด PDPA/GDPR/พ.ร.บ.คอมพิวเตอร์ฯ **ผู้ใช้รับผิดชอบเอง**
2. **โมดูล Active เปิดเผยตัวตนคุณ** — บางโมดูลติดต่อเป้าหมายจริง ทำให้เป้าหมายเห็น IP คุณได้
   ใช้ `-u passive` เมื่อต้องการความเงียบ
3. **ความถูกต้องของข้อมูล** — ผลลัพธ์มี false positive สูง ต้อง verify ทุกครั้ง อย่าตัดสินใจจากผลดิบ
4. **ความปลอดภัยของเครื่องมือเอง** — SpiderFoot ไม่มีระบบล็อกอิน อย่า bind กับ `0.0.0.0`;
   ให้ใช้ `127.0.0.1` เสมอ มิฉะนั้นผู้อื่นในเครือข่ายสั่งสแกนผ่านเครื่องคุณได้
5. **API key รั่วไหล** — key ที่ใส่ใน Settings ถูกเก็บใน `~/.spiderfoot/` อย่าแชร์ไฟล์นี้หรือ commit ขึ้น git
6. **ข้อมูลผลลัพธ์คือ PII** — ไฟล์รายงาน (CSV/JSON) และ `spiderfoot.db` มีข้อมูลส่วนบุคคล
   เก็บอย่างปลอดภัยและลบเมื่อไม่ใช้แล้ว

> **บทสรุป:** คู่มือนี้ให้เครื่องมือและวิธีการ ส่วน **การใช้อย่างถูกต้องตามกฎหมายและจริยธรรม**
> เป็นความรับผิดชอบของผู้ใช้ ใช้กับอีเมลของตัวเองหรือเป้าหมายที่ได้รับอนุญาตเท่านั้น
