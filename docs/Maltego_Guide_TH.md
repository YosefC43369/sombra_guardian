# Maltego Guide ภาษาไทย

> คู่มือใช้งาน Maltego แบบลงมือปฏิบัติบน Kali Linux ตั้งแต่ติดตั้งจนถึง Investigation Workflow ระดับกลาง–สูง สำหรับงาน OSINT, Cyber Threat Intelligence และ Digital Investigation บนข้อมูลสาธารณะและระบบที่ได้รับอนุญาตเท่านั้น

## สารบัญ

- [1. บทนำ](#1-บทนำ)
- [2. สิ่งที่ต้องเตรียม](#2-สิ่งที่ต้องเตรียม)
- [3. การติดตั้งบน Kali Linux](#3-การติดตั้งบน-kali-linux)
- [4. การเปิดใช้งาน Maltego](#4-การเปิดใช้งาน-maltego)
- [5. การสร้าง Project / Graph](#5-การสร้าง-project--graph)
- [6. Workspace และส่วนต่าง ๆ ของ UI](#6-workspace-และส่วนต่าง-ๆ-ของ-ui)
- [7. Entity](#7-entity)
- [8. Transform](#8-transform)
- [9. Transform Hub](#9-transform-hub)
- [10. Machine](#10-machine)
- [11. Data Sources](#11-data-sources)
- [12. API และ Credentials](#12-api-และ-credentials)
- [13. การค้นหา Domain](#13-การค้นหา-domain)
- [14. การค้นหา IP](#14-การค้นหา-ip)
- [15. DNS Enumeration](#15-dns-enumeration)
- [16. WHOIS](#16-whois)
- [17. Subdomain Enumeration](#17-subdomain-enumeration)
- [18. Certificate / SSL](#18-certificate--ssl)
- [19. Email Enumeration](#19-email-enumeration)
- [20. Username Investigation](#20-username-investigation)
- [21. Social Media OSINT](#21-social-media-osint)
- [22. Person / Organization Investigation](#22-person--organization-investigation)
- [23. Website Investigation](#23-website-investigation)
- [24. Infrastructure Mapping](#24-infrastructure-mapping)
- [25. ASN](#25-asn)
- [26. Netblock](#26-netblock)
- [27. Autonomous System](#27-autonomous-system)
- [28. URL และ Web Infrastructure](#28-url-และ-web-infrastructure)
- [29. Threat Intelligence](#29-threat-intelligence)
- [30. Malware-related OSINT](#30-malware-related-osint)
- [31. Breach / Leak Intelligence](#31-breach--leak-intelligence)
- [32. Cryptocurrency OSINT](#32-cryptocurrency-osint)
- [33. Geolocation-related OSINT](#33-geolocation-related-osint)
- [34. Metadata Investigation](#34-metadata-investigation)
- [35. Link Analysis](#35-link-analysis)
- [36. Graph Analysis](#36-graph-analysis)
- [37. การเชื่อม Entity หลายประเภท](#37-การเชื่อม-entity-หลายประเภท)
- [38. การใช้ Transform หลายขั้นต่อเนื่อง](#38-การใช้-transform-หลายขั้นต่อเนื่อง)
- [39. การสร้าง Investigation Workflow](#39-การสร้าง-investigation-workflow)
- [40. Maltego Machines](#40-maltego-machines)
- [41. การสร้าง Workflow แบบ Semi-Automated](#41-การสร้าง-workflow-แบบ-semi-automated)
- [42. การใช้ API](#42-การใช้-api)
- [43. การเพิ่ม Data Source](#43-การเพิ่ม-data-source)
- [44. การจัดการ Credentials](#44-การจัดการ-credentials)
- [45. การ Export Graph](#45-การ-export-graph)
- [46. การบันทึกหลักฐาน](#46-การบันทึกหลักฐาน)
- [47. การจัดระเบียบ Investigation](#47-การจัดระเบียบ-investigation)
- [48. การทำ Case Study](#48-การทำ-case-study)
- [49. Troubleshooting](#49-troubleshooting)
- [50. แนวทางใช้งานบน Kali Linux](#50-แนวทางใช้งานบน-kali-linux)
- [51. เปรียบเทียบ Maltego กับเครื่องมืออื่น](#51-เปรียบเทียบ-maltego-กับเครื่องมืออื่น)
- [52. ตัวอย่าง Workflow แบบครบกระบวนการ](#52-ตัวอย่าง-workflow-แบบครบกระบวนการ)
- [53. Checklist สำหรับ OSINT Investigation](#53-checklist-สำหรับ-osint-investigation)
- [54. สรุป Command และ Workflow ที่ใช้บ่อย](#54-สรุป-command-และ-workflow-ที่ใช้บ่อย)

---
## 1. บทนำ

### 1.1 คู่มือนี้คืออะไร
คู่มือนี้สอนใช้ Maltego บน Kali Linux ตั้งแต่ติดตั้งจนถึงสร้าง Investigation Workflow แบบหลายขั้นตอน เน้นลงมือทำจริง ทุกบทพยายามเรียงตามลำดับนี้:

```
คำสั่ง > ขั้นตอนปฏิบัติ > ตัวอย่าง > ผลลัพธ์ที่ควรเห็น > คำอธิบาย
```

Maltego คือโปรแกรม Link Analysis ที่แสดงข้อมูลเป็น Graph ประกอบด้วย:
- **Entity** — ข้อมูลหนึ่งชิ้น เช่น Domain, IP Address, Email Address
- **Transform** — คำสั่งที่รับ Entity หนึ่งตัว แล้วไปถาม Data Source เพื่อคืน Entity ใหม่กลับมา
- **Link** — เส้นเชื่อมระหว่าง Entity ที่บอกว่าข้อมูลมาจากไหน
- **Machine** — ชุดของ Transform ที่รันต่อกันอัตโนมัติ

ทั้งหมดรวมกันเป็น Graph ที่ใช้ดูความสัมพันธ์ของข้อมูล

### 1.2 ใครควรอ่าน
- ผู้ใช้ Kali Linux ที่ต้องการเริ่มใช้ Maltego
- นักวิเคราะห์ SOC / CTI ที่ต้องการ Map Infrastructure จาก IOC
- ผู้เล่น CTF ที่มีโจทย์ OSINT
- ผู้ดูแลระบบที่ต้องการตรวจสอบ Attack Surface ขององค์กรตนเอง

### 1.3 ขอบเขตการใช้งานและกฎหมาย
> **คำเตือน:** คู่มือนี้เป็นคู่มือ OSINT และการวิเคราะห์ข้อมูลสาธารณะเท่านั้น ใช้กับระบบของตนเอง, Lab, CTF, ระบบที่ได้รับอนุญาตเป็นลายลักษณ์อักษร หรือข้อมูลสาธารณะที่ค้นหาได้โดยชอบด้วยกฎหมาย การรวบรวมข้อมูลบุคคลอาจอยู่ภายใต้กฎหมายคุ้มครองข้อมูลส่วนบุคคล (เช่น PDPA ของไทย) ตรวจสอบข้อกำหนดของหน่วยงานก่อนเริ่มงานทุกครั้ง

คู่มือนี้ **ไม่** สอน:
- การเจาะระบบโดยไม่ได้รับอนุญาต
- การขโมย Credential หรือ Account Takeover
- การสร้างหรือแพร่ Malware
- การหลบเลี่ยงระบบรักษาความปลอดภัย

### 1.4 ข้อมูลตัวอย่างที่ใช้ในคู่มือ
ตัวอย่างทั้งหมดใช้ค่าที่สงวนไว้สำหรับเอกสาร (Reserved for documentation) หรือค่าสมมติ:

| ประเภท | ค่าที่ใช้ |
|---|---|
| Domain | `example.com`, `example.org`, `example.net` |
| IPv4 | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| IPv6 | `2001:db8::/32` |
| ASN | `AS64496`–`AS64511` |
| Email | `alice@example.com`, `bob@example.org` |
| Username | `alice_example`, `demo_user01` |

> **หมายเหตุ:** IP และ ASN สำหรับเอกสารจะไม่คืนข้อมูลจริงจาก Data Source ส่วนใหญ่ (หลายบริการจะตอบว่าเป็น "bogon" หรือไม่พบข้อมูล) ถ้าต้องการเห็นผลลัพธ์จริงให้ทดลองกับ Domain หรือ IP ขององค์กรที่คุณเป็นเจ้าของหรือได้รับอนุญาต ส่วน `example.com` เป็น Domain ที่ IANA ดูแลและตอบ DNS ได้จริง จึงใช้ทดสอบ DNS พื้นฐานได้

### 1.5 เรื่องเวอร์ชันและ Edition
> **หมายเหตุ:** ชื่อเมนูหรือหน้าตา UI อาจแตกต่างกันตามเวอร์ชันของ Maltego บริษัท Maltego ปรับชื่อผลิตภัณฑ์, Edition และรายการ Transform เป็นระยะ ๆ ชื่อ Transform ในคู่มือนี้อ้างจาก Standard Transforms ที่พบบ่อยในรุ่น Desktop ถ้าหาไม่เจอ ให้ใช้ช่องค้นหาในเมนู Run Transform แล้วพิมพ์คำสำคัญ เช่น `DNS`, `IP`, `MX`, `Netblock`

สิ่งที่ขึ้นกับ Edition / Account (ตรวจสอบเงื่อนไขปัจจุบันที่เว็บไซต์ Maltego เสมอ):
- จำนวนผลลัพธ์สูงสุดต่อการรัน Transform หนึ่งครั้ง (Edition ฟรีมักจำกัดต่ำกว่ารุ่นเสียเงิน)
- จำนวน Entity สูงสุดต่อ Graph
- Transform Hub Provider ที่ติดตั้งได้
- สิทธิ์ใช้งานเชิงพาณิชย์ (Edition ฟรีมักจำกัดการใช้เชิงพาณิชย์)

---

## 2. สิ่งที่ต้องเตรียม

### 2.1 Checklist ก่อนเริ่ม
- [ ] Kali Linux ที่อัปเดตแล้ว (Bare metal, VM หรือ WSL ที่มี GUI)
- [ ] RAM อย่างน้อย 4 GB (แนะนำ 8 GB ขึ้นไปถ้าทำ Graph ใหญ่)
- [ ] พื้นที่ดิสก์ว่างอย่างน้อยหลาย GB สำหรับโปรแกรม, Cache และไฟล์ Graph
- [ ] อินเทอร์เน็ตที่ออกไปยัง HTTPS (port 443) ได้
- [ ] Desktop Environment (Maltego เป็นโปรแกรม GUI ใช้ผ่าน SSH แบบ Text อย่างเดียวไม่ได้)
- [ ] Account ของ Maltego (สมัครเองที่เว็บไซต์ Maltego)
- [ ] API Key ของ Provider ที่ต้องการ (ถ้ามี — ผู้ใช้ต้องสมัครเอง)
- [ ] เอกสารขอบเขตงาน (Scope) หรือหนังสืออนุญาต ถ้าเป็นงานจริง

### 2.2 ตรวจสอบเครื่องก่อนติดตั้ง
```bash
uname -a
cat /etc/os-release
free -h
df -h ~
nproc
echo $XDG_SESSION_TYPE
```

คำอธิบาย:
- `uname -a` — ดู Kernel และสถาปัตยกรรม (x86_64 หรือ aarch64)
- `cat /etc/os-release` — ยืนยันว่าเป็น Kali และดูรุ่น
- `free -h` — ดู RAM ที่เหลือ
- `df -h ~` — ดูพื้นที่ใน Home directory
- `nproc` — จำนวน CPU core
- `echo $XDG_SESSION_TYPE` — ดูว่าใช้ `x11` หรือ `wayland` (มีผลกับโปรแกรม Java บางตัว)

ผลลัพธ์ที่ควรเห็น (ตัวอย่าง):

```
PRETTY_NAME="Kali GNU/Linux Rolling"
NAME="Kali GNU/Linux"
ID=kali
...
               total        used        free
Mem:           7.7Gi       2.1Gi       4.3Gi
...
x11
```

> **หมายเหตุ:** ถ้าใช้ Kali บน ARM (เช่น Raspberry Pi หรือ Apple Silicon VM) ให้ตรวจสอบก่อนว่า Maltego รุ่นปัจจุบันรองรับสถาปัตยกรรมนั้นหรือไม่

### 2.3 ตรวจสอบ Network เบื้องต้น
```bash
ip addr
ip route
ping -c 4 1.1.1.1
dig example.com +short
curl -I https://www.maltego.com
```

- `ip addr` — ดูว่า Interface มี IP แล้ว
- `ip route` — ดูว่ามี default gateway
- `ping -c 4 1.1.1.1` — ทดสอบการออกอินเทอร์เน็ตระดับ IP
- `dig example.com +short` — ทดสอบ DNS resolution
- `curl -I https://www.maltego.com` — ทดสอบ HTTPS ไปยังเว็บไซต์ Maltego

ถ้าทุกคำสั่งผ่าน แสดงว่าเครื่องพร้อม ถ้าไม่ผ่าน ดูบท [Troubleshooting](#49-troubleshooting)

---

## 3. การติดตั้งบน Kali Linux

มีสองวิธีหลัก เลือกวิธีใดวิธีหนึ่ง

### 3.1 วิธีที่ 1: ติดตั้งจาก Kali Repository
Kali มี Package ชื่อ `maltego` อยู่ใน Repository (และมักติดมากับ Metapackage แบบ Default อยู่แล้ว)

#### ขั้นตอนที่ 1 — ตรวจว่าติดตั้งแล้วหรือยัง
```bash
which maltego
dpkg -l | grep -i maltego
apt policy maltego
```

- ถ้า `which maltego` คืน path เช่น `/usr/bin/maltego` แสดงว่าติดตั้งแล้ว
- `apt policy maltego` บอกเวอร์ชันที่ติดตั้ง (Installed) และเวอร์ชันใน Repository (Candidate)

#### ขั้นตอนที่ 2 — อัปเดตและติดตั้ง
```bash
sudo apt update
sudo apt install -y maltego
```

- `sudo apt update` — ดึงรายการ Package ล่าสุดจาก Repository
- `sudo apt install -y maltego` — ติดตั้ง Maltego พร้อม Dependency

#### ขั้นตอนที่ 3 — ยืนยันการติดตั้ง
```bash
apt policy maltego
ls -la /usr/share/maltego 2>/dev/null | head
```

ผลลัพธ์ที่ควรเห็น:

```
maltego:
  Installed: <เวอร์ชัน>
  Candidate: <เวอร์ชัน>
```

> **หมายเหตุ:** Path ของโปรแกรมอาจต่างไปตามเวอร์ชันของ Package ถ้า `/usr/share/maltego` ไม่มี ให้ใช้ `dpkg -L maltego | head -50` ดูว่าไฟล์ถูกติดตั้งไว้ที่ไหน

### 3.2 วิธีที่ 2: ติดตั้งจากไฟล์ .deb ของ Maltego โดยตรง
ใช้วิธีนี้เมื่อต้องการเวอร์ชันใหม่กว่าที่อยู่ใน Kali Repository

#### ขั้นตอน
1. เปิดเว็บไซต์ทางการของ Maltego ไปที่หน้า Download
2. เลือกไฟล์สำหรับ Linux แบบ `.deb` (Debian/Ubuntu/Kali)
3. บันทึกไฟล์ไว้ใน `~/Downloads`
4. ติดตั้งด้วย apt (apt จะจัดการ Dependency ให้)

```bash
cd ~/Downloads
ls -lh Maltego*.deb
sha256sum Maltego*.deb
sudo apt install ./Maltego*.deb
```

- `sha256sum` — คำนวณ Hash ของไฟล์ เพื่อเทียบกับค่าที่เว็บไซต์ประกาศ (ถ้ามีประกาศ)
- `sudo apt install ./ไฟล์.deb` — ต้องมี `./` นำหน้า ไม่งั้น apt จะไปหาใน Repository

> **หมายเหตุ:** ชื่อไฟล์ `.deb` เปลี่ยนตามเวอร์ชัน ให้ตรวจสอบวิธีติดตั้งสำหรับ Kali Linux รุ่นของตนจากเอกสารทางการของ Maltego ทุกครั้ง อย่าดาวน์โหลดจากเว็บไซต์ที่ไม่ใช่ของ Maltego

### 3.3 Java
Maltego เป็นโปรแกรมที่ทำงานบน Java รุ่นใหม่ ๆ มักแนบ Java Runtime มาในตัว แต่ถ้าโปรแกรมแจ้งว่าไม่พบ Java ให้ตรวจสอบ:

```bash
java -version
update-alternatives --list java
```

ถ้ายังไม่มี Java:

```bash
sudo apt install -y default-jre
java -version
```

> **หมายเหตุ:** เวอร์ชัน Java ที่ Maltego ต้องการเปลี่ยนตามรุ่น ให้ดู Release Notes ของ Maltego รุ่นที่คุณติดตั้ง

### 3.4 อัปเดต Maltego
```bash
sudo apt update
sudo apt install --only-upgrade maltego
```

`--only-upgrade` อัปเดตเฉพาะ Package ที่ติดตั้งอยู่แล้ว ไม่ติดตั้งใหม่ถ้ายังไม่มี ตัวโปรแกรม Maltego เองอาจแจ้งเตือนอัปเดตหลังเปิดโปรแกรมด้วย

### 3.5 ถอนการติดตั้ง
```bash
sudo apt remove maltego
# ลบไฟล์ตั้งค่าของ Package ด้วย
sudo apt purge maltego
```

ไฟล์ตั้งค่าส่วนตัว (Graph, Transform settings, Cache) อยู่ใน Home directory และ **ไม่ถูกลบ** โดย apt:

```bash
ls -la ~/.maltego
```

ก่อนลบให้สำรองก่อนเสมอ:

```bash
tar czf ~/maltego-backup-$(date +%F).tar.gz ~/.maltego
```

---

## 4. การเปิดใช้งาน Maltego

### 4.1 เปิดโปรแกรม
วิธีที่ 1 — จาก Terminal:

```bash
maltego &
```

`&` ทำให้โปรแกรมรันเป็น Background และยังใช้ Terminal ต่อได้

วิธีที่ 2 — จากเมนู Kali:

```
Applications → 01 - Information Gathering → OSINT Analysis → maltego
```

> **หมายเหตุ:** ตำแหน่งในเมนูอาจต่างกันตามรุ่นของ Kali และ Desktop Environment ใช้ช่องค้นหาของเมนูแล้วพิมพ์ `maltego` จะเร็วกว่า

วิธีที่ 3 — เปิดพร้อมเก็บ Log ไว้ดูภายหลัง (ใช้ตอนแก้ปัญหา):

```bash
maltego > ~/maltego-console.log 2>&1 &
tail -f ~/maltego-console.log
```

### 4.2 First-run Setup
ครั้งแรกที่เปิด Maltego จะมีหน้าจอตั้งค่าเริ่มต้น ลำดับโดยทั่วไป:
1. **เลือก Product / Edition** — เลือก Edition ที่คุณมีสิทธิ์ใช้ (เช่น Edition ฟรีสำหรับใช้ส่วนตัว หรือรุ่นที่มี License)
2. **ยอมรับ License Agreement** — อ่านเงื่อนไข โดยเฉพาะเรื่องการใช้เชิงพาณิชย์
3. **Login** — ใส่ Email และ Password ของ Maltego Account
4. **ติดตั้ง Transform เริ่มต้น** — โปรแกรมจะดาวน์โหลด Standard Transforms และ Entity พื้นฐาน
5. **Privacy Mode** — มักมีให้เลือกระหว่างโหมดปกติ (Normal) และโหมดที่จำกัด Transform ที่ติดต่อเป้าหมายโดยตรง (Stealth)
6. **เลือก Browser / Option อื่น ๆ** — เช่น Browser ที่ใช้เปิดลิงก์
7. **Ready** — เลือกเปิด Blank Graph หรือไปหน้า Home

> **หมายเหตุ:** ชื่อหน้าจอและลำดับขั้นตอนอาจแตกต่างกันตามเวอร์ชันของ Maltego ถ้า Login ไม่ผ่านดู [Troubleshooting](#49-troubleshooting)

### 4.3 เลือก Privacy Mode อย่างไร
| สถานการณ์ | โหมดที่เหมาะ |
|---|---|
| ต้องการผลลัพธ์ครบ ทำกับระบบตัวเองหรือ Lab | Normal |
| ไม่ต้องการให้เครื่องเราติดต่อเป้าหมายโดยตรง | Stealth |

โหมดนี้เปลี่ยนภายหลังได้จากหน้าตั้งค่าของโปรแกรม (ตำแหน่งเมนูขึ้นกับเวอร์ชัน)

### 4.4 ตรวจว่าเปิดสำเร็จ
สิ่งที่ควรเห็นหลังเปิดโปรแกรม:
- แถบ Ribbon ด้านบน (มี Tab เช่น Home, Investigate, View, Organize, Import | Export, Windows — ชื่ออาจต่างตามเวอร์ชัน)
- หน้า Home ที่มีทางเข้า **Transform Hub**
- เมื่อเปิด Graph แล้ว จะเห็น **Entity Palette** ด้านซ้าย และ **Property View / Detail View** ด้านขวา

ตรวจว่าโปรแกรมรันอยู่จาก Terminal:

```bash
pgrep -af maltego
```

---

## 5. การสร้าง Project / Graph

### 5.1 แนวคิด
ใน Maltego Desktop "งาน" หนึ่งงานมักเก็บเป็นไฟล์ Graph หนึ่งไฟล์หรือหลายไฟล์ คู่มือนี้แนะนำให้สร้าง **โฟลเดอร์ Case** บน Kali ไว้เก็บทุกอย่างของงานนั้น

### 5.2 สร้างโฟลเดอร์ Case
```bash
CASE=CASE-2026-001-example
mkdir -p ~/cases/$CASE/{graphs,exports,evidence,notes,raw}
tree ~/cases/$CASE 2>/dev/null || find ~/cases/$CASE -type d
```

ผลลัพธ์:

```
/home/kali/cases/CASE-2026-001-example
├── evidence
├── exports
├── graphs
├── notes
└── raw
```

- `graphs` — ไฟล์ Graph ของ Maltego
- `exports` — CSV, PNG, PDF ที่ Export ออกมา
- `evidence` — Screenshot และไฟล์หลักฐาน
- `notes` — บันทึกการทำงาน
- `raw` — ผลลัพธ์จากเครื่องมืออื่น (dig, whois, curl)

สร้างไฟล์บันทึกเริ่มต้น:

```bash
cat > ~/cases/$CASE/notes/README.md << 'EOF'
# CASE-2026-001-example
- Analyst: <ชื่อผู้วิเคราะห์>
- Start: <วันที่>
- Scope: example.com, 203.0.113.0/24
- Authorization: <เลขที่หนังสืออนุญาต / ลิงก์>
- Goal: Map public infrastructure ของ example.com
EOF
```

### 5.3 สร้าง Graph ใหม่
1. คลิกปุ่ม **New Graph** (มักเป็นไอคอนมุมซ้ายบน หรือใน Tab Home)
2. จะได้ Tab Graph ว่างชื่อประมาณ `New Graph (1)`
3. กด `Ctrl+S` เพื่อบันทึก
4. เลือกโฟลเดอร์ `~/cases/CASE-2026-001-example/graphs/`
5. ตั้งชื่อไฟล์ เช่น `01-domain-recon.mtgl`

> **หมายเหตุ:** นามสกุลไฟล์ Graph ของ Maltego ที่พบบ่อยคือ `.mtgl` (บางรุ่นมีรูปแบบ `.mtgx` สำหรับ Graph แบบรวมไฟล์แนบ) เลือกตามที่หน้าต่าง Save เสนอ

### 5.4 ตั้งชื่อไฟล์ Graph ให้เป็นระบบ
```
<ลำดับ>-<หัวข้อ>-<วันที่>.mtgl

01-domain-recon-2026-09-25.mtgl
02-email-pivot-2026-09-25.mtgl
03-infra-map-2026-09-26.mtgl
```

แยก Graph ตามคำถามที่ต้องการตอบ ดีกว่าใส่ทุกอย่างใน Graph เดียวที่มีหลายพัน Entity

### 5.5 เปิด Graph เดิม
- `Ctrl+O` หรือ File/Open ในเมนูของโปรแกรม
- หรือดับเบิลคลิกจากรายการ Recent Graphs ในหน้า Home

ค้นหาไฟล์ Graph ทั้งหมดในเครื่อง:

```bash
find ~ -name "*.mtgl" -o -name "*.mtgx" 2>/dev/null
```

---

## 6. Workspace และส่วนต่าง ๆ ของ UI

> **หมายเหตุ:** ชื่อเมนูหรือหน้าตา UI อาจแตกต่างกันตามเวอร์ชันของ Maltego ตำแหน่งหน้าต่างทั้งหมดลากย้ายได้ และเปิด/ปิดได้จาก Tab **Windows**

### 6.1 ภาพรวมหน้าจอ
```
+---------------------------------------------------------------+
| Ribbon: Home | Investigate | View | Organize | Import|Export  |
+-----------+---------------------------------+-----------------+
| Entity    |                                 | Overview        |
| Palette   |          Graph Area             +-----------------+
|           |    (Main / Bubble / List)       | Detail View     |
| [search]  |                                 +-----------------+
| Personal  |                                 | Property View   |
| Infra...  |                                 |                 |
+-----------+---------------------------------+-----------------+
| Output / Transform Output / Run View                          |
+---------------------------------------------------------------+
```

### 6.2 หน้าที่ของแต่ละส่วน
**Entity Palette (ซ้าย)**

- รายการ Entity ทุกประเภท แบ่งเป็นหมวด เช่น Infrastructure, Personal, Locations, Groups
- มีช่องค้นหาด้านบน พิมพ์ `dom` จะเห็น Domain
- ลาก Entity ไปวางบน Graph เพื่อสร้าง

**Graph Area (กลาง)**

- พื้นที่ทำงานหลัก มีโหมดแสดงผลหลายแบบ เช่น
  - **Main View** — แสดง Entity และ Link ปกติ
  - **Bubble View** — ขนาดของ Entity ตามจำนวน Link (ใช้หา Node สำคัญ)
  - **Entity List** — แสดงเป็นตาราง เรียงลำดับและกรองได้

**Overview (ขวาบน)**

- แผนที่ย่อของ Graph ทั้งหมด ลากกรอบเพื่อเลื่อนไปส่วนที่ต้องการ

**Detail View (ขวา)**

- ข้อมูลของ Entity ที่เลือก เช่น Transform ใดสร้าง Entity นี้, Link ขาเข้า/ขาออก, Notes, Attachments

**Property View (ขวาล่าง)**

- Property ของ Entity เช่น ค่า `fqdn` ของ Domain, ค่า `ipv4-address` ของ IP
- แก้ไขค่าได้โดยตรง

**Output / Transform Output (ล่าง)**

- ข้อความจาก Transform: เริ่มทำงาน, จำนวนผลลัพธ์, Error
- ดูที่นี่ก่อนเสมอเมื่อ Transform ไม่คืนผล

**Run View / Machines**

- สถานะของ Machine ที่กำลังรัน

### 6.3 Ribbon Tab ที่ใช้บ่อย
| Tab | ใช้ทำอะไร (ตัวอย่าง) |
|---|---|
| Home | New Graph, Transform Hub, ตั้งค่าทั่วไป |
| Investigate | จำนวนผลลัพธ์ต่อ Transform, Find, Select by Type |
| View | Layout, Zoom, โหมดแสดงผล |
| Organize | Select Parents/Children/Neighbors, จัดกลุ่ม |
| Import \| Export | Import จากตาราง, Export ภาพ/ตาราง/Report, Config |
| Windows | เปิด/ปิดหน้าต่าง Palette, Detail, Property, Output |

### 6.4 Keyboard Shortcut พื้นฐาน
```
Ctrl+N      New Graph (ในบางเวอร์ชัน)
Ctrl+O      Open
Ctrl+S      Save
Ctrl+Z      Undo
Ctrl+Y      Redo
Ctrl+A      Select All
Ctrl+C      Copy Entity
Ctrl+V      Paste (วางข้อความ Maltego จะพยายามเดาประเภท Entity)
Delete      ลบ Entity ที่เลือก
Ctrl+F      ค้นหาใน Graph (ถ้ารองรับในเวอร์ชันของคุณ)
```

> **หมายเหตุ:** Shortcut บางตัวต่างกันตามเวอร์ชัน ดูได้จาก Tooltip เมื่อชี้เมาส์ค้างบนปุ่ม

### 6.5 จัด Workspace ให้เหมาะกับงาน
แนะนำการจัดหน้าจอสำหรับงาน Investigation:
1. ปิดหน้าต่างที่ไม่ใช้ เพื่อให้ Graph Area กว้างที่สุด
2. เปิด **Output** ไว้เสมอ (ดู Error ของ Transform)
3. เปิด **Detail View** ไว้เพื่อดูที่มาของ Entity
4. ถ้ามีจอสองจอ ลาก Entity List ไปอีกจอหนึ่ง

ถ้าหน้าต่างหายหรือเละ ให้ใช้คำสั่ง Reset Windows/Reset Layout ใน Tab **Windows** (ถ้ามีในเวอร์ชันของคุณ)

---
## 7. Entity

### 7.1 วิธีสร้าง Entity ทุกประเภท (ใช้ได้กับทุกหัวข้อย่อยด้านล่าง)
มี 4 วิธี:

**วิธีที่ 1 — ลากจาก Entity Palette**

1. พิมพ์ชื่อ Entity ในช่องค้นหาของ Entity Palette เช่น `Domain`
2. ลากไปวางบน Graph
3. ดับเบิลคลิกที่ข้อความใต้ไอคอน แล้วพิมพ์ค่า เช่น `example.com`
4. กด Enter

**วิธีที่ 2 — Paste ข้อความ**

1. Copy ข้อความ เช่น `203.0.113.10`
2. คลิกบนพื้นที่ว่างของ Graph แล้วกด `Ctrl+V`
3. Maltego จะพยายามเดาประเภท Entity ให้ (ถ้าเดาผิด ให้เปลี่ยนประเภทได้จากเมนูคลิกขวา — ชื่อเมนูขึ้นกับเวอร์ชัน)

**วิธีที่ 3 — Import จากตาราง CSV** ดูบท [การเพิ่ม Data Source](#43-การเพิ่ม-data-source)

**วิธีที่ 4 — ได้มาจากผลของ Transform** (วิธีที่ใช้บ่อยที่สุด)

### 7.2 Property, Notes, Bookmark และ Attachment
ทุก Entity มีส่วนประกอบเหล่านี้:
- **Value / Display value** — ค่าหลักที่แสดงใต้ไอคอน
- **Properties** — ค่าเพิ่มเติม ดูและแก้ได้ใน Property View
- **Notes** — บันทึกข้อความ (มีประโยชน์มากสำหรับจดที่มาของข้อมูล)
- **Bookmark** — ธงสีสำหรับจัดลำดับความสำคัญ
- **Attachments** — แนบไฟล์ เช่น Screenshot
- **Weight** — ค่าน้ำหนัก ที่ Transform บางตัวใส่มา ใช้เรียงลำดับได้

ตรวจ Entity type ID ทั้งหมดที่ติดตั้งในเครื่อง: เปิด **Entity Manager** (มักอยู่ใน Tab Home หรือ Entities ขึ้นกับเวอร์ชัน) จะเห็นชื่อ, ID เช่น `maltego.Domain`, และ Property ของแต่ละ Entity

### 7.3 Domain
- **ใช้ทำอะไร:** แทนชื่อโดเมนระดับที่จดทะเบียน เช่น `example.com` (ไม่ใช่ Host อย่าง `www.example.com` — ใช้ DNS Name แทน)
- **เพิ่มอย่างไร:** Palette → Infrastructure → Domain

**ใส่ข้อมูล:** ค่าหลักคือชื่อโดเมน ไม่ต้องใส่ `http://` หรือ `/`

```
ถูก:   example.com
ผิด:   https://example.com/
ผิด:   www.example.com   (อันนี้คือ DNS Name / Website)
```

**Transform ที่เกี่ยวข้อง (Standard Transforms):**

- `To DNS Name - MX (mail server)` — หา Mail server
- `To DNS Name - NS (name server)` — หา Name server
- `To DNS Name [Find common DNS names]` — ลองชื่อ Host ที่พบบ่อย เช่น www, mail
- `To Website [Quick lookup]` — หา Website ของ Domain
- `To Domain [Find other TLDs]` — หา Domain ชื่อเดียวกันใน TLD อื่น
- `To Entities from WHOIS [IBM Watson]` — ดึงข้อมูลจาก WHOIS (ถ้ายังมีในเวอร์ชันของคุณ)

**ตัวอย่าง:** Domain `example.com` → รัน `To DNS Name - NS (name server)`
- **อ่านผลลัพธ์:** จะได้ Entity ประเภท NS Record 1–หลายตัว แต่ละตัวคือ Name server ที่รับผิดชอบโซน
- **เชื่อมไปยัง:** DNS Name, MX Record, NS Record, Website, Email Address, Person/Organization (จาก WHOIS)

### 7.4 DNS Name
- **ใช้ทำอะไร:** ชื่อ Host แบบเต็ม (FQDN) เช่น `www.example.com`, `vpn.example.com`
- **เพิ่มอย่างไร:** Palette → Infrastructure → DNS Name
- **ใส่ข้อมูล:** FQDN ไม่มี Protocol และ Path

**Transform ที่เกี่ยวข้อง:**

- `To IP Address [DNS]` — Resolve เป็น IP (A record)
- Transform กลุ่ม "To Domain" — หา Domain แม่ของ Host
- Transform กลุ่ม Website — ตรวจว่า Host นี้เป็นเว็บไซต์หรือไม่

**ตัวอย่าง:** `mail.example.com` → `To IP Address [DNS]` → `203.0.113.25`
- **อ่านผลลัพธ์:** ถ้าได้ IP หลายตัว อาจเป็น Load balancer หรือ CDN ถ้าได้ 0 อาจเป็นชื่อที่ไม่มี A record (ตรวจด้วย `dig`)
- **เชื่อมไปยัง:** IP Address, Domain, Website

### 7.5 IP Address (IPv4)
- **ใช้ทำอะไร:** ที่อยู่ IPv4 หนึ่งตัว
- **เพิ่มอย่างไร:** Palette → Infrastructure → IPv4 Address หรือ Paste `203.0.113.10`

**Transform ที่เกี่ยวข้อง:**

- `To DNS Name [Reverse DNS]` — PTR record
- `To Netblock [Using natural boundaries]` — หาช่วง IP ที่ครอบ IP นี้
- `To AS number` — หา ASN ที่ประกาศเส้นทางของ IP
- `To Location [city, country]` — ตำแหน่งโดยประมาณ (GeoIP)
- Transform จาก Hub เช่น Threat Intel / Port data (ต้องติดตั้ง Provider และอาจต้องมี API Key)

**ตัวอย่าง:** `203.0.113.10` → `To AS number`
- **อ่านผลลัพธ์:** IP สำหรับเอกสารจะคืนผลว่างหรือไม่มีข้อมูล ถ้าทดสอบกับ IP จริงจะได้ AS Entity เช่น `AS<หมายเลข>`
- **เชื่อมไปยัง:** DNS Name, Netblock, AS, Location, Domain (reverse lookup จาก Passive DNS)

> **หมายเหตุ:** ผลลัพธ์ GeoIP คือ "ตำแหน่งโดยประมาณของผู้ให้บริการ" ไม่ใช่ตำแหน่งจริงของเครื่องหรือบุคคล

### 7.6 IPv6 Address
- **ใช้ทำอะไร:** ที่อยู่ IPv6 เช่น `2001:db8::10`
- **เพิ่มอย่างไร:** Palette → Infrastructure → IPv6 Address
- **ใส่ข้อมูล:** ใช้รูปแบบย่อมาตรฐาน `2001:db8::10` ได้
- **Transform ที่เกี่ยวข้อง:** ขึ้นกับ Provider — Standard Transforms บางรุ่นรองรับ IPv6 น้อยกว่า IPv4 ตรวจรายการ Transform ด้วยการคลิกขวาที่ Entity

**ตรวจเทียบด้วย Command:**

```bash
dig AAAA example.com +short
dig -x 2001:db8::10 +short
```

**เชื่อมไปยัง:** DNS Name (AAAA), Netblock, AS

### 7.7 AS (Autonomous System)
- **ใช้ทำอะไร:** แทนหมายเลข ASN เช่น `64496` ใช้ดูว่า IP อยู่ในเครือข่ายขององค์กรใด
- **เพิ่มอย่างไร:** Palette → Infrastructure → AS
- **ใส่ข้อมูล:** ใส่เฉพาะตัวเลข เช่น `64496` (บาง Transform รับ `AS64496` ได้ ขึ้นกับเวอร์ชัน)
- **Transform ที่เกี่ยวข้อง:** Transform กลุ่ม AS → Netblock / AS → Company (ชื่อขึ้นกับ Provider)
- **อ่านผลลัพธ์:** AS หนึ่งตัวอาจมี Netblock หลายร้อยช่วง (เช่น Cloud provider) ให้จำกัดจำนวนผลลัพธ์ก่อนรัน
- **เชื่อมไปยัง:** Netblock, IP Address, Organization

รายละเอียดเพิ่มเติมดูบท [ASN](#25-asn) และ [Autonomous System](#27-autonomous-system)

### 7.8 Netblock
- **ใช้ทำอะไร:** ช่วง IP เช่น `203.0.113.0/24` หรือ `203.0.113.0-203.0.113.255`
- **เพิ่มอย่างไร:** Palette → Infrastructure → Netblock

**Transform ที่เกี่ยวข้อง:**

- Transform ที่แตก Netblock เป็น IP (ระวังจำนวน — /24 = 256 IP)
- `To AS number`
- Transform ที่หา DNS Name ภายในช่วง (Reverse DNS ของทั้งช่วง ขึ้นกับ Provider)

**คำนวณขนาดช่วงก่อนรัน:**

```bash
sudo apt install -y ipcalc
ipcalc 203.0.113.0/24
```

**เชื่อมไปยัง:** IP Address, AS, Organization

### 7.9 Website
- **ใช้ทำอะไร:** แทนเว็บไซต์ (ระดับ Host ที่ให้บริการ HTTP/HTTPS) เช่น `www.example.com`
- **เพิ่มอย่างไร:** Palette → Infrastructure → Website

**Transform ที่เกี่ยวข้อง:**

- `To IP Address [DNS]`
- Transform กลุ่ม Server Technologies / Tracking codes / Links (ขึ้นกับ Provider ที่ติดตั้ง)

**เชื่อมไปยัง:** IP, Domain, URL, Tracking code, Email (ที่ปรากฏในหน้าเว็บ)

### 7.10 URL
- **ใช้ทำอะไร:** ที่อยู่เต็มของหน้าเว็บหรือไฟล์ เช่น `https://www.example.com/login?next=/`
- **Property สำคัญ:** URL เต็ม, Title (ถ้ามี)

**Transform ที่เกี่ยวข้อง:**

- Transform ที่แยก URL เป็น Website / Domain
- Transform จาก Threat Intel Provider เช่น การตรวจชื่อเสียงของ URL (ต้องมี API Key)

**เชื่อมไปยัง:** Website, Domain, IP, Hash (ไฟล์ที่ดาวน์โหลดจาก URL)

> **หมายเหตุ:** อย่าเปิด URL ที่สงสัยว่าเป็นอันตรายด้วย Browser บนเครื่องหลัก ดูบท [Malware-related OSINT](#30-malware-related-osint)

### 7.11 Email Address
- **ใช้ทำอะไร:** ที่อยู่อีเมล เช่น `alice@example.com`
- **เพิ่มอย่างไร:** Palette → Personal → Email Address หรือ Paste

**Transform ที่เกี่ยวข้อง:**

- Transform ที่แยก Domain จาก Email (ค้นคำว่า `Domain` ในเมนู Transform ของ Email)
- Transform ที่หา Person / Alias ที่เกี่ยวข้อง (ขึ้นกับ Provider)
- Transform ตรวจการรั่วไหลจาก Provider แบบ Breach (ต้องมี API Key)

**อ่านผลลัพธ์:** Email → Domain เป็นผลแน่นอน (ส่วนหลัง @) ส่วน Email → Person เป็นผลแบบ "อาจเกี่ยวข้อง" ต้องยืนยันจากแหล่งอื่น
- **เชื่อมไปยัง:** Domain, Person, Alias, Phone Number, Website

### 7.12 Person
- **ใช้ทำอะไร:** แทนบุคคล ค่าหลักคือชื่อ-นามสกุล
- **ใส่ข้อมูล:** ใช้ชื่อเต็มตามที่พบในแหล่งข้อมูล เช่น `Alice Example` (ค่าสมมติ)
- **Transform ที่เกี่ยวข้อง:** Transform หา Email/Alias/Social profile (ส่วนใหญ่ต้องใช้ Provider เฉพาะทาง และอาจต้องมี License เพิ่ม)
- **อ่านผลลัพธ์:** ชื่อบุคคลซ้ำกันได้มาก ห้ามสรุปว่าเป็นคนเดียวกันจากชื่ออย่างเดียว
- **เชื่อมไปยัง:** Email, Phone, Alias, Organization, Location

### 7.13 Organization
- **ใช้ทำอะไร:** แทนบริษัท/หน่วยงาน เช่น `Example Corp` (ค่าสมมติ)
- **Transform ที่เกี่ยวข้อง:** Transform หา Domain/Website ขององค์กร, Transform จาก Provider ข้อมูลบริษัท (ขึ้นกับที่ติดตั้ง)
- **เชื่อมไปยัง:** Domain, AS, Netblock, Person, Location, Document

### 7.14 Phone Number
- **ใช้ทำอะไร:** เบอร์โทรศัพท์
- **ใส่ข้อมูล:** แนะนำรูปแบบสากล E.164 เช่น `+66 2 000 0000` (ค่าสมมติ) Property มักแยก country code, area code
- **Transform ที่เกี่ยวข้อง:** ขึ้นกับ Provider (Standard Transforms มีจำกัด)
- **เชื่อมไปยัง:** Person, Organization, Location

### 7.15 Alias
- **ใช้ทำอะไร:** ชื่อเล่นหรือชื่อแฝงที่คนใช้บนอินเทอร์เน็ต เช่น `alice_example`
- **ต่างจาก Username อย่างไร:** Alias คือ "ชื่อที่คนใช้" แบบทั่วไป ส่วน Username/Affiliation มักผูกกับบริการเฉพาะ (เช่น บัญชีบนแพลตฟอร์มหนึ่ง) ประเภท Entity ของบัญชี Social อาจชื่อต่างกันตาม Provider
- **เชื่อมไปยัง:** Username/Social account, Person, Email

### 7.16 Username
- **ใช้ทำอะไร:** ชื่อบัญชีบนบริการใดบริการหนึ่ง
- **เพิ่มอย่างไร:** ค้นใน Palette ด้วยคำว่า `user`, `alias` หรือ `affiliation` (Entity ที่ใช้แทนบัญชี Social อยู่ในหมวด Social Network ในหลายเวอร์ชัน)
- **Transform ที่เกี่ยวข้อง:** Transform จาก Provider ด้าน Social Media (มักต้องมี License / API Key)
- **ตัวเสริมนอก Maltego:** `sherlock` บน Kali ใช้ตรวจว่าชื่อผู้ใช้มีอยู่บนเว็บไซต์ใดบ้าง แล้วนำผลมา Import เข้า Maltego ได้ ดูบท [Username Investigation](#20-username-investigation)

### 7.17 Location
- **ใช้ทำอะไร:** ตำแหน่ง เช่น ประเทศ/เมือง หรือพิกัด
- **ใส่ข้อมูล:** ชื่อสถานที่ หรือ Property Latitude/Longitude
- **Transform ที่เกี่ยวข้อง:** IP → Location (GeoIP), Location → แผนที่ (บางเวอร์ชันเปิดใน Browser)
- **อ่านผลลัพธ์:** ตำแหน่งจาก GeoIP มักเป็นระดับเมืองหรือประเทศ และอาจผิด

### 7.18 Document
- **ใช้ทำอะไร:** แทนไฟล์เอกสาร เช่น PDF, DOCX ที่พบบนเว็บไซต์
- **Property สำคัญ:** URL ของเอกสาร, Title, Metadata (ถ้า Transform ดึงมา)

**ใช้คู่กับ Command:**

```bash
exiftool report.pdf
pdfinfo report.pdf
```

**เชื่อมไปยัง:** Person (ผู้เขียนใน Metadata), Organization, Website, Phrase (ชื่อโปรแกรมที่สร้างไฟล์)

ดูบท [Metadata Investigation](#34-metadata-investigation)

### 7.19 Hash
**ใช้ทำอะไร:** ค่า Hash ของไฟล์ (MD5, SHA1, SHA256) ใช้เป็น IOC

**ใส่ข้อมูล:** ค่า Hash ตัวพิมพ์เล็ก เช่น SHA256 ของไฟล์ทดสอบ EICAR:

```
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

**Transform ที่เกี่ยวข้อง:** Transform จาก Threat Intel Provider (เช่น การค้นรายงานไฟล์, Domain/IP ที่เกี่ยวข้อง) ต้องติดตั้งจาก Transform Hub และมักต้องมี API Key

**คำนวณ Hash บน Kali:**

```bash
sha256sum sample.bin
md5sum sample.bin
sha1sum sample.bin
```

### 7.20 Cryptocurrency Address
- **ใช้ทำอะไร:** ที่อยู่กระเป๋าเงินดิจิทัล
- **เพิ่มอย่างไร:** ค้นใน Palette ด้วยคำว่า `crypto` หรือ `bitcoin` (Entity กลุ่มนี้มาจาก Provider ที่ติดตั้ง ชื่อจึงต่างกันได้)
- **ใส่ข้อมูล:** ในคู่มือใช้ `<WALLET_ADDRESS>` แทนที่อยู่จริงเสมอ
- **Transform ที่เกี่ยวข้อง:** Transform ด้าน Blockchain จาก Provider เฉพาะทาง (มักต้องมี License)

ดูบท [Cryptocurrency OSINT](#32-cryptocurrency-osint)

### 7.21 Certificate
- **ใช้ทำอะไร:** แทน SSL/TLS Certificate มี Property เช่น Subject, Issuer, Serial, Fingerprint, วันหมดอายุ
- **เพิ่มอย่างไร:** ค้นใน Palette ด้วยคำว่า `cert` (มีในเวอร์ชัน/Provider ที่รองรับ)
- **Transform ที่เกี่ยวข้อง:** Transform จาก Provider ด้าน Certificate Transparency หรือ Internet scan data (ขึ้นกับที่ติดตั้ง)

**ตรวจด้วย Command:**

```bash
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256
```

ดูบท [Certificate / SSL](#18-certificate--ssl)

---

## 8. Transform

บทนี้คือหัวใจของคู่มือ

### 8.1 Transform คืออะไรในเชิงใช้งาน
```
[Input Entity] --(Transform)--> [Data Source] --> [Output Entities + Links]
```

- รับ Entity หนึ่งตัว (หรือหลายตัวที่เลือกพร้อมกัน)
- ส่งคำถามไปยัง Data Source (DNS server, WHOIS, API ของ Provider ฯลฯ)
- คืน Entity ใหม่ พร้อม Link จาก Input → Output
- Transform บางตัวรันบน Server ของ Provider (Remote Transform) บางตัวรันบนเครื่องเรา (Local Transform)

### 8.2 วิธี Run Transform
#### ขั้นตอน
1. คลิกขวาที่ Entity (หรือเลือกหลาย Entity แล้วคลิกขวา)
2. เมนู Transform จะแสดงรายการตามหมวด/Provider
3. เลือก Transform ที่ต้องการ หรือพิมพ์คำค้นในช่องค้นหาของเมนู
4. คลิกชื่อ Transform (หรือปุ่ม Run ข้างชื่อ)
5. ดูความคืบหน้าใน **Output**

ตัวเลือกที่พบบ่อยในเมนู:
- รัน Transform เดี่ยว
- รันทุก Transform ในหมวด/Set (ระวัง: ผลลัพธ์เยอะมาก)
- รันพร้อมตั้งค่า (Transform ที่มี Input parameter จะถามค่าก่อนรัน)

#### ตัวอย่าง
```
Entity : example.com (Domain)
Run    : To DNS Name - MX (mail server)
```

#### ผลลัพธ์
- Graph มี MX Record ใหม่เชื่อมจาก `example.com`
- Output แสดงข้อความประมาณว่า Transform เริ่ม, เสร็จ และคืนผลกี่ Entity

> **หมายเหตุ:** `example.com` อาจไม่มี MX ที่ใช้งานจริง ถ้าได้ 0 ผลลัพธ์ให้ตรวจเทียบด้วย `dig MX example.com`

### 8.3 จำนวนผลลัพธ์ต่อ Transform
Maltego มีตัวตั้งค่าจำนวนผลลัพธ์สูงสุดต่อการรันหนึ่งครั้ง (มักอยู่ใน Tab Investigate)
- เริ่มจากค่าน้อยก่อนเสมอ
- เพิ่มค่าเมื่อแน่ใจว่าต้องการข้อมูลครบ
- Edition ฟรีมีเพดานต่ำกว่ารุ่นเสียเงิน (ตรวจเงื่อนไขปัจจุบัน)

### 8.4 Transform ส่งผลลัพธ์แบบใด
| แบบ | ตัวอย่าง | ความน่าเชื่อถือ |
|---|---|---|
| ข้อเท็จจริงทางเทคนิค | Domain → NS record | สูง (ตรวจซ้ำได้ด้วย dig) |
| ข้อมูลจากฐานข้อมูลภายนอก | IP → AS, IP → Location | กลาง–สูง (ขึ้นกับความสดของข้อมูล) |
| ข้อมูลเชิงประวัติ | Passive DNS, Certificate history | กลาง (อาจเก่าแล้ว) |
| การจับคู่/เดา | Email → Person, Person → Alias | ต่ำ–กลาง (ต้องยืนยัน) |

นอกจาก Entity แล้ว Transform อาจใส่ข้อมูลใน:
- **Property** ของ Entity ใหม่
- **Link label** (เช่น ชนิด Record)
- **Display information** ใน Detail View (ข้อความ/ลิงก์อ้างอิง)

### 8.5 Transform Chain
Transform Chain = การใช้ผลลัพธ์ของ Transform หนึ่งเป็น Input ของ Transform ถัดไป

```
Domain
  → (To DNS Name - NS)            → NS Record
  → (To DNS Name - MX)            → MX Record
  → (To DNS Name [Find common DNS names]) → DNS Name
        → (To IP Address [DNS])   → IP Address
              → (To Netblock)     → Netblock
              → (To AS number)    → AS
```

อีกตัวอย่าง:

```
Email
  → Domain
  → Username / Alias
  → Website
  → Social Profile
```

> **หมายเหตุ:** ผลลัพธ์จริงของ Chain ขึ้นอยู่กับ Data Source และ Transform ที่ติดตั้งอยู่ เส้นทางบางช่วง (เช่น Email → Username) ต้องใช้ Provider เฉพาะ ซึ่ง Standard Transforms อาจไม่มี

### 8.6 วิธีรัน Chain บน Entity หลายตัวพร้อมกัน
1. รัน Transform แรก
2. เลือก Entity ผลลัพธ์ทั้งหมดของประเภทเดียวกัน
   - ใช้ **Select by Type** (Tab Investigate/Organize ขึ้นกับเวอร์ชัน) หรือ
   - คลิก Entity ต้นทาง แล้วใช้ **Select Children**
3. คลิกขวาที่ Entity ใดก็ได้ในกลุ่มที่เลือก → รัน Transform ถัดไป
4. Transform จะรันกับทุก Entity ที่เลือก

### 8.7 วิธีเลือก Transform ให้เหมาะกับ Investigation
ถามตัวเอง 3 ข้อ:
1. **คำถามที่ต้องการตอบคืออะไร** เช่น "เว็บนี้ Host อยู่ที่ไหน" → Domain → DNS Name → IP → AS
2. **Transform นี้แตะเป้าหมายโดยตรงหรือไม่** เช่น DNS lookup ไปถาม DNS server ของเป้าหมาย ส่วน Passive DNS ถามฐานข้อมูลของ Provider
3. **คุ้มกับ Quota หรือไม่** Transform ที่ใช้ API แบบจำกัด Quota ควรใช้กับ Entity ที่คัดแล้วเท่านั้น

ลำดับที่แนะนำ:

```
1. Transform ฟรี/ข้อเท็จจริง (DNS, WHOIS)
2. Transform เชิงประวัติ (Passive DNS, Certificate)
3. Transform ที่ใช้ Quota (Threat Intel, Breach)
4. Transform แบบจับคู่บุคคล (ใช้เมื่อจำเป็นและอยู่ในขอบเขต)
```

### 8.8 วิธีหยุดเมื่อข้อมูลเริ่มมากเกินไป
สัญญาณว่าควรหยุด:
- Entity ใน Graph เกินหลักพันและยังเพิ่มขึ้น
- ผลลัพธ์เริ่มเป็นของ Shared hosting / CDN (IP เดียวมีหลายพัน Domain)
- ผลลัพธ์ไม่เกี่ยวกับคำถามตั้งต้น

วิธีหยุดและจัดการ:
1. หยุด Transform ที่กำลังรัน (ปุ่ม Stop ในหน้าต่าง Output/Run View)
2. `Ctrl+Z` ย้อนผลลัพธ์ล่าสุด ถ้าเพิ่งรันและผลไม่เกี่ยวข้อง
3. ลบ Entity ปลายทางที่ไม่มีประโยชน์ (ใช้ Machine `Prune Leaf Entities` ถ้ามีในเวอร์ชันของคุณ หรือเลือกแล้วกด Delete)
4. บันทึก Graph เป็นไฟล์ใหม่ก่อนขยายต่อ (`Save As`)
5. ย้ายส่วนที่สนใจไปยัง Graph ใหม่ (Copy/Paste Entity)

### 8.9 จัด Graph หลังรัน Transform
- เปลี่ยน Layout เป็น **Hierarchical** เมื่อต้องการดูลำดับชั้น (Domain → Host → IP)
- ใช้ **Organic** เมื่อต้องการดูกลุ่มก้อน (Cluster)
- ใช้ **Block** เมื่อต้องการเรียงแบบตาราง
- เปิด Bubble View เพื่อหา Entity ที่มี Link มาก

รายละเอียดดูบท [Graph Analysis](#36-graph-analysis)

### 8.10 ดูที่มาของผลลัพธ์
คลิก Entity → ดู **Detail View**:
- Transform ใดสร้าง Entity นี้
- Entity ต้นทาง (Incoming links)
- Display information จาก Provider

คลิกที่ **Link** → ดู Property ของ Link เช่น ชื่อ Transform ที่สร้าง

### 8.11 Transform Manager
Transform Manager ใช้ดู/ตั้งค่า Transform ทั้งหมดที่ติดตั้ง (มักเข้าจาก Tab Transforms หรือ Home ขึ้นกับเวอร์ชัน)

สิ่งที่ทำได้:
- ดูชื่อ, ID, Input Entity, Provider (Seed) ของแต่ละ Transform
- เปิด/ปิด Transform
- ตั้งค่า Transform settings เช่น API Key, Timeout
- จัด Transform Sets (กลุ่ม Transform ที่ใช้ร่วมกัน)

### 8.12 Transform Sets
Transform Set คือกลุ่มของ Transform ที่ตั้งชื่อเอง ใช้เพื่อให้เมนูคลิกขวาสั้นลง

ตัวอย่าง Set ที่แนะนำให้สร้าง:

```
SET: Infra-Basic
  - To DNS Name - MX (mail server)
  - To DNS Name - NS (name server)
  - To IP Address [DNS]
  - To Netblock [Using natural boundaries]
  - To AS number
```

ขั้นตอน:
1. เปิด Transform Manager
2. ไปที่ส่วน Transform Sets
3. สร้าง Set ใหม่ ตั้งชื่อ `Infra-Basic`
4. ลาก Transform ที่ต้องการเข้า Set
5. กลับไปที่ Graph คลิกขวาที่ Entity จะเห็น Set นี้ในเมนู

---
## 9. Transform Hub

Transform Hub คือหน้าที่ใช้ติดตั้ง Transform จาก Provider ต่าง ๆ (ทั้งของ Maltego และบริษัทภายนอก)

> **หมายเหตุ:** รายการ Provider ใน Transform Hub เปลี่ยนตลอด บาง Provider ถูกถอดออก บางรายเปลี่ยนเงื่อนไขเป็นแบบเสียเงิน ตัวอย่าง Provider ที่เคยปรากฏใน Hub เช่น Shodan, VirusTotal, AlienVault OTX, SecurityTrails, Censys, Have I Been Pwned ให้ตรวจสอบรายการจริงในโปรแกรมของคุณ

### 9.1 เปิด Transform Hub
1. ไปที่ Tab **Home**
2. คลิก **Transform Hub** (หรือเห็นเป็นหน้าแรกเมื่อเปิดโปรแกรม)
3. จะเห็น Tile ของแต่ละ Provider

แต่ละ Tile มักแสดง:
- ชื่อ Provider
- สถานะ: ติดตั้งแล้ว / ยังไม่ติดตั้ง
- ข้อความบอกว่าต้องใช้ API Key / ต้องมี Subscription หรือไม่
- ปุ่ม Install / Uninstall / Settings / Details

### 9.2 ค้นหา Provider
- ใช้ช่องค้นหาบนหน้า Hub พิมพ์คำ เช่น `dns`, `threat`, `whois`
- ใช้ตัวกรอง (ถ้ามี) เช่น Free / Paid / Installed
- คลิก Tile เพื่ออ่านรายละเอียด: Transform ที่ได้, Entity ที่เพิ่ม, เงื่อนไขการใช้งาน

### 9.3 ติดตั้ง Transform
#### ขั้นตอน
1. คลิก Tile ของ Provider
2. อ่านรายละเอียด และเงื่อนไข (Terms)
3. คลิก **Install**
4. ถ้า Provider ต้องใช้ API Key หน้าต่างจะถามค่า ใส่ `YOUR_API_KEY` ของคุณ (ขั้นตอนสมัคร Account กับ Provider ผู้ใช้ต้องทำเอง)
5. รอจนสถานะเปลี่ยนเป็น Installed

#### ผลลัพธ์
- เมนูคลิกขวาของ Entity จะมีหมวดใหม่ชื่อ Provider นั้น
- Entity Palette อาจมี Entity ประเภทใหม่ (ถ้า Provider เพิ่ม Entity)

### 9.4 ตรวจสอบสิทธิ์ (Permissions)
ก่อนรัน Transform จาก Provider ใหม่ ให้ตรวจ:
- Account ของ Maltego มีสิทธิ์ใช้ Provider นี้หรือไม่ (บาง Provider ต้องมี Edition ที่สูงกว่า)
- API Key มีสิทธิ์ใช้ Endpoint ที่ Transform เรียกหรือไม่ (บาง Endpoint ต้องเป็น Plan เสียเงิน)
- Terms of Service ของ Provider อนุญาตการใช้งานแบบที่คุณกำลังทำหรือไม่

### 9.5 ตั้งค่า API Key หลังติดตั้ง
วิธีที่ 1 — จาก Transform Hub:
1. คลิก Tile ของ Provider ที่ติดตั้งแล้ว
2. คลิก **Settings**
3. ใส่ API Key ในช่องที่กำหนด
4. คลิก OK

วิธีที่ 2 — จาก Transform Manager:
1. เปิด Transform Manager
2. เลือก Transform ของ Provider
3. ดูส่วน Transform Settings / Properties
4. ใส่ API Key และเลือกว่าจะให้ใช้กับทุก Transform ของ Provider (Global) หรือไม่ (ขึ้นกับเวอร์ชัน)

รูปแบบค่าในคู่มือ:

```
API_KEY=YOUR_API_KEY
```

ห้ามใส่ API Key จริงลงใน Screenshot, Report หรือ Git repository

### 9.6 ทดสอบ Transform ที่เพิ่งติดตั้ง
1. สร้าง Graph ใหม่ชื่อ `hub-test.mtgl`
2. เพิ่ม Entity ที่ Provider รองรับ (ดูจาก Tile ว่า Input คืออะไร) ใช้ค่าที่คุณมีสิทธิ์ เช่น Domain ของตัวเอง
3. คลิกขวา → เลือกหมวดของ Provider → รัน Transform ที่ง่ายที่สุด 1 ตัว
4. ดู Output

ผลลัพธ์ที่ควรเห็น:
- มี Entity ใหม่ หรือ
- ข้อความแจ้งว่าไม่พบข้อมูล (ยังถือว่า Transform ทำงาน) หรือ
- ข้อความ Error (ไปข้อ 9.7)

### 9.7 ตรวจสอบ Error
| ข้อความที่พบ (ประมาณ) | ความหมายที่เป็นไปได้ |
|---|---|
| Unauthorized / Invalid API key / 401 | Key ผิด หมดอายุ หรือไม่ได้ใส่ |
| Forbidden / 403 | Key ถูก แต่ Plan ไม่มีสิทธิ์ Endpoint นี้ |
| Too many requests / 429 | ติด Rate limit |
| Quota exceeded | ใช้โควตาหมดตามรอบ |
| Timeout | Provider ช้า หรือ Network มีปัญหา |
| Transform server unavailable | Server ของ Provider ล่ม หรือถูกปิด |

ดูรายละเอียดวิธีแก้ในบท [Troubleshooting](#49-troubleshooting)

### 9.8 ถอน Transform
1. เปิด Transform Hub
2. คลิก Tile ของ Provider
3. คลิก **Uninstall**
4. ยืนยัน

ผลลัพธ์: หมวด Transform ของ Provider หายจากเมนู Entity ที่อยู่ใน Graph เดิมยังอยู่ แต่รัน Transform ของ Provider นั้นต่อไม่ได้

### 9.9 Transform Seed
Seed คือ URL ที่บอก Maltego ว่าจะไปดึงรายการ Transform จาก Server ใด Provider ในองค์กร (เช่น Transform server ภายในทีม) อาจให้ Seed URL มา

ขั้นตอนทั่วไป:
1. ในหน้า Transform Hub หาเมนูสำหรับเพิ่ม Transform Seed / Add Server (ชื่อขึ้นกับเวอร์ชัน)
2. ใส่ชื่อและ Seed URL ที่ได้รับจากผู้ดูแลระบบ
3. ติดตั้งเหมือน Provider ทั่วไป

> **หมายเหตุ:** เพิ่ม Seed จากแหล่งที่เชื่อถือได้เท่านั้น Transform server ได้รับค่าของ Entity ทุกตัวที่คุณรัน Transform ใส่

---

## 10. Machine

บทนี้แนะนำภาพรวม วิธีสร้าง Machine แบบละเอียดอยู่ในบท [Maltego Machines](#40-maltego-machines)

### 10.1 Machine คืออะไร
Machine = ลำดับ Transform ที่รันต่อกันอัตโนมัติจาก Entity เริ่มต้นหนึ่งตัว

```
[Domain] → Transform A → Transform B → Transform C → Graph ที่ขยายแล้ว
```

### 10.2 Run Machine แบบเร็ว
1. คลิกขวาที่ Entity (เช่น Domain `example.com`)
2. เลือกเมนู Run Machine / Machines (หรือใช้ Tab Machines บน Ribbon ถ้ามี)
3. เลือก Machine เช่น `Footprint L1`
4. ดูความคืบหน้าใน Run View
5. กด Stop ได้ตลอดเวลา

> **หมายเหตุ:** Machine ที่มากับโปรแกรม (เช่น `Footprint L1`, `Footprint L2`, `Footprint L3`, `Company Stalker`, `URL To Network And Domain Information`, `Prune Leaf Entities`) อาจมีหรือไม่มีขึ้นกับเวอร์ชัน ให้ดูรายการในเครื่องของคุณ

### 10.3 Machine แต่ละระดับต่างกันอย่างไร
- Machine ระดับเบา (เช่น Footprint L1) รันเร็ว ผลลัพธ์น้อย เหมาะเริ่มต้น
- Machine ระดับลึก (เช่น L2, L3) รันนาน ผลลัพธ์มาก และอาจมีขั้นตอนให้ผู้ใช้เลือกกรองผลระหว่างทาง

เริ่มจากระดับเบาเสมอ แล้วค่อยขยายเฉพาะส่วนที่สนใจ

---

## 11. Data Sources

### 11.1 Data Source มาจากไหน
| ประเภท | ตัวอย่าง | แตะเป้าหมายโดยตรงหรือไม่ |
|---|---|---|
| DNS แบบ Live | A, MX, NS, TXT query | ใช่ (ถาม DNS server ที่รับผิดชอบโซน) |
| WHOIS / RDAP | ข้อมูลการจดทะเบียน | ไม่ (ถาม Registry/Registrar) |
| Passive DNS | ประวัติการ Resolve | ไม่ |
| Certificate Transparency | Log ของ Certificate | ไม่ |
| Internet scan data | Port/Banner ที่ Provider สแกนไว้ | ไม่ (ข้อมูลของ Provider) |
| Threat Intel | IOC, Reputation | ไม่ |
| Website | อ่านหน้าเว็บของเป้าหมาย | ใช่ |
| Social/Public records | Profile สาธารณะ | ขึ้นกับวิธี |

### 11.2 ทำไมต้องรู้ว่า Data Source คืออะไร
1. **ความถูกต้อง** — Passive DNS อาจเป็นข้อมูลเก่า ต้องดูวันที่
2. **Footprint** — Transform ที่แตะเป้าหมายจะทิ้งร่องรอยใน Log ของเป้าหมาย
3. **กฎหมาย/Terms** — แต่ละ Provider มีเงื่อนไขการใช้งานต่างกัน
4. **การอ้างอิงใน Report** — ต้องระบุแหล่งที่มาของข้อมูลได้

### 11.3 วิธีดูว่า Transform ใช้ Data Source อะไร
- อ่านคำอธิบายของ Transform ใน Transform Manager
- อ่านหน้ารายละเอียดของ Provider ใน Transform Hub
- ดู Display information ใน Detail View ของ Entity ผลลัพธ์

### 11.4 ตรวจซ้ำด้วยเครื่องมือบน Kali
ทุกข้อเท็จจริงสำคัญควรตรวจซ้ำด้วยเครื่องมืออีกตัว:

```bash
# ผล Maltego: example.com มี NS เป็น X
dig NS example.com +short

# ผล Maltego: www.example.com → IP
dig A www.example.com +short

# ผล Maltego: WHOIS
whois example.com | less
```

> **หมายเหตุ:** `dig`, `whois`, `curl` เป็นเครื่องมือเสริมบน Kali ไม่ใช่ส่วนหนึ่งของ Maltego ใช้เพื่อยืนยันผลเท่านั้น

---

## 12. API และ Credentials

### 12.1 API Key คืออะไร
API Key คือรหัสที่ Provider ออกให้ เพื่อระบุว่าคำขอมาจาก Account ใด ใช้สำหรับ:
- ยืนยันตัวตน (Authentication)
- นับโควตา (Quota)
- จำกัดความถี่ (Rate limit)
- กำหนดสิทธิ์ (Plan ฟรี / เสียเงิน)

### 12.2 ใส่ API Key ตรงไหน
| ที่ใช้ | ตำแหน่ง |
|---|---|
| Transform จาก Hub | Transform Hub → Provider → Settings |
| Transform รายตัว | Transform Manager → Transform Settings |
| Local Transform ที่เขียนเอง | Environment variable หรือไฟล์ Config บน Kali |
| ทดสอบด้วย curl | Environment variable ใน Terminal |

### 12.3 เก็บ API Key บน Kali อย่างปลอดภัย
```bash
mkdir -p ~/.config/osint
chmod 700 ~/.config/osint
cat > ~/.config/osint/keys.env << 'EOF'
VT_API_KEY=YOUR_API_KEY
SHODAN_API_KEY=YOUR_API_KEY
OTX_API_KEY=YOUR_API_KEY
EOF
chmod 600 ~/.config/osint/keys.env
ls -l ~/.config/osint/keys.env
```

ผลลัพธ์ที่ควรเห็น:

```
-rw------- 1 kali kali 90 ... /home/kali/.config/osint/keys.env
```

โหลดเข้า Shell เมื่อต้องการใช้:

```bash
set -a; source ~/.config/osint/keys.env; set +a
echo ${VT_API_KEY:0:4}****
```

- `set -a` ทำให้ตัวแปรที่ source มาถูก export อัตโนมัติ
- แสดงเฉพาะ 4 ตัวแรกเพื่อยืนยันว่าโหลดแล้ว โดยไม่พิมพ์ Key เต็มลงจอ

ป้องกันไม่ให้ Key หลุดเข้า Git:

```bash
echo "keys.env" >> ~/.gitignore_global
git config --global core.excludesfile ~/.gitignore_global
```

### 12.4 ตรวจสอบว่า API Key ใช้งานได้
ทดสอบนอก Maltego ก่อน ถ้า curl ใช้ได้แต่ Maltego ใช้ไม่ได้ ปัญหาอยู่ที่การตั้งค่าใน Maltego

ตัวอย่าง (Endpoint อาจเปลี่ยน ให้ดูเอกสาร API ของแต่ละ Provider):

```bash
# VirusTotal API v3
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "x-apikey: $VT_API_KEY" \
  https://www.virustotal.com/api/v3/domains/example.com

# Shodan: ข้อมูล Account/Plan
curl -s "https://api.shodan.io/api-info?key=$SHODAN_API_KEY" | jq .

# AlienVault OTX
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "X-OTX-API-KEY: $OTX_API_KEY" \
  https://otx.alienvault.com/api/v1/indicators/domain/example.com/general
```

การอ่าน HTTP status code:

```
200  ใช้งานได้
401  Key ผิด / ไม่ได้ส่ง Key
403  Key ถูกแต่ไม่มีสิทธิ์
404  ไม่พบข้อมูล (Key อาจถูกต้อง)
429  เกิน Rate limit
5xx  ฝั่ง Provider มีปัญหา
```

### 12.5 Rate Limit และ Quota
- **Rate limit** — จำนวนคำขอต่อช่วงเวลาสั้น ๆ (ต่อวินาที/ต่อนาที) เกินแล้วจะได้ 429 รอแล้วลองใหม่ได้
- **Quota** — จำนวนคำขอรวมต่อวัน/เดือน หมดแล้วต้องรอรอบใหม่หรืออัปเกรด Plan

ผลต่อการใช้ Maltego:
- รัน Transform กับ 200 Entity พร้อมกัน = 200 คำขอ อาจใช้ Quota รายวันหมดในครั้งเดียว
- Transform บางตัวคืนผลไม่ครบโดยไม่แจ้ง Error ชัดเจนเมื่อติด Limit

แนวทาง:
1. คัด Entity ก่อนรัน Transform ที่ใช้ Quota
2. รันทีละกลุ่มเล็ก ๆ
3. จด Quota ที่ใช้ไปในไฟล์ Notes ของ Case
4. ตรวจ Quota คงเหลือจากหน้า Dashboard ของ Provider

ดูอาการและวิธีแก้ปัญหา API แบบละเอียดในบท [Troubleshooting](#49-troubleshooting)

---

## 13. การค้นหา Domain

### 13.1 Workflow: Domain Footprint พื้นฐาน
#### เป้าหมาย
รู้ว่า Domain หนึ่งมี Name server, Mail server, Host หลัก และ IP อะไรบ้าง

#### ขั้นตอน
1. เปิด Maltego
2. สร้าง Graph `01-domain-recon.mtgl`
3. เพิ่ม Entity **Domain** ค่า `example.com`
4. เลือก Transform:
   - `To DNS Name - NS (name server)`
   - `To DNS Name - MX (mail server)`
   - `To DNS Name [Find common DNS names]`
   - `To Website [Quick lookup]`
5. Run Transform ทีละตัว (หรือใส่ใน Transform Set `Infra-Basic` แล้วรันทั้ง Set)
6. เลือก NS, MX, DNS Name, Website ทั้งหมด → รัน `To IP Address [DNS]`
7. วิเคราะห์ผลลัพธ์

#### ตัวอย่าง
```
Input: example.com
```

#### ผลลัพธ์
```
example.com
    |
    +-- [NS]  ns1.example.net
    +-- [NS]  ns2.example.net
    +-- [MX]  mail.example.com ---- 203.0.113.25
    +-- [DNS] www.example.com  ---- 203.0.113.10
    +-- [Web] www.example.com
```

(ค่าข้างบนเป็นผลลัพธ์สมมติเพื่อแสดงโครงสร้าง ผลจริงของ `example.com` จะต่างออกไป)

#### หมายเหตุ
- Transform กลุ่มนี้ส่วนใหญ่ใช้ DNS แบบ Live จึงแตะ DNS server ของเป้าหมาย
- ไม่ต้องใช้ API Key สำหรับ Standard Transforms แต่ต้อง Login Maltego

### 13.2 ตรวจเทียบด้วย Command
```bash
D=example.com
for t in NS MX A AAAA TXT SOA; do
  echo "== $t =="
  dig +short $t $D
done | tee ~/cases/$CASE/raw/dns-$D.txt
```

`tee` แสดงผลบนจอและบันทึกลงไฟล์ในโฟลเดอร์ `raw` ของ Case พร้อมกัน

### 13.3 หา Domain ที่เกี่ยวข้อง
#### เป้าหมาย
หา Domain อื่นที่อาจเป็นขององค์กรเดียวกัน

#### ขั้นตอน
1. เลือก Domain `example.com`
2. รัน `To Domain [Find other TLDs]`
3. ตรวจ Domain ที่ได้ทีละตัว: WHOIS, NS, MX ตรงกับ Domain หลักหรือไม่

#### ผลลัพธ์
```
example.com
    +-- example.net
    +-- example.org
```

#### หมายเหตุ
Domain ที่ชื่อเหมือนกันแต่ต่าง TLD ไม่ได้แปลว่าเป็นเจ้าของเดียวกัน ต้องมีหลักฐานอย่างน้อยหนึ่งอย่าง เช่น NS เดียวกัน, WHOIS Organization เดียวกัน, Certificate เดียวกัน

### 13.4 Pivot ที่ใช้ยืนยันความเป็นเจ้าของเดียวกัน
```
Domain A ─┐
          ├── NS เดียวกัน (อ่อน ถ้าเป็น NS ของผู้ให้บริการรายใหญ่)
Domain B ─┘

Domain A ─┐
          ├── WHOIS Organization เดียวกัน (กลาง)
Domain B ─┘

Domain A ─┐
          ├── Certificate ใบเดียวกัน (SAN รวมทั้งสอง) (แข็ง)
Domain B ─┘
```

---

## 14. การค้นหา IP

### 14.1 Workflow: IP Context
#### เป้าหมาย
รู้ว่า IP หนึ่งอยู่ในเครือข่ายใด เป็นของใคร และมีชื่อ Host อะไรชี้มา

#### ขั้นตอน
1. เปิด Maltego
2. สร้าง Graph `02-ip-context.mtgl`
3. เพิ่ม Entity **IPv4 Address** ค่า `203.0.113.10`
4. Run Transform:
   - `To DNS Name [Reverse DNS]`
   - `To Netblock [Using natural boundaries]`
   - `To AS number`
   - `To Location [city, country]`
5. วิเคราะห์ผลลัพธ์

#### ตัวอย่าง
```
Input: 203.0.113.10  (TEST-NET-3)
```

#### ผลลัพธ์
```
203.0.113.10
    |
    +-- [PTR]      host10.example.net
    +-- [Netblock] 203.0.113.0-203.0.113.255
    +-- [AS]       64500
    +-- [Location] <City>, <Country>
```

(ผลลัพธ์สมมติ IP สำหรับเอกสารจะไม่คืนข้อมูลจริง)

#### หมายเหตุ
- Reverse DNS ถูกตั้งโดยเจ้าของ IP อาจไม่ตรงกับ Domain ที่ใช้งานจริง
- GeoIP เป็นค่าประมาณ

### 14.2 ตรวจเทียบด้วย Command
```bash
IP=203.0.113.10
dig -x $IP +short
whois $IP | grep -Ei 'netrange|cidr|inetnum|orgname|org-name|country|origin'
whois -h whois.cymru.com " -v $IP"
```

- `dig -x` — Reverse DNS (PTR)
- `whois $IP` — ข้อมูลจาก RIR (ARIN/APNIC/RIPE ฯลฯ)
- `whois.cymru.com` — บริการ IP-to-ASN ของ Team Cymru

ผลลัพธ์ของ Team Cymru (รูปแบบ):

```
AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name
NA      | 203.0.113.10     | NA                  |    |          |            | NA
```

IP สำหรับเอกสารไม่มีการประกาศเส้นทางจริง จึงได้ `NA`

### 14.3 แยก IP ของเป้าหมาย กับ IP ของผู้ให้บริการ
คำถามสำคัญที่ต้องตอบก่อน Pivot ต่อ:
- IP นี้เป็นของ CDN / Cloud / Shared hosting หรือไม่
- ถ้าใช่ การหา "Domain อื่นบน IP เดียวกัน" จะได้ผลเป็นพัน และส่วนใหญ่ไม่เกี่ยวข้องกัน

วิธีสังเกต:
1. ชื่อ AS / Organization เป็นผู้ให้บริการ Cloud หรือ CDN
2. Reverse DNS เป็นชื่อรูปแบบของผู้ให้บริการ
3. Passive DNS แสดง Domain จำนวนมากบน IP เดียว

---

## 15. DNS Enumeration

### 15.1 Record ที่ควรรู้
```
A      ชื่อ → IPv4
AAAA   ชื่อ → IPv6
CNAME  ชื่อ → ชื่ออื่น (alias)
MX     Mail server ของ Domain
NS     Name server ของ Domain
TXT    ข้อความ เช่น SPF, DMARC, Domain verification
SOA    ข้อมูลโซน (Primary NS, Email ผู้ดูแล, Serial)
PTR    IP → ชื่อ
SRV    บริการเฉพาะ เช่น _sip._tcp
CAA    CA ที่อนุญาตให้ออก Certificate
```

### 15.2 Workflow: DNS Enumeration ใน Maltego
#### เป้าหมาย
ได้รายการ Record สาธารณะของ Domain ครบที่สุดโดยไม่ Brute force

#### ขั้นตอน
1. เปิด Maltego และ Graph ของ Case
2. เพิ่ม Domain `example.com`
3. Run: `To DNS Name - NS (name server)` และ `To DNS Name - MX (mail server)`
4. Run: `To DNS Name [Find common DNS names]`
5. เลือก DNS Name ทั้งหมด → `To IP Address [DNS]`
6. เปลี่ยน Layout เป็น Hierarchical
7. วิเคราะห์ผลลัพธ์

#### ผลลัพธ์
Graph แบบลำดับชั้น Domain → Host → IP

#### หมายเหตุ
TXT, SOA, CAA อาจไม่มี Transform มาตรฐานให้ใช้ในทุกเวอร์ชัน ให้ดึงด้วย `dig` แล้วบันทึกเป็น Notes ของ Domain Entity

### 15.3 DNS Enumeration ด้วย Command (ใช้คู่กับ Maltego)
```bash
D=example.com
dig $D ANY +noall +answer          # หลาย Server ไม่ตอบ ANY แล้ว
dig TXT $D +short                  # SPF / verification tokens
dig TXT _dmarc.$D +short           # DMARC
dig CAA $D +short                  # CA ที่อนุญาต
dig SOA $D +short
dig NS $D +short
dig +trace $D                      # ดูเส้นทาง Resolve ตั้งแต่ Root
```

อ่าน SPF เพื่อหา Infrastructure ที่เกี่ยวข้อง:

```bash
dig TXT example.com +short | grep -i spf
```

ตัวอย่างผล (สมมติ):

```
"v=spf1 ip4:198.51.100.0/24 include:_spf.example.net -all"
```

สิ่งที่ได้:
- `198.51.100.0/24` → เพิ่มเป็น Netblock Entity ใน Maltego
- `_spf.example.net` → เพิ่มเป็น DNS Name แล้ว `dig TXT` ต่อ

### 15.4 Zone Transfer (AXFR) — เฉพาะระบบของตนเอง
ใช้ตรวจว่า DNS server ของ **องค์กรตัวเอง** เปิด Zone transfer โดยไม่ตั้งใจหรือไม่

```bash
dig NS example.com +short
dig AXFR example.com @ns1.example.com
```

ผลลัพธ์ที่ปลอดภัย:

```
; Transfer failed.
```

ถ้าได้รายการ Record ทั้งโซน แสดงว่าตั้งค่าผิด ควรจำกัด AXFR ให้เฉพาะ Secondary NS

> **คำเตือน:** ทำเฉพาะกับ DNS server ที่คุณดูแลหรือได้รับอนุญาต Transform แบบ Zone transfer ใน Maltego (ถ้ามีในเวอร์ชันของคุณ) ก็อยู่ภายใต้เงื่อนไขเดียวกัน

---

## 16. WHOIS

### 16.1 Workflow: WHOIS → Entity
#### เป้าหมาย
ดึงข้อมูลการจดทะเบียน Domain เช่น Registrar, วันที่จด, Name server และ Contact (ถ้าไม่ถูกปกปิด)

#### ขั้นตอน
1. เปิด Maltego
2. เพิ่ม Domain `example.com`
3. Run Transform กลุ่ม WHOIS (เช่น `To Entities from WHOIS [IBM Watson]` ถ้ามี หรือ Transform WHOIS ของ Provider อื่น)
4. ดู Entity ใหม่: Person, Organization, Email, Phone, Location
5. ตรวจ Detail View ว่าข้อมูลมาจาก Record ส่วนใด

#### ผลลัพธ์
- Organization / Registrar
- Email ผู้ดูแล (มักถูก Redact หรือเป็น Email ของบริการปกปิดข้อมูล)

#### หมายเหตุ
- หลังการบังคับใช้กฎหมายคุ้มครองข้อมูลส่วนบุคคลในหลายประเทศ ข้อมูล Contact ใน WHOIS มักถูกปกปิด
- ถ้าพบ Email ของบริการ Privacy/Proxy อย่า Pivot ต่อ เพราะจะไปเจอ Domain หลายล้านตัวที่ใช้บริการเดียวกัน

### 16.2 WHOIS และ RDAP ด้วย Command
```bash
whois example.com
whois example.com | grep -Ei 'registrar|creation|updated|expir|name server|status'

# RDAP (ข้อมูลแบบ JSON)
curl -s https://rdap.org/domain/example.com | jq '{handle, status, events, nameservers: [.nameservers[]?.ldhName]}'
```

ผลลัพธ์ RDAP (ตัดมาบางส่วน):

```json
{
  "handle": "...",
  "status": ["client delete prohibited", "..."],
  "events": [{"eventAction": "registration", "eventDate": "..."}],
  "nameservers": ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"]
}
```

### 16.3 สิ่งที่ควรดึงจาก WHOIS ไปใส่ Graph
| ข้อมูล | ใส่เป็น |
|---|---|
| Registrar | Organization หรือ Notes |
| Creation date | Property / Notes |
| Name server | NS Record |
| Registrant Organization (ถ้าไม่ถูกปกปิด) | Organization |
| Abuse contact | Notes (ใช้สำหรับรายงาน Abuse) |

Domain ที่เพิ่งจดไม่กี่วันในเหตุการณ์ Phishing เป็นตัวบ่งชี้ความเสี่ยงที่ใช้บ่อยในงาน Threat Intelligence

---

## 17. Subdomain Enumeration

### 17.1 แหล่งที่มาของ Subdomain
1. DNS แบบ Live (ชื่อที่พบบ่อย, Record ที่ชี้กัน)
2. Certificate Transparency (ชื่อใน SAN ของ Certificate)
3. Passive DNS (ประวัติจาก Provider)
4. เนื้อหาเว็บไซต์ (ลิงก์ในหน้าเว็บ)
5. เครื่องมือภายนอก เช่น Amass (Passive mode)

### 17.2 Workflow: Subdomain Enumeration แบบ Passive
#### เป้าหมาย
รวบรวม Subdomain ของ `example.com` จากแหล่งข้อมูลสาธารณะ โดยไม่ Brute force DNS ของเป้าหมาย

#### ขั้นตอน
1. เปิด Maltego → Graph `03-subdomains.mtgl`
2. เพิ่ม Domain `example.com`
3. Run Transform ด้าน Passive DNS / Certificate จาก Provider ที่ติดตั้ง (ถ้ามี)
4. Run `To DNS Name [Find common DNS names]` เพื่อเสริม
5. รวบรวม Subdomain จากเครื่องมือภายนอก (ข้อ 17.3) แล้ว Import (ข้อ 17.4)
6. เลือก DNS Name ทั้งหมด → `To IP Address [DNS]` เพื่อดูว่าตัวไหนยัง Resolve ได้
7. วิเคราะห์ผลลัพธ์

#### ผลลัพธ์
- DNS Name ที่ Resolve ได้ → ยังใช้งานอยู่ (มี IP ต่อ)
- DNS Name ที่ไม่มี IP → อาจเลิกใช้แล้ว หรือเป็นชื่อภายใน

#### หมายเหตุ
Passive DNS และ Certificate Transform ส่วนใหญ่ต้องติดตั้ง Provider และใช้ API Key

### 17.3 รวบรวมจากเครื่องมือภายนอกบน Kali
```bash
D=example.com
OUT=~/cases/$CASE/raw

# Certificate Transparency ผ่าน crt.sh
curl -s "https://crt.sh/?q=%25.$D&output=json" \
  | jq -r '.[].name_value' | tr 'A-Z' 'a-z' | sed 's/^\*\.//' \
  | sort -u > $OUT/subs-crtsh.txt

# Amass แบบ passive (ติดตั้งด้วย sudo apt install amass)
amass enum -passive -d $D -o $OUT/subs-amass.txt

# รวมและตัดซ้ำ
cat $OUT/subs-*.txt | grep -E "\.$D$|^$D$" | sort -u > $OUT/subs-all.txt
wc -l $OUT/subs-all.txt
```

> **หมายเหตุ:** Option ของ Amass เปลี่ยนตามเวอร์ชัน ตรวจด้วย `amass enum -h` crt.sh เป็นบริการสาธารณะที่อาจช้าหรือตอบไม่ได้ในบางช่วง

### 17.4 Import รายชื่อ Subdomain เข้า Maltego
สร้าง CSV:

```bash
{ echo "dns_name"; cat $OUT/subs-all.txt; } > ~/cases/$CASE/raw/subs-import.csv
head ~/cases/$CASE/raw/subs-import.csv
```

ขั้นตอนใน Maltego:
1. Tab **Import | Export** → **Import Graph from Table** (ชื่อเมนูอาจต่างกัน)
2. เลือกไฟล์ `subs-import.csv`
3. กำหนดให้แถวแรกเป็น Header
4. Map คอลัมน์ `dns_name` → Entity type **DNS Name**
5. Finish

ผลลัพธ์: DNS Name ทุกตัวปรากฏบน Graph (ยังไม่มี Link) จากนั้นเลือกทั้งหมดแล้วรัน `To IP Address [DNS]`

### 17.5 ตรวจสถานะ Resolve ด้วย Command
```bash
while read h; do
  ip=$(dig +short A "$h" | grep -E '^[0-9.]+$' | head -1)
  echo "$h,${ip:-NXDOMAIN_OR_NO_A}"
done < $OUT/subs-all.txt | tee $OUT/subs-resolved.csv
```

ไฟล์ `subs-resolved.csv` นำไป Import เป็นคู่ DNS Name → IP ได้ (Map สองคอลัมน์และสร้าง Link ระหว่างกัน)

---

## 18. Certificate / SSL

### 18.1 ทำไม Certificate สำคัญ
- Certificate หนึ่งใบอาจมีหลายชื่อใน SAN (Subject Alternative Name) → เปิดเผย Host อื่นขององค์กร
- Fingerprint ของ Certificate ใช้ Pivot หา Server อื่นที่ใช้ใบเดียวกัน (ผ่าน Internet scan data)
- วันที่ออก Certificate บอก Timeline ของ Infrastructure

### 18.2 ดึง Certificate ด้วย openssl
```bash
H=example.com
echo | openssl s_client -connect $H:443 -servername $H 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -serial -fingerprint -sha256
```

ผลลัพธ์ (รูปแบบ):

```
subject=CN = example.com
issuer=C = US, O = <CA>, CN = <CA name>
notBefore=...
notAfter=...
serial=...
sha256 Fingerprint=AB:CD:...
```

ดึงรายชื่อ SAN:

```bash
echo | openssl s_client -connect $H:443 -servername $H 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName
```

### 18.3 Workflow: Certificate Pivot
#### เป้าหมาย
หา Host อื่นที่อยู่ใน Certificate เดียวกันกับ `www.example.com`

#### ขั้นตอน
1. เปิด Maltego
2. สร้าง Graph `04-cert-pivot.mtgl`
3. เพิ่ม Website/DNS Name `www.example.com`
4. เลือก Transform ด้าน Certificate จาก Provider ที่ติดตั้ง (ถ้ามี) หรือ
   - ดึง SAN ด้วย openssl (ข้อ 18.2)
   - สร้าง Entity Certificate (ถ้ามีใน Palette) ใส่ Fingerprint ใน Property/Notes
   - สร้าง DNS Name ตามรายชื่อ SAN แล้วลาก Link จาก Certificate
5. Run `To IP Address [DNS]` กับ DNS Name ใหม่
6. วิเคราะห์ผลลัพธ์

#### ผลลัพธ์
```
[Certificate SHA256 AB:CD:...]
    |
    +-- www.example.com ---- 203.0.113.10
    +-- example.com     ---- 203.0.113.10
    +-- dev.example.com ---- 198.51.100.20
```

#### หมายเหตุ
- `dev.example.com` อยู่คนละ Netblock เป็นจุดที่ควรตรวจต่อ (อาจเป็น Hosting อื่น)
- Certificate แบบ Wildcard (`*.example.com`) ไม่เปิดเผยชื่อ Host

### 18.4 Certificate Transparency ด้วย crt.sh
```bash
curl -s "https://crt.sh/?q=example.com&output=json" \
  | jq -r '.[] | [.not_before, .issuer_name, .name_value] | @tsv' \
  | sort | tail -20
```

สิ่งที่ดู:
- Certificate ออกบ่อยผิดปกติหรือไม่
- มี CA แปลก ๆ ที่องค์กรไม่ได้ใช้หรือไม่ (เทียบกับ CAA record)
- มีชื่อ Host ใหม่ที่ไม่เคยเห็น

---
## 19. Email Enumeration

### 19.1 Workflow: หา Email สาธารณะขององค์กร
#### เป้าหมาย
รู้รูปแบบ Email ขององค์กร (เช่น `firstname@`, `f.lastname@`) และ Email สาธารณะที่ประกาศไว้

#### ขั้นตอน
1. เปิด Maltego → Graph `05-email.mtgl`
2. เพิ่ม Domain `example.com`
3. Run Transform กลุ่ม WHOIS (Email ผู้ดูแล)
4. Run Transform ที่หา Email จาก Domain ของ Provider ที่ติดตั้ง (ค้นคำว่า `Email` ในเมนู Transform ของ Domain)
5. เพิ่ม Email ที่พบจากหน้าเว็บ "ติดต่อเรา" ด้วยมือ (Paste)
6. วิเคราะห์รูปแบบ

#### ตัวอย่าง
```
Domain: example.com
พบ: info@example.com, support@example.com, alice@example.com
```

#### ผลลัพธ์
```
example.com
    +-- info@example.com      (role account)
    +-- support@example.com   (role account)
    +-- alice@example.com     (personal pattern: firstname@)
```

#### หมายเหตุ
- Transform ด้าน Email มักต้องมี Provider เฉพาะและ API Key
- ห้ามเดา Email แล้วส่งอีเมลทดสอบ/ตรวจสอบกับ Mail server ของเป้าหมายโดยไม่ได้รับอนุญาต

### 19.2 ตรวจ Mail Infrastructure ของ Domain
```bash
D=example.com
dig MX $D +short
dig TXT $D +short | grep -i spf
dig TXT _dmarc.$D +short
dig TXT default._domainkey.$D +short   # ชื่อ selector ต่างกันแต่ละองค์กร
```

สิ่งที่ได้ไปใส่ Graph:
- MX → DNS Name → IP → AS (รู้ว่าใช้ Mail provider ใด)
- SPF include → DNS Name ของบริการส่งเมลที่ใช้
- DMARC `rua=mailto:` → Email / Domain ของบริการรายงาน DMARC

### 19.3 Workflow: Email เดี่ยว → Context
#### เป้าหมาย
จาก Email หนึ่งตัว หาข้อมูลสาธารณะที่เกี่ยวข้อง

#### ขั้นตอน
1. เพิ่ม Email Address `alice@example.com`
2. Run Transform ที่แยกเป็น Domain
3. Run Transform ของ Provider ที่ติดตั้ง (เช่น Breach, Social) ถ้าอยู่ในขอบเขต
4. ต่อ Domain เข้ากับ Workflow ในบท 13

#### ผลลัพธ์
```
alice@example.com
    +-- example.com ---- (ต่อด้วย DNS/IP ตามบท 13)
    +-- [Alias] alice_example   (ถ้า Provider คืนมา — ต้องยืนยัน)
```

#### หมายเหตุ
ผลลัพธ์ Email → Alias/Person เป็นการจับคู่ ไม่ใช่ข้อเท็จจริง ดูบท [Link Analysis](#35-link-analysis) เรื่องระดับความเชื่อมั่น

---

## 20. Username Investigation

### 20.1 Workflow: Username → Public Profiles
#### เป้าหมาย
ตรวจว่า Username หนึ่งมีบัญชีสาธารณะบนบริการใดบ้าง

#### ขั้นตอน
1. ใช้ `sherlock` บน Kali ตรวจชื่อผู้ใช้ (ข้อ 20.2)
2. เปิด Maltego → Graph `06-username.mtgl`
3. เพิ่ม Entity Alias ค่า `alice_example`
4. Import ผล sherlock เป็น URL Entity (ข้อ 20.3)
5. เปิดตรวจแต่ละ URL ด้วยตนเอง ลบที่เป็น False positive
6. บันทึกหลักฐานของ Profile ที่ยืนยันแล้ว

#### ตัวอย่าง
```
Username: alice_example
```

#### ผลลัพธ์
```
[Alias] alice_example
    +-- [URL] https://<service-1>/alice_example   (ยืนยันแล้ว)
    +-- [URL] https://<service-2>/alice_example   (False positive — ลบ)
```

#### หมายเหตุ
Username เดียวกันบนหลายบริการ **ไม่** แปลว่าเป็นคนเดียวกัน ต้องมีตัวบ่งชี้ร่วม เช่น รูปเดียวกัน, ลิงก์ข้ามบัญชี, Bio เดียวกัน

### 20.2 ใช้ sherlock
```bash
sudo apt install -y sherlock
sherlock --help | head -30
sherlock alice_example --timeout 10 --csv
ls -l alice_example*
```

> **หมายเหตุ:** Option ของ sherlock เปลี่ยนตามเวอร์ชัน (เช่น `--csv`, `--output`) ตรวจด้วย `sherlock --help`

### 20.3 แปลงผลเป็น CSV สำหรับ Maltego
ถ้า sherlock สร้างไฟล์ CSV ให้ดูคอลัมน์ก่อน:

```bash
head -3 alice_example.csv
```

สร้างไฟล์ Import แบบสองคอลัมน์ (Alias → URL):

```bash
# สมมติคอลัมน์ URL อยู่ในไฟล์ .txt ผลลัพธ์ของ sherlock (1 URL ต่อบรรทัด)
grep -Eo 'https?://[^ ]+' alice_example.txt \
  | awk -v u=alice_example 'BEGIN{print "alias,url"} {print u","$0}' \
  > ~/cases/$CASE/raw/alias-urls.csv
```

Import ใน Maltego: Map `alias` → Alias, `url` → URL และเลือกสร้าง Link จาก alias ไป url

---

## 21. Social Media OSINT

### 21.1 สิ่งที่ Maltego ทำได้และข้อจำกัด
- Transform ด้าน Social Media ส่วนใหญ่มาจาก Provider เฉพาะทาง และมักเป็นแบบเสียเงิน
- แพลตฟอร์ม Social ปรับ API และนโยบายบ่อย Transform ที่เคยใช้ได้อาจหยุดทำงาน
- Standard Transforms มีความสามารถด้าน Social จำกัด

### 21.2 Workflow: บันทึก Social Profile ด้วยมือเข้า Graph
#### เป้าหมาย
ใช้ Maltego เป็นที่รวบรวมความสัมพันธ์ แม้ไม่มี Transform ด้าน Social

#### ขั้นตอน
1. เปิด Graph ของ Case
2. เพิ่ม Entity Alias/Social account (ค้นใน Palette หมวด Social Network)
3. ใส่ URL ของ Profile ใน Property หรือ Notes
4. แนบ Screenshot ใน Attachments (ดูบท [การบันทึกหลักฐาน](#46-การบันทึกหลักฐาน))
5. ลาก Link ไปยัง Email/Website/Alias ที่พบใน Profile
6. ตั้งชื่อ Link เช่น `bio link`, `same avatar`

#### ผลลัพธ์
```
[Alias] alice_example
    +--(bio link)--> [Website] www.example.org
    +--(same avatar)--> [Alias] demo_user01
```

#### หมายเหตุ
ข้อมูลบน Social Media เป็นข้อมูลส่วนบุคคล ต้องมีเหตุผลทางกฎหมายและอยู่ในขอบเขตงาน

### 21.3 ตัวบ่งชี้ที่ใช้เชื่อมบัญชี (เรียงจากแข็งไปอ่อน)
1. บัญชีลิงก์หากันเอง (Profile A ใส่ลิงก์ไป Profile B)
2. Email / Website เดียวกันใน Bio
3. รูป Profile เดียวกัน (ตรวจด้วย Reverse image search)
4. รูปแบบการเขียนและเวลาโพสต์คล้ายกัน
5. Username เหมือนกัน (อ่อนที่สุด)

---

## 22. Person / Organization Investigation

### 22.1 Workflow: Organization → Digital Footprint
#### เป้าหมาย
จากชื่อองค์กร หา Domain, Website และ Infrastructure ที่เป็นทางการ

#### ขั้นตอน
1. เปิด Maltego → Graph `07-org.mtgl`
2. เพิ่ม Entity Organization `Example Corp`
3. Run Transform ที่หา Domain/Website จาก Organization (ขึ้นกับ Provider) หรือเพิ่ม Domain ที่ทราบด้วยมือ
4. จาก Domain → ทำ Workflow บท 13 (DNS/IP)
5. จาก IP → AS → ตรวจว่ามี AS ขององค์กรเองหรือไม่ (บท 25)
6. เพิ่มเอกสารสาธารณะ (Document) ที่พบบนเว็บไซต์ (บท 34)

#### ผลลัพธ์
```
[Org] Example Corp
    +-- example.com
    |      +-- www.example.com ---- 203.0.113.10 ---- AS64500 (Hosting)
    |      +-- mail.example.com --- 198.51.100.25 --- AS64501 (Mail provider)
    +-- example.org
    +-- [Document] annual-report.pdf
```

#### หมายเหตุ
การค้นหาจากชื่อองค์กรมักได้ผลที่ชื่อคล้ายกันแต่ไม่เกี่ยวข้อง ตรวจกับเว็บไซต์ทางการเสมอ

### 22.2 Workflow: Person (ในขอบเขตงาน) → Public Professional Footprint
#### เป้าหมาย
รวบรวมข้อมูลสาธารณะเชิงวิชาชีพของบุคคลที่อยู่ในขอบเขต (เช่น ผู้บริหารขององค์กรที่ว่าจ้างให้ประเมิน Social engineering exposure)

#### ขั้นตอน
1. เพิ่ม Person `Alice Example` (ค่าสมมติ)
2. เชื่อมกับ Organization `Example Corp` ด้วยมือ (Link label: `employee - source: company website`)
3. เพิ่ม Email ตามรูปแบบที่ยืนยันแล้วของบริษัท (บท 19) — ระบุใน Notes ว่า "อนุมานจากรูปแบบ"
4. รัน Transform ของ Provider ที่อยู่ในขอบเขต
5. บันทึกเฉพาะข้อมูลที่เกี่ยวกับความเสี่ยงขององค์กร

#### หมายเหตุ
เก็บข้อมูลเท่าที่จำเป็น (Data minimization) ไม่เก็บข้อมูลครอบครัว ที่อยู่บ้าน หรือข้อมูลอ่อนไหวที่ไม่เกี่ยวกับวัตถุประสงค์

---

## 23. Website Investigation

### 23.1 Workflow: Website Profiling
#### เป้าหมาย
รู้ว่าเว็บไซต์ Host ที่ไหน ใช้เทคโนโลยีอะไร และเชื่อมกับเว็บไซต์อื่นอย่างไร

#### ขั้นตอน
1. เพิ่ม Website `www.example.com`
2. Run `To IP Address [DNS]`
3. Run Transform ด้านเทคโนโลยีเว็บ / Tracking codes (ถ้ามีในเวอร์ชันหรือ Provider ของคุณ)
4. ตรวจ HTTP header ด้วย curl (ข้อ 23.2) บันทึกลง Notes
5. เชื่อม IP → AS (บท 25)

#### ผลลัพธ์
```
www.example.com
    +-- 203.0.113.10
    +-- [Tech] <Web server>, <CMS>
    +-- [Tracking code] <analytics ID>  ---- www.example.org (ใช้ ID เดียวกัน)
```

#### หมายเหตุ
Tracking code ID ที่เหมือนกันบนหลายเว็บไซต์เป็นตัวบ่งชี้ว่าอาจมีผู้ดูแลเดียวกัน (แต่ไม่ใช่หลักฐานเด็ดขาด)

### 23.2 Command ตรวจเว็บไซต์
```bash
U=https://www.example.com
curl -sI $U
curl -sIL $U | grep -Ei '^(HTTP|location|server|x-powered-by|strict-transport)'
curl -s $U | grep -Eio '<title>[^<]*' | head -1
curl -s $U/robots.txt
curl -s $U/.well-known/security.txt
```

- `-I` ดึงเฉพาะ Header
- `-L` ตาม Redirect
- `robots.txt` และ `security.txt` เป็นไฟล์สาธารณะที่ตั้งใจเปิดเผย

---

## 24. Infrastructure Mapping

### 24.1 Workflow: Infrastructure Map แบบรวม
#### เป้าหมาย
สร้างแผนภาพ Infrastructure สาธารณะทั้งหมดขององค์กรใน Graph เดียว

#### ขั้นตอน
1. เริ่มจาก Graph ของบท 13 และบท 17 (Domain + Subdomain + IP)
2. เลือก IP ทั้งหมด (Select by Type → IPv4 Address)
3. Run `To Netblock [Using natural boundaries]`
4. Run `To AS number`
5. ใช้ Layout **Hierarchical** หรือ **Organic**
6. ใส่ Bookmark สี:
   - เขียว = Infrastructure ขององค์กรเอง
   - เหลือง = Cloud/CDN
   - แดง = ไม่ทราบเจ้าของ ต้องตรวจต่อ
7. Export ภาพ (บท 45)

#### ผลลัพธ์
```
example.com
 ├── www.example.com  → 203.0.113.10  → 203.0.113.0/24  → AS64500 (Example Corp)
 ├── mail.example.com → 198.51.100.25 → 198.51.100.0/24 → AS64501 (Mail provider)
 └── dev.example.com  → 192.0.2.50    → 192.0.2.0/24    → AS64502 (Cloud)
```

#### หมายเหตุ
Graph นี้คือ Attack Surface สาธารณะ เหมาะกับงานประเมินองค์กรตัวเองหรืองานที่ได้รับอนุญาต

---

## 25. ASN

### 25.1 Workflow: IP → ASN → เจ้าของเครือข่าย
#### เป้าหมาย
รู้ว่า IP อยู่ใน ASN ใด และ ASN นั้นเป็นของใคร

#### ขั้นตอน
1. เลือก IP Entity
2. Run `To AS number`
3. คลิก AS Entity → ดู Property/Detail View (ชื่อ AS, ประเทศ ถ้ามี)
4. ตรวจเทียบด้วย Command (ข้อ 25.2)

#### ผลลัพธ์
```
203.0.113.10 ---- [AS] 64500
```

#### หมายเหตุ
AS ที่เป็นของ Cloud/CDN รายใหญ่ ไม่ควร Pivot ไปยัง Netblock ทั้งหมด (มีจำนวนมหาศาลและไม่เกี่ยวข้อง)

### 25.2 Command สำหรับ ASN
```bash
# IP → ASN (Team Cymru)
whois -h whois.cymru.com " -v 203.0.113.10"

# ข้อมูล ASN จาก RIR
whois AS64496

# ASN → Prefix ที่ประกาศ (RIPEstat)
curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS64496" \
  | jq -r '.data.prefixes[].prefix'
```

ASN `64496–64511` สงวนไว้สำหรับเอกสาร จึงไม่มี Prefix ที่ประกาศจริง ผลลัพธ์จะว่าง

---

## 26. Netblock

### 26.1 Workflow: Netblock → IP ที่ใช้งาน
#### เป้าหมาย
ใน Netblock ขององค์กรตัวเอง หาว่า IP ใดมีชื่อ Host (PTR) ชี้อยู่

#### ขั้นตอน
1. เพิ่ม Netblock `203.0.113.0/24`
2. ตรวจขนาดด้วย `ipcalc` ก่อน (256 IP)
3. Run Transform ที่แปลง Netblock เป็น IP หรือ DNS Name (ตั้งจำนวนผลลัพธ์ให้เหมาะสม)
4. เลือก IP ที่ได้ → `To DNS Name [Reverse DNS]`
5. ลบ IP ที่ไม่มี PTR (ถ้าไม่ต้องการ)

#### ผลลัพธ์
```
203.0.113.0/24
    +-- 203.0.113.10 ---- www.example.com
    +-- 203.0.113.25 ---- mail.example.com
```

#### หมายเหตุ
การแตก Netblock ใหญ่ (เช่น /16 = 65,536 IP) ใช้ Quota และเวลามาก ทำเฉพาะช่วงที่อยู่ในขอบเขต

### 26.2 Reverse DNS ทั้งช่วงด้วย Command (ระบบของตนเอง)
```bash
for i in $(seq 1 254); do
  ip=203.0.113.$i
  ptr=$(dig -x $ip +short | head -1)
  [ -n "$ptr" ] && echo "$ip,$ptr"
done | tee ~/cases/$CASE/raw/ptr-203.0.113.csv
```

ไฟล์ผลลัพธ์นำไป Import เป็นคู่ IP → DNS Name ได้

---

## 27. Autonomous System

บทนี้ต่างจากบท 25: บท 25 ใช้หา "IP นี้อยู่ AS ไหน" บทนี้ใช้ดู "AS นี้มีขอบเขตแค่ไหน และเชื่อมกับใคร"

### 27.1 Workflow: AS Profiling
#### เป้าหมาย
ประเมินว่า AS หนึ่งเป็นของใคร มี Prefix อะไร และเป็นผู้ให้บริการแบบไหน

#### ขั้นตอน
1. เพิ่ม AS `64500`
2. Run Transform AS → Netblock (ถ้ามี) ตั้งจำนวนผลลัพธ์ต่ำก่อน
3. ดึงข้อมูลเสริมด้วย RIPEstat (ข้อ 27.2) บันทึกใน Notes ของ AS
4. จัดประเภท AS: องค์กร / Hosting / Cloud / ISP
5. ตัดสินใจว่าจะ Pivot ต่อหรือไม่

#### ผลลัพธ์
```
[AS] 64500 (Example Corp)
    +-- 203.0.113.0/24
    +-- 2001:db8:100::/48
```

#### หมายเหตุ
AS ขององค์กรเองมักมี Prefix น้อยและชื่อตรงกับองค์กร AS ของ Hosting มี Prefix มากและลูกค้าหลากหลาย

### 27.2 ดูข้อมูล AS ด้วย API สาธารณะ
```bash
AS=AS64496
curl -s "https://stat.ripe.net/data/as-overview/data.json?resource=$AS" | jq '.data'
curl -s "https://stat.ripe.net/data/asn-neighbours/data.json?resource=$AS" \
  | jq -r '.data.neighbours[] | "\(.asn) \(.type)"' | head
```

- `as-overview` — ชื่อ AS และสถานะการประกาศ
- `asn-neighbours` — AS ที่เชื่อมต่อ (upstream/downstream)

---

## 28. URL และ Web Infrastructure

### 28.1 Workflow: URL → Infrastructure
#### เป้าหมาย
จาก URL หนึ่ง (เช่น ลิงก์ในอีเมลที่ถูกรายงาน) ระบุ Domain, Host, IP และ Hosting โดยไม่เปิด URL บนเครื่องหลัก

#### ขั้นตอน
1. เพิ่ม URL `https://login.example.net/account/verify`
2. Run Transform ที่แยก URL → Website / Domain (หรือ Machine `URL To Network And Domain Information` ถ้ามี)
3. Website → `To IP Address [DNS]`
4. IP → `To AS number`, `To Netblock [Using natural boundaries]`
5. Domain → WHOIS (ดูวันที่จด)
6. Run Transform Threat Intel กับ URL/Domain (ถ้ามี Provider)

#### ผลลัพธ์
```
https://login.example.net/account/verify
    +-- login.example.net ---- 198.51.100.77 ---- AS64510
    +-- example.net (WHOIS: created <recent date>)
```

#### หมายเหตุ
ใช้ Sandbox หรือบริการสแกน URL สาธารณะแทนการเปิด URL เอง

### 28.2 แยกส่วนประกอบ URL ด้วย Command
```bash
U='https://login.example.net/account/verify?id=123'
python3 - "$U" << 'EOF'
import sys
from urllib.parse import urlparse
u = urlparse(sys.argv[1])
print("scheme:", u.scheme)
print("host:  ", u.hostname)
print("path:  ", u.path)
print("query: ", u.query)
EOF
```

ตรวจ Redirect chain โดยไม่ดาวน์โหลดเนื้อหา:

```bash
curl -sIL --max-redirs 5 "$U" | grep -Ei '^(HTTP|location)'
```

> **คำเตือน:** แม้ `curl -I` จะไม่รัน JavaScript แต่ก็ยังติดต่อ Server ของ URL นั้น ใช้เฉพาะเมื่ออยู่ในขอบเขตงาน และพิจารณาใช้ผ่านเครือข่ายแยก

---

## 29. Threat Intelligence

### 29.1 IOC ใน Maltego
| IOC | Entity |
|---|---|
| Domain | Domain |
| Host | DNS Name |
| IP | IPv4/IPv6 Address |
| URL | URL |
| File hash | Hash |
| Certificate fingerprint | Certificate หรือ Property/Notes |
| Email ผู้ส่ง | Email Address |

### 29.2 Workflow: IOC Enrichment
#### เป้าหมาย
เพิ่ม Context ให้ IOC จากรายงานเหตุการณ์ โดยใช้ข้อมูลสาธารณะและ Threat Intel Provider

#### ขั้นตอน
1. สร้างไฟล์ IOC (ข้อ 29.3)
2. Import เข้า Maltego (Map แต่ละคอลัมน์เป็น Entity type)
3. Domain/DNS Name → `To IP Address [DNS]`
4. IP → `To AS number`, `To Netblock [Using natural boundaries]`
5. รัน Transform ของ Threat Intel Provider ที่ติดตั้ง (Reputation, Passive DNS, Related samples)
6. หา Entity ที่มี Link จาก IOC หลายตัว (จุดร่วม)
7. บันทึกข้อค้นพบใน Notes และ Bookmark

#### ตัวอย่าง
```
IOC จากรายงาน (สมมติ):
- update-check.example.net
- 198.51.100.77
- 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f (EICAR test file)
```

#### ผลลัพธ์
```
update-check.example.net ──┐
                           ├──> 198.51.100.77 ──> AS64510
cdn-sync.example.org ──────┘        (จุดร่วม: IP เดียวกัน)
```

#### หมายเหตุ
- ผลของ Threat Intel ขึ้นกับ Provider และ Plan
- IP ร่วมกันบน Shared hosting ไม่ได้แปลว่าเป็นผู้กระทำเดียวกัน

### 29.3 เตรียมไฟล์ IOC
```bash
cat > ~/cases/$CASE/raw/iocs.csv << 'EOF'
type,value
domain,update-check.example.net
domain,cdn-sync.example.org
ip,198.51.100.77
hash,275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
EOF
```

แยกตามประเภทเพื่อ Import ง่ายขึ้น:

```bash
cd ~/cases/$CASE/raw
for t in domain ip hash; do
  { echo "$t"; awk -F, -v t=$t '$1==t{print $2}' iocs.csv; } > ioc-$t.csv
done
wc -l ioc-*.csv
```

### 29.4 Defang / Refang IOC
เวลาเขียนรายงาน ให้ Defang เพื่อกันการคลิกโดยไม่ตั้งใจ:

```bash
echo "update-check.example.net 198.51.100.77" \
  | sed -e 's/\./[.]/g'
# ผล: update-check[.]example[.]net 198[.]51[.]100[.]77
```

ก่อน Import เข้า Maltego ต้อง Refang กลับ:

```bash
sed -e 's/\[\.\]/./g' -e 's/hxxp/http/g' iocs-defanged.txt > iocs-clean.txt
```

---

## 30. Malware-related OSINT

บทนี้เน้นวิเคราะห์ Infrastructure ที่เกี่ยวกับ Malware จากข้อมูลสาธารณะเท่านั้น ไม่มีการรันหรือแจกจ่าย Malware

### 30.1 Workflow: Hash → Infrastructure
#### เป้าหมาย
จาก Hash ของไฟล์ต้องสงสัย หา Domain/IP ที่ Sandbox สาธารณะบันทึกว่าเกี่ยวข้อง

#### ขั้นตอน
1. เพิ่ม Hash Entity (ใช้ Hash ของไฟล์ทดสอบ EICAR ในการฝึก)
2. รัน Transform ของ Threat Intel Provider ที่รองรับ Hash (ต้องติดตั้งและมี API Key)
3. ผลที่ได้อาจเป็น: ชื่อตระกูล Malware, Domain/IP ที่ติดต่อ, URL ที่ดาวน์โหลด
4. นำ Domain/IP เข้า Workflow บท 29.2
5. ตรวจ Certificate ของ Domain ที่พบ (บท 18)

#### ผลลัพธ์
```
[Hash] 275a02...fd0f
    +-- [Detection] EICAR test file
```

(ไฟล์ EICAR ไม่ใช่ Malware จริง จึงไม่มี Infrastructure ต่อ ใช้เพื่อทดสอบว่า Transform ทำงาน)

#### หมายเหตุ
การค้น Hash ในบริการสาธารณะปลอดภัยกว่าการอัปโหลดไฟล์ เพราะไฟล์ที่อัปโหลดอาจถูกเผยแพร่ต่อผู้ใช้อื่นของบริการ ห้ามอัปโหลดไฟล์ที่มีข้อมูลลับขององค์กร

### 30.2 คำนวณ Hash และค้นแบบไม่อัปโหลดไฟล์
```bash
sha256sum suspicious.bin | awk '{print $1}' > hash.txt
cat hash.txt

# ค้นรายงานด้วย Hash (VirusTotal API v3)
curl -s -H "x-apikey: $VT_API_KEY" \
  "https://www.virustotal.com/api/v3/files/$(cat hash.txt)" \
  | jq '.data.attributes | {type_description, last_analysis_stats}'
```

### 30.3 รูปแบบ Infrastructure ที่ควรสังเกต
- Domain หลายตัวจดใกล้วันกัน ใช้ Registrar และ NS เดียวกัน
- Certificate ออกพร้อมกันหลายชื่อ
- IP อยู่ใน AS ของ Hosting ราคาถูกเดียวกัน
- ชื่อ Host เลียนแบบบริการที่รู้จัก (เช่น `update-`, `cdn-`, `login-`)

---

## 31. Breach / Leak Intelligence

### 31.1 ขอบเขตที่ทำได้
- ตรวจว่า Email/Domain **ขององค์กรตัวเอง** ปรากฏในเหตุการณ์ข้อมูลรั่วไหลที่เปิดเผยต่อสาธารณะหรือไม่
- ใช้บริการที่ถูกกฎหมาย เช่น Have I Been Pwned (มี API แบบเสียเงินสำหรับค้นรายบัญชี)

> **คำเตือน:** ห้ามดาวน์โหลด, ซื้อ หรือใช้ Credential ที่รั่วไหล การนำรหัสผ่านที่รั่วไปลอง Login เป็นการเข้าถึงโดยไม่ได้รับอนุญาต

### 31.2 Workflow: Organization Breach Exposure
#### เป้าหมาย
ประเมินว่าบัญชีขององค์กรปรากฏในเหตุการณ์รั่วไหลใดบ้าง เพื่อกำหนดมาตรการ (บังคับเปลี่ยนรหัส, เปิด MFA)

#### ขั้นตอน
1. เพิ่ม Email ขององค์กรที่ได้รับอนุญาตให้ตรวจ เช่น `alice@example.com`
2. ติดตั้ง Provider ด้าน Breach จาก Transform Hub (ถ้ามี) และใส่ API Key
3. รัน Transform ตรวจ Breach
4. ผลลัพธ์จะเป็นชื่อเหตุการณ์ (Breach name) ที่ Email ปรากฏ
5. บันทึกเฉพาะชื่อเหตุการณ์และวันที่ ไม่บันทึกข้อมูลรั่วไหลจริง

#### ผลลัพธ์
```
alice@example.com
    +-- [Breach] <ExampleServiceBreach> (<date>)
```

#### หมายเหตุ
ต้องมี API Key และอาจต้องยืนยันความเป็นเจ้าของ Domain ในบริการ

### 31.3 ตรวจด้วย API โดยตรง
```bash
# รายการ Breach ทั้งหมดที่เปิดเผย (ไม่ต้องใช้ Key)
curl -s -A "maltego-guide-lab" https://haveibeenpwned.com/api/v3/breaches \
  | jq -r '.[] | "\(.BreachDate) \(.Name)"' | sort | tail -5

# ค้นรายบัญชี (ต้องใช้ Key)
curl -s -A "maltego-guide-lab" -H "hibp-api-key: $HIBP_API_KEY" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/alice%40example.com?truncateResponse=true"
```

- `-A` ตั้ง User-Agent (บริการนี้กำหนดให้ต้องมี)
- `%40` คือ `@` ที่ Encode แล้ว
- ได้ HTTP 404 = ไม่พบในเหตุการณ์ที่บริการรู้จัก

---

## 32. Cryptocurrency OSINT

### 32.1 สิ่งที่ต้องรู้ก่อน
- Blockchain สาธารณะ (เช่น Bitcoin) เปิดให้ดูธุรกรรมได้ แต่ไม่ได้บอกตัวตนเจ้าของโดยตรง
- Transform ด้าน Crypto ใน Maltego มาจาก Provider เฉพาะทาง ส่วนใหญ่ต้องมี License
- การระบุตัวตนเจ้าของกระเป๋าต้องอาศัยข้อมูลนอก Blockchain (เช่น ประกาศรับบริจาคบนเว็บไซต์)

### 32.2 Workflow: Wallet ในรายงาน → Context สาธารณะ
#### เป้าหมาย
จาก Wallet address ที่พบในรายงาน (เช่น ข้อความเรียกค่าไถ่ หรือหน้าเว็บหลอกลวง) หาว่าปรากฏที่ใดบ้างในแหล่งสาธารณะ

#### ขั้นตอน
1. เพิ่ม Entity Cryptocurrency Address (ถ้ามีใน Palette) ค่า `<WALLET_ADDRESS>`
2. รัน Transform ของ Provider ด้าน Blockchain (ถ้าติดตั้ง) เพื่อดูธุรกรรมและ Address ที่เชื่อมกัน
3. เชื่อมกับ URL/Website ที่พบ Wallet นี้ด้วยมือ
4. ถ้า Address เชื่อมกับบริการแลกเปลี่ยน (Exchange) ให้บันทึกไว้สำหรับส่งต่อหน่วยงานที่มีอำนาจ

#### ผลลัพธ์
```
[Website] scam-site.example.net
    +-- [Crypto Address] <WALLET_ADDRESS>
            +-- [Crypto Address] <WALLET_ADDRESS_2>  (รับเงินต่อ)
```

#### หมายเหตุ
ข้อมูลเชิงลึกเรื่อง Clustering/Attribution ขึ้นกับ Provider ที่มี License และต้องตีความอย่างระมัดระวัง

---

## 33. Geolocation-related OSINT

### 33.1 แหล่งข้อมูลตำแหน่ง
| แหล่ง | ความแม่นยำโดยทั่วไป |
|---|---|
| GeoIP ของ IP | ระดับประเทศ/เมือง (อาจผิด โดยเฉพาะ Cloud/VPN/Mobile) |
| WHOIS address | ที่อยู่จดทะเบียน ไม่ใช่ที่ตั้ง Server |
| EXIF GPS ในรูปภาพ | แม่นยำถ้ามี (แต่หลายแพลตฟอร์มลบทิ้ง) |
| เนื้อหาในภาพ | ต้องวิเคราะห์ด้วยตนเอง |

### 33.2 Workflow: IP → Location และตรวจความสอดคล้อง
#### เป้าหมาย
ดูตำแหน่งโดยประมาณของ Infrastructure และตรวจว่าข้อมูลจากหลายแหล่งตรงกันหรือไม่

#### ขั้นตอน
1. เลือก IP ทั้งหมดใน Graph
2. Run `To Location [city, country]`
3. เปรียบเทียบกับประเทศใน WHOIS ของ Netblock (ข้อ 14.2)
4. บันทึกความไม่สอดคล้องใน Notes

#### ผลลัพธ์
```
203.0.113.10 ---- [Location] <City A>, <Country A>
             ---- (WHOIS Netblock country: <Country B>)  ← ไม่ตรงกัน
```

#### หมายเหตุ
ความไม่ตรงกันพบได้บ่อยกับ Cloud และ Anycast ไม่ใช่สัญญาณผิดปกติเสมอไป

### 33.3 ดู GPS ในรูปภาพ
```bash
exiftool -gpslatitude -gpslongitude -gpsposition -n photo.jpg
exiftool -a -G1 -s photo.jpg | grep -i gps
```

ถ้าพบพิกัด ให้สร้าง Entity Location และใส่ Latitude/Longitude ใน Property

---

## 34. Metadata Investigation

### 34.1 Workflow: เอกสารสาธารณะ → Metadata → Entity
#### เป้าหมาย
ตรวจว่าเอกสารที่องค์กรเผยแพร่บนเว็บไซต์ เปิดเผยชื่อผู้ใช้ภายใน, ชื่อซอฟต์แวร์ หรือ Path ภายในหรือไม่

#### ขั้นตอน
1. รวบรวม URL ของเอกสารบนเว็บไซต์ของตนเอง (เช่น จาก Sitemap)
2. ดาวน์โหลดเข้าโฟลเดอร์ `evidence` (ข้อ 34.2)
3. ดึง Metadata ด้วย exiftool เป็น CSV
4. Import เข้า Maltego: Document → Person (Author), Document → Phrase (Creator/Producer)
5. หาค่าที่ซ้ำกันหลายเอกสาร (เช่น Author คนเดียวกัน)

#### ผลลัพธ์
```
[Document] report-2025.pdf ──> [Alias] a.example   (Author)
[Document] brochure.pdf    ──> [Alias] a.example   (Author)
                           ──> <Office software version> (Producer)
```

#### หมายเหตุ
ผลนี้ใช้ปรับปรุงนโยบายล้าง Metadata ก่อนเผยแพร่เอกสาร

### 34.2 Command สำหรับ Metadata
```bash
sudo apt install -y libimage-exiftool-perl poppler-utils
mkdir -p ~/cases/$CASE/evidence/docs && cd ~/cases/$CASE/evidence/docs

# ดาวน์โหลดจากรายการ URL (ของเว็บไซต์ตนเอง)
wget -q -i ../../raw/doc-urls.txt

# Metadata ทุกไฟล์เป็น CSV
exiftool -csv -Author -Creator -Producer -CreateDate -ModifyDate *.pdf *.docx 2>/dev/null \
  > ../../raw/doc-metadata.csv
column -s, -t < ../../raw/doc-metadata.csv | head

# รายละเอียด PDF
pdfinfo report-2025.pdf

# Hash ของหลักฐาน
sha256sum * > SHA256SUMS
```

ล้าง Metadata ก่อนเผยแพร่ (ฝั่งป้องกัน):

```bash
exiftool -all= -overwrite_original brochure.pdf
```

---
## 35. Link Analysis

### 35.1 อ่าน Link อย่างไร
Link ใน Maltego บอกว่า "Entity B ได้มาจาก Entity A ผ่าน Transform/การกระทำใด" ไม่ได้บอกว่าความสัมพันธ์นั้นจริงแค่ไหน ต้องประเมินเอง

ระดับความเชื่อมั่นที่แนะนำ (ใส่ใน Link label หรือ Notes):

```
[H] High    ตรวจซ้ำได้ด้วยข้อเท็จจริงทางเทคนิค (DNS, Certificate SAN)
[M] Medium  มาจากฐานข้อมูลภายนอกที่เชื่อถือได้ (WHOIS, ASN, Passive DNS ล่าสุด)
[L] Low     การจับคู่ชื่อ/Username, ข้อมูลเก่า, แหล่งเดียว
```

### 35.2 ความสัมพันธ์ระหว่างประเภท Entity
```
Person ──works at──> Organization ──owns──> Domain
  │                                           │
  └──uses──> Email ──@domain──────────────────┘
               │
Username <──same handle──┘ [L]
                                   Domain ──DNS──> IP ──> AS (Infrastructure)
Website ──hosted on──> IP                          │
   └──tracking code──> Website อื่น [M]            └──> Netblock
```

### 35.3 ตัวอย่าง Graph และการอ่าน
```
example.com
    |
    +-- mail.example.com
    |        |
    |        +-- 203.0.113.25
    |
    +-- www.example.com
    |        |
    |        +-- 203.0.113.10
    |                 |
    |                 +-- AS64500
    |
    +-- dev.example.com
             |
             +-- 203.0.113.10   (IP เดียวกับ www)
```

การอ่าน:
1. `www` และ `dev` ใช้ IP เดียวกัน → อาจเป็น Server เดียวกัน (Virtual host)
2. `mail` อยู่ใน Netblock เดียวกันแต่คนละ IP → Infrastructure เดียวกัน
3. ทั้งหมดอยู่ใน AS64500 → ถ้า AS นี้เป็นขององค์กร แสดงว่า Host เอง

### 35.4 กฎการสรุป
- ความสัมพันธ์ 1 เส้น [L] = สมมติฐาน
- [L] หลายเส้นจากแหล่ง **อิสระ** ต่อกัน = น่าสงสัย ควรตรวจต่อ
- อย่างน้อย 1 เส้น [H] หรือหลายเส้น [M] = พอใส่ในรายงานพร้อมระบุระดับความเชื่อมั่น

---

## 36. Graph Analysis

> **หมายเหตุ:** ตำแหน่งปุ่มของแต่ละคำสั่งอาจแตกต่างกันตามเวอร์ชัน ส่วนใหญ่อยู่ใน Tab View, Organize, Investigate หรือเมนูคลิกขวา

### 36.1 การเคลื่อนที่
- **Zoom** — Scroll เมาส์, ปุ่ม Zoom in/out, **Zoom to Fit** เพื่อเห็นทั้ง Graph
- **Zoom to Selection** — ซูมไปยัง Entity ที่เลือก
- **Pan** — ลากพื้นที่ว่าง (ปุ่มเมาส์ที่ใช้ขึ้นกับเวอร์ชัน) หรือลากกรอบใน Overview

### 36.2 ค้นหาและเลือก
- **Search / Find** — พิมพ์ค่าเพื่อหา Entity (เช่น `203.0.113`)
- **Select by Type** — เลือก Entity ทุกตัวของประเภทเดียวกัน
- **Select Parents / Children / Neighbors** — เลือกตามความสัมพันธ์
- **Add Parents / Add Children** — ขยายการเลือกเพิ่มทีละชั้น
- **Invert Selection** — กลับการเลือก (ใช้ลบทุกอย่างที่ไม่ได้เลือก)

### 36.3 Filter, Sort, Group
- **Entity List view** — เรียงตาม Type, Value, Weight, จำนวน Link
- **Bubble View** — ขนาดตามจำนวน Link ช่วยหา Hub
- **Collection / Grouping** — Maltego รุ่นใหม่รวม Entity ประเภทเดียวกันที่เชื่อมแบบเดียวกันเป็น Collection node เมื่อจำนวนเกินค่าที่ตั้ง (ตั้งเกณฑ์ได้ใน View settings ขึ้นกับเวอร์ชัน)

### 36.4 Layout
| Layout | ใช้เมื่อ |
|---|---|
| Hierarchical | ดูลำดับการ Pivot จากบนลงล่าง |
| Organic | ดู Cluster ที่เกาะกลุ่ม |
| Circular | ดูว่า Entity กลุ่มหนึ่งเชื่อมกันอย่างไร |
| Block | เรียงให้เป็นระเบียบ อ่านชื่อง่าย |

เคล็ดลับ: เลือกเฉพาะบางส่วนแล้วสั่ง Layout เพื่อจัดเฉพาะส่วนนั้น (ถ้าเวอร์ชันรองรับ)

### 36.5 แก้ไข Graph
- **Remove Entity** — เลือกแล้วกด `Delete`
- **Copy Entity** — `Ctrl+C` แล้ว `Ctrl+V` ใน Graph อื่น
- **Connect Entity** — ลากจากขอบของ Entity หนึ่งไปอีกตัวเพื่อสร้าง Link ด้วยมือ แล้วตั้งชื่อ Link
- **Merge** — รวม Entity ที่ซ้ำกัน (ถ้ามีคำสั่งนี้ในเวอร์ชันของคุณ)
- **View Properties** — Property View
- **View Transform Results** — Detail View และ Output

### 36.6 Workflow: ทำ Graph ที่รกให้อ่านได้
#### เป้าหมาย
ลด Graph 1,500 Entity ให้เหลือเฉพาะส่วนที่ตอบคำถาม

#### ขั้นตอน
1. `Save As` เป็นไฟล์ใหม่ `...-clean.mtgl`
2. เปิด Bubble View หา Hub (Entity ที่มี Link มาก)
3. ตรวจ Hub ที่เป็น Shared infrastructure (CDN, NS ของ Registrar, Privacy email) → ลบ Entity ลูกที่ได้จาก Hub เหล่านั้น
4. ลบ Leaf entity ที่ไม่มีประโยชน์ (หรือใช้ Machine `Prune Leaf Entities` ถ้ามี)
5. ใช้ Bookmark สีจัดลำดับความสำคัญ
6. สั่ง Layout Hierarchical

#### ผลลัพธ์
Graph เหลือไม่กี่สิบถึงร้อย Entity ที่อธิบายได้ทุกเส้น

---

## 37. การเชื่อม Entity หลายประเภท

### 37.1 Pivot ข้ามประเภทที่ใช้บ่อย
```
Technical → Identity:  Domain → WHOIS → Email → Person
Identity → Technical:  Email → Domain → DNS → IP
Content  → Technical:  Document → Author(Alias) → Username → Website
Threat   → Technical:  Hash → Domain → IP → AS
```

### 37.2 Workflow: สร้าง Link ด้วยมือพร้อมที่มา
#### ขั้นตอน
1. ลากจาก Entity A ไป Entity B
2. ตั้ง Link label รูปแบบ `<ความสัมพันธ์> | <แหล่ง> | <ระดับ>` เช่น

```
same tracking ID | curl homepage 2026-09-25 | [M]
```

3. ใส่ Screenshot ใน Attachments ของ Entity B

#### หมายเหตุ
Link ที่สร้างด้วยมือต้องมีแหล่งที่มาเสมอ ไม่เช่นนั้นผู้อ่าน Graph จะแยกไม่ออกว่าอันไหนมาจาก Transform อันไหนมาจากการตีความ

---

## 38. การใช้ Transform หลายขั้นต่อเนื่อง

### 38.1 หลัก "ขยาย → คัด → ขยาย"
```
รอบ 1: ขยาย   Domain → DNS Name (ทั้งหมด)
รอบ 1: คัด    เก็บเฉพาะ DNS Name ที่ Resolve ได้
รอบ 2: ขยาย   DNS Name → IP
รอบ 2: คัด    ตัด IP ของ CDN
รอบ 3: ขยาย   IP → Netblock, AS
```

### 38.2 Workflow: Chain 4 ขั้นแบบควบคุมได้
#### ขั้นตอน
1. Domain `example.com` → `To DNS Name [Find common DNS names]`
2. **Select Children** ของ Domain → `To IP Address [DNS]`
3. Select by Type IPv4 → ตรวจ AS ด้วย `To AS number`
4. ลบ IP ที่อยู่ใน AS ของ CDN
5. IP ที่เหลือ → `To Netblock [Using natural boundaries]`
6. Save Graph เป็น Version ใหม่ทุกครั้งหลังขั้นใหญ่

#### ผลลัพธ์
Chain ที่ทุกชั้นมีแต่ Entity ที่เกี่ยวข้อง ไม่มี Noise จากผู้ให้บริการ

---

## 39. การสร้าง Investigation Workflow

### 39.1 Template ของ Workflow
```
ชื่อ:        <Workflow name>
คำถาม:       <คำถามที่ต้องตอบ>
Input:       <Entity type + ตัวอย่าง>
ขอบเขต:      <Domain/IP/บุคคลที่อนุญาต>
ขั้นตอน:      1..n (Transform + การคัด)
จุดหยุด:      <เงื่อนไขที่หยุดขยาย>
Output:      <Graph, CSV, Report>
Provider/API: <รายการ + Quota ที่คาดว่าใช้>
```

### 39.2 เก็บ Workflow เป็นไฟล์ใน Case
```bash
cat > ~/cases/$CASE/notes/workflow-domain.md << 'EOF'
ชื่อ: Domain Recon v1
คำถาม: Infrastructure สาธารณะของ example.com อยู่ที่ไหน
Input: Domain example.com
ขั้นตอน: NS, MX, common DNS → IP → AS/Netblock
จุดหยุด: ไม่ขยาย IP ที่อยู่ใน AS ของ CDN
Output: 01-domain-recon.mtgl, infra.csv, infra.png
EOF
```

Workflow ที่ใช้ซ้ำบ่อยควรแปลงเป็น Machine (บทถัดไป)

---

## 40. Maltego Machines

### 40.1 ส่วนประกอบของ Machine
- **Input** — Entity เริ่มต้น (Machine กำหนดว่ารับประเภทใด)
- **Transforms** — ลำดับ Transform ที่รัน
- **Filters** — เงื่อนไขกรอง Entity ระหว่างทาง (รวมถึงให้ผู้ใช้เลือกเอง)
- **Output** — Entity ทั้งหมดที่เกิดใน Graph

### 40.2 Run Machine และตรวจผล
1. คลิกขวา Entity → Run Machine → เลือก Machine
2. หน้าต่าง Run View แสดงขั้นที่กำลังทำ
3. ถ้า Machine มีขั้น "ให้ผู้ใช้เลือก" จะมีหน้าต่างให้ติ๊กเลือก Entity ที่ต้องการไปต่อ
4. เมื่อจบ ตรวจ Output window ว่ามี Transform ใด Error
5. หยุดกลางทาง: ปุ่ม Stop ใน Run View (หรือคำสั่ง Stop all machines ถ้ามี)

### 40.3 สร้าง Machine ใหม่
1. เปิดเมนู New Machine (Tab Machines หรือ Manage Machines ขึ้นกับเวอร์ชัน)
2. ตั้งชื่อ, ID (เช่น `local.DomainToInfra`), คำอธิบาย
3. เลือก Template: แบบ Macro (รันครั้งเดียว) หรือแบบ Timer (รันซ้ำตามรอบ)
4. เขียนสคริปต์ด้วย MSL (Maltego Scripting Language)
5. Save แล้วทดสอบกับ `example.com`

### 40.4 หา Transform ID ก่อนเขียน MSL
MSL เรียก Transform ด้วย **ID** ไม่ใช่ชื่อที่เห็นในเมนู
1. เปิด Transform Manager
2. คลิก Transform เช่น `To IP Address [DNS]`
3. ดูค่า ID ในรายละเอียด แล้ว Copy มาใช้

### 40.5 ตัวอย่าง MSL: Domain → DNS → IP → ASN → Infrastructure
แทนที่ `<ID_...>` ด้วย Transform ID จริงจากเครื่องของคุณ:

```
machine("local.DomainToInfra",
        displayName:"Domain to Infrastructure (Lab)",
        author:"Analyst",
        description:"Domain -> DNS -> IP -> AS/Netblock") {
    start {
        status("Step 1: DNS names")
        paths {
            path { run("<ID_TO_DNS_NAME_NS>") }
            path { run("<ID_TO_DNS_NAME_MX>") }
            path { run("<ID_TO_DNS_NAME_COMMON>") }
        }
        status("Step 2: Resolve to IP")
        run("<ID_TO_IP_ADDRESS_DNS>")
        status("Step 3: Network context")
        paths {
            path { run("<ID_TO_AS_NUMBER>") }
            path { run("<ID_TO_NETBLOCK_NATURAL>") }
        }
        status("Done")
    }
}
```

คำอธิบาย:
- `start { }` — จุดเริ่ม
- `run()` — รัน Transform กับ Entity จากขั้นก่อนหน้า
- `paths { path{} path{} }` — แตกหลายเส้นทางแบบขนาน
- `status()` — ข้อความสถานะใน Run View

> **หมายเหตุ:** ไวยากรณ์และฟังก์ชันของ MSL (เช่น ตัวกรองและการให้ผู้ใช้เลือก Entity) ให้ตรวจจากเอกสาร MSL ของ Maltego รุ่นที่ใช้ หากบันทึกไม่ผ่าน ข้อความ Error จะบอกบรรทัดที่ผิด

### 40.6 ตัวอย่าง Machine: Email → Domain → Public Profiles
```
machine("local.EmailToProfiles",
        displayName:"Email to Public Profiles (Lab)",
        author:"Analyst",
        description:"Email -> Domain, Email -> Provider profile lookups") {
    start {
        paths {
            path { run("<ID_EMAIL_TO_DOMAIN>") }
            path { run("<ID_PROVIDER_EMAIL_TO_PROFILE>") }
        }
    }
}
```

ทดสอบด้วย `alice@example.com` ผลจะว่างเกือบทั้งหมด (เป็นค่าสมมติ) แต่ใช้ยืนยันว่า Machine รันครบทุกขั้นโดยไม่มี Error

---

## 41. การสร้าง Workflow แบบ Semi-Automated

### 41.1 แนวคิด
```
Kali (Script รวบรวมข้อมูล) → CSV → Maltego (Import + Transform + วิเคราะห์) → Export
```

ให้ Script ทำงานซ้ำ ๆ ส่วน Maltego ใช้วิเคราะห์ความสัมพันธ์

### 41.2 Script: Domain → CSV สำหรับ Import
```bash
cat > ~/bin/dns2csv.sh << 'EOF'
#!/usr/bin/env bash
# ใช้: dns2csv.sh example.com > out.csv
set -euo pipefail
D="$1"
echo "domain,record_type,value"
for t in NS MX A AAAA; do
  dig +short "$t" "$D" | sed 's/\.$//' | while read -r v; do
    [ "$t" = "MX" ] && v=$(echo "$v" | awk '{print $2}')
    echo "$D,$t,$v"
  done
done
EOF
chmod +x ~/bin/dns2csv.sh
~/bin/dns2csv.sh example.com | tee ~/cases/$CASE/raw/dns-example.csv
```

Import: Map `domain` → Domain, `value` → DNS Name หรือ IP (แยกไฟล์ตาม `record_type` จะ Map ง่ายกว่า)

### 41.3 จุดที่ต้องมีคนตัดสินใจ
- เลือกว่า Entity ใดอยู่ในขอบเขต
- ตัด Shared infrastructure
- ยืนยันความสัมพันธ์ระดับ [L]
- อนุมัติก่อนใช้ Transform ที่ใช้ Quota มาก

---

## 42. การใช้ API

### 42.1 Local Transform คืออะไร
Local Transform คือโปรแกรมบนเครื่องเรา ที่ Maltego เรียกโดยส่งค่า Entity เป็น Argument แล้วอ่านผลลัพธ์ XML จาก stdout ใช้เชื่อม API ที่ไม่มีใน Transform Hub

### 42.2 เขียน Local Transform ด้วย Python (ไม่ใช้ Library เพิ่ม)
```bash
mkdir -p ~/maltego-local && cat > ~/maltego-local/dns_to_ip.py << 'EOF'
#!/usr/bin/env python3
"""Local Transform: DNS Name -> IPv4 Address (ใช้ resolver ของเครื่อง)"""
import socket, sys
from xml.sax.saxutils import escape

def entity(etype, value):
    return (f'<Entity Type="{etype}"><Value>{escape(value)}</Value></Entity>')

name = sys.argv[1] if len(sys.argv) > 1 else ""
out, msgs = [], []
try:
    ips = sorted({ai[4][0] for ai in socket.getaddrinfo(name, None, socket.AF_INET)})
    out = [entity("maltego.IPv4Address", ip) for ip in ips]
except socket.gaierror as e:
    msgs.append(f'<UIMessage MessageType="PartialError">resolve failed: {escape(str(e))}</UIMessage>')

print("<MaltegoMessage><MaltegoTransformResponseMessage>"
      f"<Entities>{''.join(out)}</Entities>"
      f"<UIMessages>{''.join(msgs)}</UIMessages>"
      "</MaltegoTransformResponseMessage></MaltegoMessage>")
EOF
chmod +x ~/maltego-local/dns_to_ip.py
python3 ~/maltego-local/dns_to_ip.py example.com
```

ผลลัพธ์ที่ควรเห็น (รูปแบบ):

```
<MaltegoMessage><MaltegoTransformResponseMessage><Entities><Entity Type="maltego.IPv4Address"><Value>...</Value></Entity></Entities><UIMessages></UIMessages></MaltegoTransformResponseMessage></MaltegoMessage>
```

### 42.3 ลงทะเบียน Local Transform ใน Maltego
1. เปิดเมนู New Local Transform (มักอยู่ใน Tab Transforms)
2. ตั้ง Display name `DNS to IP (local)`, ID `local.DNSToIP`, Input entity = DNS Name
3. Command: `/usr/bin/python3`
4. Parameters: `/home/kali/maltego-local/dns_to_ip.py`
5. Working directory: `/home/kali/maltego-local`
6. Finish → ทดสอบกับ DNS Name `www.example.com`

### 42.4 Local Transform ที่เรียก API ภายนอก
หลักการ:
- อ่าน Key จาก Environment/ไฟล์ Config ห้าม Hard-code ใน Script
- จัดการ HTTP 401/403/429 แล้วส่งเป็น UIMessage ให้ผู้ใช้เห็น
- ตั้ง Timeout

```python
import os, json, urllib.request, urllib.error
KEY = os.environ.get("VT_API_KEY")  # หรืออ่านจาก ~/.config/osint/keys.env
if not KEY:
    raise SystemExit("VT_API_KEY not set")
req = urllib.request.Request(
    "https://www.virustotal.com/api/v3/domains/example.com",
    headers={"x-apikey": KEY})
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.load(r)
except urllib.error.HTTPError as e:
    print("HTTP", e.code)   # 401/403/429 -> ส่งเป็น UIMessage ใน Transform จริง
```

> **หมายเหตุ:** Maltego ที่เปิดจากเมนู Desktop อาจไม่เห็น Environment variable ที่ตั้งใน `.bashrc` ให้ Script อ่าน Key จากไฟล์ Config (`~/.config/osint/keys.env`) โดยตรงจะเสถียรกว่า

ถ้าต้องการ Framework สำหรับ Transform จำนวนมาก ดู Library `maltego-trx` (ติดตั้งด้วย `pip install maltego-trx`) และอ่านเอกสารของ Library รุ่นล่าสุด

---

## 43. การเพิ่ม Data Source

### 43.1 วิธีเพิ่ม Data Source ให้ Maltego
| วิธี | เหมาะกับ |
|---|---|
| ติดตั้ง Provider จาก Transform Hub | บริการที่มี Integration อยู่แล้ว |
| เพิ่ม Transform Seed | Transform server ภายในองค์กร |
| Local Transform | API/Script ของเราเอง |
| Import Graph from Table | ข้อมูลจากเครื่องมืออื่น (CSV/XLSX) |

### 43.2 Import Graph from Table แบบมี Link
ไฟล์ตัวอย่าง:

```bash
cat > ~/cases/$CASE/raw/host-ip.csv << 'EOF'
host,ip
www.example.com,203.0.113.10
mail.example.com,203.0.113.25
dev.example.com,198.51.100.20
EOF
```

ขั้นตอน:
1. Import | Export → Import Graph from Table
2. เลือกไฟล์ → ยืนยัน Header
3. คอลัมน์ `host` → DNS Name, คอลัมน์ `ip` → IPv4 Address
4. ขั้นกำหนด Link: สร้าง Link จาก `host` → `ip`
5. Finish

ผลลัพธ์: 3 คู่ DNS Name → IP พร้อม Link บน Graph

> **หมายเหตุ:** ขั้นตอนของ Wizard อาจแตกต่างกันตามเวอร์ชัน ถ้า Import แล้วไม่มี Link ให้ตรวจขั้นตอนการ Map Link อีกครั้ง

---

## 44. การจัดการ Credentials

### 44.1 หลักการ
- 1 Provider = 1 Key ต่อ Analyst (ไม่แชร์ Key ในทีม ถ้า Provider ไม่อนุญาต)
- เก็บ Key ในไฟล์สิทธิ์ `600` หรือ Password manager
- หมุนเวียน (Rotate) Key เมื่อสงสัยว่ารั่ว หรือเมื่อคนออกจากทีม
- ไม่ใส่ Key ใน Screenshot, Graph Notes, Report

### 44.2 ตรวจว่า Key หลุดในไฟล์ของ Case หรือไม่
```bash
grep -rInE '(api[_-]?key|apikey|token|secret)\s*[:=]' ~/cases/$CASE 2>/dev/null
```

### 44.3 Export/Import Config อย่างปลอดภัย
Maltego มีคำสั่ง Export Config (ไฟล์ `.mtz`) สำหรับย้าย Entity, Transform settings, Machine ไปเครื่องอื่น
- ก่อนแชร์ `.mtz` ให้ตรวจว่าไม่ได้เลือก Export ส่วนที่มี Credential
- ไฟล์ `.mtz` เป็น zip ตรวจเนื้อหาได้:

```bash
unzip -l my-config.mtz | head -50
unzip -p my-config.mtz | grep -aiE 'api.?key|token' | head
```

### 44.4 เมื่อ Key รั่ว
1. Revoke Key ที่หน้า Dashboard ของ Provider ทันที
2. สร้าง Key ใหม่ แล้วใส่ใน Maltego/ไฟล์ Config
3. ตรวจ Log การใช้งานของ Provider ว่ามีการใช้ผิดปกติหรือไม่
4. ลบ Key ออกจากไฟล์/Git history ที่หลุด

---

## 45. การ Export Graph

### 45.1 รูปแบบ Export
| ต้องการ | คำสั่ง (ชื่ออาจต่างตามเวอร์ชัน) | ไฟล์ |
|---|---|---|
| ภาพ Graph | Export Graph as Image | PNG/JPG/SVG |
| ตารางข้อมูล | Export Graph to Table | CSV/XLSX |
| รายงาน | Generate Report | PDF |
| ส่ง Graph ให้คนอื่นเปิด | Save As | `.mtgl` / `.mtgx` |
| ย้ายการตั้งค่า | Export Config | `.mtz` |

### 45.2 Workflow: Export ชุดส่งมอบ
#### ขั้นตอน
1. จัด Graph ให้อ่านได้ (บท 36)
2. Export ภาพ → `exports/infra.png`
3. Export ตาราง → `exports/infra.csv`
4. Generate Report → `exports/report.pdf`
5. Save As Graph สุดท้าย → `graphs/final.mtgl`
6. สร้าง Hash ของไฟล์ส่งมอบ

```bash
cd ~/cases/$CASE/exports
sha256sum * > SHA256SUMS
cat SHA256SUMS
```

### 45.3 ตรวจไฟล์ CSV ที่ Export
```bash
head -5 infra.csv
cut -d, -f1 infra.csv | sort | uniq -c | sort -rn   # นับตามคอลัมน์แรก (ปรับตามโครงสร้างจริง)
```

---

## 46. การบันทึกหลักฐาน

### 46.1 สิ่งที่ต้องบันทึกทุกครั้ง
- วันที่/เวลา (ระบุ Timezone)
- แหล่งข้อมูล (Transform/Provider/URL)
- ค่าที่ได้ (Screenshot หรือ Raw output)
- Hash ของไฟล์หลักฐาน
- ผู้บันทึก

### 46.2 Log การทำงานอัตโนมัติด้วย script
```bash
script -q -a ~/cases/$CASE/notes/terminal-$(date +%F).log
# ... ทำงานตามปกติ ...
exit
```

ทุกคำสั่งและผลลัพธ์ใน Terminal จะถูกบันทึกลงไฟล์

### 46.3 บันทึก Raw output พร้อม Timestamp
```bash
ev() { # ใช้: ev <ชื่อไฟล์> <คำสั่ง...>
  local f=~/cases/$CASE/raw/$(date -u +%Y%m%dT%H%M%SZ)-$1.txt; shift
  { echo "# cmd: $*"; echo "# utc: $(date -u)"; "$@"; } > "$f" 2>&1
  sha256sum "$f" >> ~/cases/$CASE/raw/SHA256SUMS
  echo "saved $f"
}
ev whois-example whois example.com
ev dig-mx dig MX example.com +short
```

### 46.4 หลักฐานใน Maltego
1. แนบ Screenshot ที่ Entity (Attachments)
2. ใส่ Notes: แหล่ง + เวลา UTC + ระดับความเชื่อมั่น
3. Save Graph แบบที่รวมไฟล์แนบ (ถ้าเวอร์ชันรองรับ)
4. เก็บ Hash ของไฟล์ Graph ในไฟล์ `SHA256SUMS`

---

## 47. การจัดระเบียบ Investigation

### 47.1 ระบบ Bookmark สี (ตัวอย่างข้อตกลงในทีม)
```
แดง    ต้องตรวจต่อ / สำคัญ
เขียว  ยืนยันแล้ว อยู่ในขอบเขต
เหลือง Shared infrastructure (CDN/Cloud/Registrar)
น้ำเงิน ข้อมูลจากการ Import ภายนอก
```

### 47.2 ข้อตกลงการตั้งชื่อ
```
Case folder : CASE-<ปี>-<ลำดับ>-<ชื่อสั้น>
Graph       : <ลำดับ>-<คำถาม>-<วันที่>.mtgl
Export      : <graph-name>-<ชนิด>.<ext>
Link label  : <ความสัมพันธ์> | <แหล่ง> | [H/M/L]
```

### 47.3 สำรองข้อมูล Case
```bash
tar czf ~/backup/$CASE-$(date +%F).tar.gz -C ~/cases $CASE
sha256sum ~/backup/$CASE-*.tar.gz
```

---
## 48. การทำ Case Study

ทุกกรณีเป็นสถานการณ์สมมติ ใช้ Reserved Domain/IP และชื่อสมมติทั้งหมด ผลลัพธ์ที่แสดงเป็นตัวอย่างโครงสร้าง ไม่ใช่ผลจริง

### 48.1 Case 1 — องค์กรสมมติ → Domain → Infrastructure
**สถานการณ์:** ทีม Security ของ "Example Corp" ต้องการรู้ Attack Surface สาธารณะก่อนทำ Pentest (มีหนังสืออนุญาตภายใน)

**ขั้นตอน:** Organization → Domain (`example.com`, `example.org`) → Workflow บท 13 → Subdomain บท 17 → IP → AS/Netblock บท 24

```
[Org] Example Corp
 ├── example.com
 │    ├── www.example.com    → 203.0.113.10  → AS64500 (Example Corp)
 │    ├── vpn.example.com    → 203.0.113.30  → AS64500
 │    └── old-crm.example.com → 192.0.2.50   → AS64502 (Cloud)   ← ไม่มีใน Asset list
 └── example.org → 198.51.100.40 → AS64501 (Hosting)
```

- **ข้อค้นพบ:** `old-crm.example.com` อยู่นอก Asset inventory และอยู่บน Cloud คนละผู้ให้บริการ
- **สิ่งที่เรียนรู้:** Graph ช่วยเทียบ "สิ่งที่มีจริง" กับ "สิ่งที่องค์กรคิดว่ามี" ส่งรายการ Host ที่ไม่มีเจ้าของให้ทีม IT ตรวจสอบ

### 48.2 Case 2 — Email สมมติ → Domain → Public Accounts
**สถานการณ์:** ทีม Awareness ต้องการประเมินว่า Email ของพนักงานตัวอย่าง `alice@example.com` เปิดเผยต่อสาธารณะแค่ไหน (พนักงานยินยอม)

**ขั้นตอน:** Email → Domain (บท 19.3) → Breach check (บท 31.2) → Username `alice_example` (บท 20) → ยืนยัน Profile ด้วยตนเอง

```
alice@example.com
 ├── example.com
 ├── [Breach] <ExampleServiceBreach>
 └── [Alias] alice_example
       ├── [URL] https://<service-1>/alice_example  (Bio ลิงก์ไป www.example.com) [M]
       └── [URL] https://<service-2>/alice_example  (ไม่มีตัวบ่งชี้ร่วม) [L] → ตัดออก
```

**สิ่งที่เรียนรู้:** Username เหมือนกันเพียงอย่างเดียวไม่พอยืนยันตัวตน ผลลัพธ์นำไปทำ Training และบังคับเปลี่ยนรหัสผ่านบริการที่รั่ว

### 48.3 Case 3 — Domain → Certificate → Related Hosts
**สถานการณ์:** SOC ได้รับรายงาน Phishing ที่ใช้ `secure-login.example.net`

**ขั้นตอน:** URL → Website → IP (บท 28) → ดึง Certificate (บท 18) → SAN → DNS Name อื่น → WHOIS วันที่จด (บท 16)

```
[Cert SHA256 12:34:...]
 ├── secure-login.example.net  → 198.51.100.77
 ├── account-verify.example.net → 198.51.100.77
 └── billing-update.example.org → 198.51.100.78
      (WHOIS: จดภายใน 3 วันก่อนเหตุการณ์ ทั้งสาม Domain)
```

**สิ่งที่เรียนรู้:** Certificate ใบเดียวเปิดเผย Domain หลอกลวงอีก 2 ตัวที่ยังไม่ถูกรายงาน นำไป Block เชิงรุก

### 48.4 Case 4 — IP → ASN → Netblock
**สถานการณ์:** Firewall log แสดงการ Scan จำนวนมากจาก `203.0.113.45` ทีมต้องการตัดสินใจว่าจะ Block ระดับ IP หรือ Netblock

**ขั้นตอน:** IP → `To AS number` → `To Netblock [Using natural boundaries]` → AS profiling (บท 27) → Threat Intel reputation (บท 29)

```
203.0.113.45 → 203.0.113.0/24 → AS64505 (<Hosting provider>)
                    └── IP อื่นใน /24 ที่ปรากฏใน Log: .46, .47, .60
```

**สิ่งที่เรียนรู้:** พบหลาย IP ในช่วงเดียวกัน แต่ AS เป็น Hosting ที่มีลูกค้าจำนวนมาก จึง Block เฉพาะ /24 ชั่วคราวและรายงาน Abuse contact ที่ได้จาก WHOIS แทนการ Block ทั้ง AS

### 48.5 Case 5 — Username → Public Profiles → Related Identity Indicators
**สถานการณ์:** โจทย์ CTF ให้ Username `demo_user01` และถามว่าผู้ใช้นี้ทำงานที่องค์กรใด (ข้อมูลในโจทย์สร้างขึ้นสำหรับการแข่งขัน)

**ขั้นตอน:** sherlock → Import URL (บท 20) → อ่าน Profile → พบลิงก์ Website → Website → Domain → WHOIS/หน้าเว็บ → Organization

```
[Alias] demo_user01
 └── [URL] <ctf-profile-page>
       └── bio: www.example.org
             └── example.org → หน้า About → [Org] Example Research Lab (flag)
```

**สิ่งที่เรียนรู้:** Maltego ใช้เป็น "กระดานความคิด" ได้ดีแม้ข้อมูลส่วนใหญ่มาจากการ Import และ Link ด้วยมือ

### 48.6 Case 6 — Metadata → Internal Naming Exposure
- **สถานการณ์:** ตรวจเอกสาร PDF 20 ไฟล์บนเว็บไซต์ของ `example.com` (องค์กรตนเอง)
- **ขั้นตอน:** บท 34 → Import Metadata → ดู Hub ใน Bubble View
- **ข้อค้นพบ:** Author 3 ค่าปรากฏในหลายเอกสาร ตรงกับรูปแบบ Username ภายใน (`a.example`) → เสนอให้ล้าง Metadata ก่อนเผยแพร่

---

## 49. Troubleshooting

### 49.1 Transform ไม่ทำงาน
- **อาการ:** คลิก Run แล้วไม่มีอะไรเกิดขึ้น หรือ Output แสดง Error
- **สาเหตุที่เป็นไปได้:** ไม่ได้ Login, Transform ถูกปิด, Provider ถูกถอน, Network
- **วิธีตรวจสอบ:** ดู Output window, ตรวจสถานะ Login, เปิด Transform Manager ดูว่า Transform เปิดอยู่

```bash
curl -sI https://www.maltego.com | head -1
find ~/.maltego -name "messages.log" 2>/dev/null | head -1 | xargs -r tail -n 50
```

- **วิธีแก้:** Login ใหม่, เปิด Transform, ติดตั้ง Provider ใหม่จาก Hub
- **ตัวอย่าง:** Output แจ้งว่า Transform server ไม่ตอบ → ทดสอบ curl ผ่าน → รีสตาร์ต Maltego แล้วรันใหม่

### 49.2 API Key ไม่ถูกต้อง
- **อาการ:** ข้อความ Unauthorized / Invalid key / 401
- **สาเหตุ:** Key ผิด, มีช่องว่างติดมา, Key ถูก Revoke, ใส่ผิดช่อง
- **วิธีตรวจสอบ:** ทดสอบ Key ด้วย curl (บท 12.4)

```bash
printf '%s' "$VT_API_KEY" | wc -c
curl -s -o /dev/null -w "%{http_code}\n" -H "x-apikey: $VT_API_KEY" \
  https://www.virustotal.com/api/v3/domains/example.com
```

- **วิธีแก้:** Copy Key ใหม่จาก Dashboard โดยไม่มีช่องว่าง ใส่ใหม่ใน Hub → Settings
- **ตัวอย่าง:** `wc -c` ได้มากกว่าความยาว Key จริง 1 ตัว → มี newline ติดมา

### 49.3 Provider unavailable
- **อาการ:** Transform server unavailable / Provider ไม่ตอบ
- **สาเหตุ:** Provider ล่ม, ปิดบริการ, เปลี่ยน Endpoint, Account ไม่มีสิทธิ์ Provider นั้นแล้ว
- **วิธีตรวจสอบ:** ดูหน้า Status ของ Provider, ดูว่า Tile ใน Hub ยังอยู่หรือไม่

```bash
curl -s -o /dev/null -w "%{http_code} %{time_total}s\n" https://<provider-api-host>/
```

- **วิธีแก้:** รอ, อัปเดต Provider ใน Hub, หา Data Source ทดแทน
- **ตัวอย่าง:** Tile หายจาก Hub หลังอัปเดต → Provider ถูกถอดจาก Hub ต้องใช้ Local Transform เรียก API แทน (บท 42)

### 49.4 Rate limit
- **อาการ:** 429 / Too many requests / ผลลัพธ์ขาดหายเมื่อรันกับ Entity จำนวนมาก
- **สาเหตุ:** ส่งคำขอเร็วเกิน Plan
- **วิธีตรวจสอบ:** รันกับ Entity ตัวเดียว ถ้าผ่าน แสดงว่าเป็นเรื่องปริมาณ

```bash
curl -s -D - -o /dev/null -H "x-apikey: $VT_API_KEY" \
  https://www.virustotal.com/api/v3/domains/example.com | grep -iE '^(HTTP|retry-after|x-ratelimit)'
```

- **วิธีแก้:** แบ่งรันทีละกลุ่ม, รอตาม `Retry-After`, ลดจำนวน Entity ที่เลือก
- **ตัวอย่าง:** เลือก 300 IP รันพร้อมกันแล้วได้ผล 40 → แบ่งเป็น 8 รอบ รอบละ 40

### 49.5 Graph ไม่แสดงผล
- **อาการ:** Graph ว่าง, Entity หายหลัง Layout, หน้าต่างเป็นสีเทา
- **สาเหตุ:** Zoom อยู่นอกพื้นที่, Filter ซ่อน Entity, ปัญหา Java/Graphics, หน่วยความจำไม่พอ
- **วิธีตรวจสอบ:** กด Zoom to Fit, สลับไป Entity List view ดูว่ามี Entity หรือไม่

```bash
free -h
echo $XDG_SESSION_TYPE
```

- **วิธีแก้:** Zoom to Fit, ล้าง Filter, ปิดโปรแกรมอื่นเพื่อคืน RAM, ถ้าใช้ Window manager แบบ Tiling ลองเปิดด้วย:

```bash
_JAVA_AWT_WM_NONREPARENTING=1 maltego &
```

- **ตัวอย่าง:** Entity List มี 500 Entity แต่ Main View ว่าง → Zoom to Fit แล้วเห็นทั้งหมด

### 49.6 Entity ไม่สามารถ Resolve ได้
- **อาการ:** `To IP Address [DNS]` คืน 0 ผลลัพธ์
- **สาเหตุ:** ชื่อไม่มี A record, มีแค่ AAAA/CNAME, พิมพ์ผิด, ใส่ `http://` หรือ `/` ปนมา
- **วิธีตรวจสอบ:**

```bash
dig www.example.com A +short
dig www.example.com AAAA +short
dig www.example.com CNAME +short
```

- **วิธีแก้:** แก้ค่า Entity ให้เป็น FQDN ล้วน, ใช้ Transform ที่รองรับ AAAA/CNAME
- **ตัวอย่าง:** ค่า Entity เป็น `https://www.example.com/` → แก้เป็น `www.example.com` แล้วรันใหม่ได้ผล

### 49.7 Transform คืนค่า 0 Results
- **อาการ:** Transform จบโดยไม่มี Error แต่ไม่มี Entity ใหม่
- **สาเหตุ:** ไม่มีข้อมูลจริง, ใช้ IP/ASN สำหรับเอกสาร, เพดานจำนวนผลลัพธ์, Stealth mode กรอง Transform, Provider ไม่มีข้อมูลของเป้าหมาย
- **วิธีตรวจสอบ:** ตรวจเทียบด้วย Command (`dig`, `whois`), ตรวจค่า Result limit, ตรวจ Privacy mode
- **วิธีแก้:** ลองกับ Domain/IP ที่มีข้อมูลจริงและอยู่ในขอบเขต, เพิ่ม Result limit
- **ตัวอย่าง:** `203.0.113.10` → `To AS number` = 0 → ถูกต้อง เพราะเป็น TEST-NET

### 49.8 Login ไม่ได้
- **อาการ:** หน้า Login ค้าง, แจ้งรหัสผิด, แจ้ง License
- **สาเหตุ:** รหัสผ่านผิด, ยังไม่ยืนยัน Email, เวลาเครื่องคลาดเคลื่อน (ทำให้ TLS ล้มเหลว), Proxy/Firewall บล็อก
- **วิธีตรวจสอบ:**

```bash
timedatectl
curl -sI https://www.maltego.com | head -1
env | grep -i proxy
```

- **วิธีแก้:** Reset password ผ่านเว็บไซต์, ตั้งเวลาอัตโนมัติ `sudo timedatectl set-ntp true`, ตั้ง Proxy ใน Maltego ให้ตรงกับระบบ
- **ตัวอย่าง:** VM ถูก Suspend หลายวัน เวลาช้า → เปิด NTP แล้ว Login ผ่าน

### 49.9 Network Error
- **อาการ:** Timeout ทุก Transform
- **สาเหตุ:** ไม่มี Internet, Gateway ผิด, VPN ตัดการเชื่อมต่อ, Firewall ขาออก
- **วิธีตรวจสอบ:**

```bash
ip addr
ip route
ping -c 4 1.1.1.1
curl -sI https://www.maltego.com | head -1
```

- **วิธีแก้:** แก้ Network ของ VM (NAT/Bridged), ตรวจ VPN, ขอเปิด Port 443 ขาออก
- **ตัวอย่าง:** `ip route` ไม่มี default route → เปลี่ยน Network adapter ของ VM เป็น NAT แล้วต่อใหม่

### 49.10 DNS Resolution Error
- **อาการ:** ping IP ได้ แต่ชื่อ Domain ใช้ไม่ได้ Transform ที่ใช้ DNS ล้มหมด
- **สาเหตุ:** `/etc/resolv.conf` ผิด, DNS server ขององค์กรบล็อก
- **วิธีตรวจสอบ:**

```bash
cat /etc/resolv.conf
dig example.com
dig @1.1.1.1 example.com +short
nslookup example.com
```

- **วิธีแก้:** ถ้า `dig @1.1.1.1` ผ่านแต่ `dig` ปกติไม่ผ่าน → แก้ DNS server ใน NetworkManager (หรือตามนโยบายองค์กร)
- **ตัวอย่าง:** resolv.conf ชี้ไป DNS ของ VPN ที่ตัดไปแล้ว → เชื่อม VPN ใหม่หรือเปลี่ยน DNS

### 49.11 Permission Error
- **อาการ:** Save Graph ไม่ได้, Maltego เปิดไม่ขึ้นหลังเคยรันด้วย `sudo`
- **สาเหตุ:** ไฟล์ใน `~/.maltego` หรือโฟลเดอร์ Case เป็นของ root
- **วิธีตรวจสอบ:**

```bash
ls -la ~/.maltego | head
find ~/.maltego ~/cases ! -user $USER 2>/dev/null | head
```

- **วิธีแก้:** คืนสิทธิ์ แล้วอย่ารัน Maltego ด้วย sudo อีก

```bash
sudo chown -R $USER:$USER ~/.maltego ~/cases
```

- **ตัวอย่าง:** `find` แสดงไฟล์ของ root หลายไฟล์ → chown แล้วเปิดโปรแกรมได้ปกติ

### 49.12 Package Installation Error
- **อาการ:** `apt install maltego` ล้มเหลว, Dependency ไม่ครบ, dpkg ค้าง
- **สาเหตุ:** Repository ไม่ได้อัปเดต, `sources.list` ผิด, การติดตั้งก่อนหน้าค้าง
- **วิธีตรวจสอบ:**

```bash
cat /etc/apt/sources.list
sudo apt update
apt policy maltego
```

- **วิธีแก้:**

```bash
sudo dpkg --configure -a
sudo apt --fix-broken install
sudo apt update && sudo apt install -y maltego
```

- **ตัวอย่าง:** `apt policy maltego` ไม่พบ Candidate → `sources.list` ไม่มี Kali repository → แก้ตามเอกสารของ Kali แล้ว `apt update`

---

## 50. แนวทางใช้งานบน Kali Linux

เครื่องมือในบทนี้เป็นเครื่องมือเสริมบน Kali ไม่ใช่ส่วนหนึ่งของ Maltego ใช้เพื่อตรวจระบบ ตรวจยืนยันผล และเตรียมข้อมูลนำเข้า

### 50.1 ติดตั้งเครื่องมือเสริมทั้งหมดในครั้งเดียว
```bash
sudo apt update
sudo apt install -y dnsutils whois curl jq ipcalc \
  libimage-exiftool-perl poppler-utils amass sherlock theharvester spiderfoot recon-ng
```

### 50.2 เพิ่มหน่วยความจำให้ Maltego (Graph ใหญ่)
Maltego ที่เป็นแอป Java มักมีไฟล์ตั้งค่า JVM (เช่นไฟล์ `.conf` ในโฟลเดอร์ติดตั้ง) และบางเวอร์ชันตั้งค่าหน่วยความจำได้จากหน้า Options ของโปรแกรม

```bash
dpkg -L maltego | grep -E '\.conf$'
grep -n "Xmx" $(dpkg -L maltego | grep -E '\.conf$') 2>/dev/null
```

> **หมายเหตุ:** แก้ไฟล์ในโฟลเดอร์ติดตั้งต้องใช้ sudo และอาจถูกทับเมื่ออัปเดต ตั้งค่าไม่เกินประมาณครึ่งหนึ่งของ RAM เครื่อง

### 50.3 VM และ Snapshot
- ถ่าย Snapshot ก่อนอัปเดต Maltego หรือ Kali
- ใช้ VM แยกต่อ Case ที่อ่อนไหว
- ปิด Shared clipboard/folder ระหว่าง VM กับเครื่องหลักถ้าวิเคราะห์ IOC

### 50.4 Alias ที่ใช้บ่อย
```bash
cat >> ~/.bashrc << 'EOF'
alias dnsall='f(){ for t in A AAAA MX NS TXT SOA CAA; do echo "== $t"; dig +short $t $1; done; }; f'
alias ptr='dig -x'
alias asn='f(){ whois -h whois.cymru.com " -v $1"; }; f'
alias certinfo='f(){ echo | openssl s_client -connect $1:443 -servername $1 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName; }; f'
EOF
source ~/.bashrc
dnsall example.com
```

---

## 51. เปรียบเทียบ Maltego กับเครื่องมืออื่น

ไม่มีการจัดอันดับ แต่ละตัวเหมาะกับงานต่างกัน และใช้ร่วมกันได้ (ผลจากเครื่องมืออื่น Import เข้า Maltego เป็น CSV)

| เครื่องมือ | เหมาะกับ |
|---|---|
| Maltego | วิเคราะห์ความสัมพันธ์แบบ Graph, รวมหลาย Data Source ในที่เดียว |
| SpiderFoot | สแกน OSINT อัตโนมัติจำนวนมาก Module ผ่าน Web UI |
| Recon-ng | Framework แบบ Command line ที่มี Module และฐานข้อมูลในตัว |
| theHarvester | รวบรวม Email/Host/Subdomain จากแหล่งสาธารณะอย่างรวดเร็ว |
| Sherlock | ตรวจว่า Username มีอยู่บนเว็บไซต์ใดบ้าง |
| Amass | Subdomain enumeration และ Attack surface mapping เชิงลึก |

ตัวอย่างการเรียกใช้เบื้องต้น (Option เปลี่ยนตามเวอร์ชัน ตรวจด้วย `-h`):

```bash
spiderfoot -l 127.0.0.1:5001          # เปิด Web UI แล้วเข้า http://127.0.0.1:5001
recon-ng                              # เข้าสู่ Console
theHarvester -d example.com -b crtsh  # ใช้แหล่ง crt.sh
sherlock alice_example
amass enum -passive -d example.com
```

---

## 52. ตัวอย่าง Workflow แบบครบกระบวนการ

### 52.1 Workflow Catalog (10 Workflow)
ขั้นตอนละเอียดของแต่ละ Workflow อยู่ในบทที่อ้างถึง

```
WF-01 Domain Recon           Domain → DNS → Subdomain → IP → ASN → Certificate   (บท 13, 17, 18)
WF-02 Email Investigation    Email → Domain → Public Profiles → Related Infra    (บท 19, 20)
WF-03 Organization Recon     Org → Domain → Websites → Infra → Public Documents  (บท 22, 34)
WF-04 Infrastructure Mapping Domain → IP → ASN → Netblock → Related Infra        (บท 24–27)
WF-05 Username Investigation Username → Public Profiles → Websites → Aliases     (บท 20, 21)
WF-06 IOC Enrichment         IOC list → Resolve → ASN → Threat Intel → จุดร่วม    (บท 29)
WF-07 Phishing URL Triage    URL → Website → IP → WHOIS age → Cert SAN           (บท 28, 18, 16)
WF-08 Hash to Infrastructure Hash → Sandbox report → Domain/IP → ASN             (บท 30)
WF-09 Breach Exposure        Org emails → Breach names → มาตรการ                   (บท 31)
WF-10 Document Metadata      Website docs → Metadata → Author/Producer → Pattern  (บท 34)
WF-11 Mail Infra Mapping     Domain → MX/SPF/DMARC → Mail provider IP/ASN         (บท 19.2)
WF-12 Netblock Hygiene       Netblock → IP → PTR → Host inventory diff           (บท 26)
```

### 52.2 Workflow แบบครบกระบวนการ: External Attack Surface Review ของ example.com
#### เป้าหมาย
ส่งมอบแผนผัง Infrastructure สาธารณะ พร้อมรายการ Host ที่ต้องตรวจต่อ ภายใน 1 วันทำงาน

#### ขั้นตอน
**Phase 0 — เตรียม (15 นาที)**

```bash
CASE=CASE-2026-002-easr
mkdir -p ~/cases/$CASE/{graphs,exports,evidence,notes,raw}
script -q -a ~/cases/$CASE/notes/terminal.log
```

บันทึก Scope และหนังสืออนุญาตใน `notes/README.md` (บท 5.2)

**Phase 1 — รวบรวม (Kali)**

```bash
cd ~/cases/$CASE/raw
~/bin/dns2csv.sh example.com > dns.csv
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' \
  | sed 's/^\*\.//' | sort -u > subs-crtsh.txt
amass enum -passive -d example.com -o subs-amass.txt
cat subs-*.txt | sort -u > subs-all.txt
```

**Phase 2 — สร้าง Graph (Maltego)**

1. Graph `01-easr.mtgl` → Domain `example.com`
2. รัน Machine `local.DomainToInfra` (บท 40.5) หรือ Transform Set `Infra-Basic`
3. Import `subs-all.txt` เป็น DNS Name (บท 17.4) → `To IP Address [DNS]`

**Phase 3 — ขยายแบบควบคุม**

1. Select by Type IPv4 → `To AS number`
2. Bookmark เหลืองให้ IP ของ CDN/Cloud แล้วหยุดขยายสายนั้น
3. IP ขององค์กร → `To Netblock [Using natural boundaries]`
4. Website หลัก → Certificate SAN (บท 18)

**Phase 4 — วิเคราะห์**

1. Bubble View หา Hub
2. เทียบกับ Asset inventory (ข้อ 52.3)
3. Bookmark แดงให้ Host ที่ไม่อยู่ใน Inventory

**Phase 5 — ส่งมอบ**

Export ภาพ, CSV, Report แล้วทำ Hash (บท 45.2)

#### ตัวอย่าง
```
Input: example.com (Scope: example.com, 203.0.113.0/24)
```

#### ผลลัพธ์
```
example.com
 ├── www.example.com  → 203.0.113.10 → AS64500  [เขียว]
 ├── vpn.example.com  → 203.0.113.30 → AS64500  [เขียว]
 ├── cdn.example.com  → 198.51.100.5 → AS64510 (CDN) [เหลือง — หยุดขยาย]
 └── test.example.com → 192.0.2.50   → AS64502  [แดง — ไม่อยู่ใน Inventory]
```

#### หมายเหตุ
Transform ที่ใช้เป็น Standard Transforms (ไม่ต้องใช้ API Key) ส่วน Passive DNS/Certificate จาก Provider เสริมต้องมี Key และ Quota

### 52.3 เทียบกับ Asset Inventory
```bash
# inventory.txt = รายชื่อ Host ที่ทีม IT ลงทะเบียนไว้
comm -13 <(sort -u inventory.txt) <(sort -u subs-all.txt) > not-in-inventory.txt
wc -l not-in-inventory.txt
```

`comm -13` แสดงบรรทัดที่อยู่ในไฟล์ที่สองแต่ไม่อยู่ในไฟล์แรก คือ Host ที่พบจาก OSINT แต่ไม่มีในทะเบียน

---

## 53. Checklist สำหรับ OSINT Investigation

### 53.1 ก่อนเริ่ม
- [ ] มี Scope และหนังสืออนุญาต (หรือเป็น Lab/CTF/ระบบของตนเอง)
- [ ] สร้างโฟลเดอร์ Case และไฟล์ README
- [ ] ตรวจ Network, DNS, เวลาเครื่อง
- [ ] Login Maltego และตรวจ Provider/API Key ที่ต้องใช้
- [ ] เลือก Privacy mode ให้เหมาะกับงาน
- [ ] เปิด `script` บันทึก Terminal

### 53.2 ระหว่างทำ
- [ ] เริ่มจาก Transform ที่เป็นข้อเท็จจริง (DNS/WHOIS) ก่อน
- [ ] จำกัดจำนวนผลลัพธ์ต่อ Transform
- [ ] หยุดขยาย Shared infrastructure
- [ ] ตรวจซ้ำข้อเท็จจริงสำคัญด้วย Command
- [ ] ใส่ Notes, Bookmark, ระดับความเชื่อมั่น [H/M/L]
- [ ] Save As เป็น Version ใหม่หลังขั้นใหญ่
- [ ] ตรวจ Quota ของ API ที่ใช้

### 53.3 หลังจบ
- [ ] ทำ Graph ให้อ่านได้ (Layout, ลบ Noise)
- [ ] Export ภาพ, CSV, Report
- [ ] สร้าง SHA256SUMS ของหลักฐานและไฟล์ส่งมอบ
- [ ] ตรวจว่าไม่มี API Key ในไฟล์ส่งมอบ
- [ ] ตรวจว่าเก็บข้อมูลส่วนบุคคลเท่าที่จำเป็น
- [ ] สำรอง Case และกำหนดวันลบข้อมูลตามนโยบาย

---

## 54. สรุป Command และ Workflow ที่ใช้บ่อย

### 54.1 Linux Commands
```bash
uname -a                         # Kernel / สถาปัตยกรรม
cat /etc/os-release              # รุ่น Kali
free -h ; df -h ~                # RAM / Disk
apt policy maltego               # เวอร์ชันที่ติดตั้ง / ใน Repo
sudo apt update && sudo apt install -y maltego
maltego &                        # เปิดโปรแกรม
pgrep -af maltego                # ตรวจว่ารันอยู่
sudo chown -R $USER:$USER ~/.maltego
timedatectl                      # ตรวจเวลา (มีผลกับ TLS/Login)
sha256sum <file>                 # Hash หลักฐาน
```

### 54.2 DNS Commands
```bash
dig example.com +short
dig MX example.com +short
dig NS example.com +short
dig TXT example.com +short
dig TXT _dmarc.example.com +short
dig -x 203.0.113.10 +short
dig @1.1.1.1 example.com +short
dig +trace example.com
nslookup example.com
whois example.com
curl -s https://rdap.org/domain/example.com | jq .
```

### 54.3 Network Commands
```bash
ip addr
ip route
ping -c 4 1.1.1.1
curl -I https://example.com
curl -sIL https://example.com | grep -Ei '^(HTTP|location)'
whois 203.0.113.10
whois -h whois.cymru.com " -v 203.0.113.10"
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
ipcalc 203.0.113.0/24
```

### 54.4 Maltego Workflow
```
New Graph → Save (Case folder) → Add Entity → Run Transform
   → ดู Output → คัด Entity → Run Transform ถัดไป
   → Layout / Bookmark / Notes → Export → Hash
```

### 54.5 Entity Workflow
```
Domain
 ↓
DNS Name
 ↓
IP Address
 ↓
AS
 ↓
Netblock
```

```
Email Address → Domain → Alias/Username → URL (Profile) → Website
Hash → Domain/IP → AS → Netblock
Document → Author (Alias) → Organization
```

### 54.6 Transform Workflow
```
Domain   : To DNS Name - NS (name server)
           To DNS Name - MX (mail server)
           To DNS Name [Find common DNS names]
           To Website [Quick lookup]
           To Domain [Find other TLDs]
DNS Name : To IP Address [DNS]
IP       : To DNS Name [Reverse DNS]
           To Netblock [Using natural boundaries]
           To AS number
           To Location [city, country]
หลักการ   : ขยาย → คัด → ขยาย, เริ่มจาก Result limit ต่ำ
```

### 54.7 API Troubleshooting
```bash
set -a; source ~/.config/osint/keys.env; set +a       # โหลด Key
printf '%s' "$VT_API_KEY" | wc -c                     # ตรวจความยาว/ช่องว่าง
curl -s -o /dev/null -w "%{http_code}\n" -H "x-apikey: $VT_API_KEY" \
  https://www.virustotal.com/api/v3/domains/example.com
# 200 OK | 401 Key ผิด | 403 ไม่มีสิทธิ์ | 404 ไม่พบ | 429 Rate limit | 5xx Provider
curl -s -D - -o /dev/null <API_URL> | grep -iE 'retry-after|ratelimit'
env | grep -i proxy                                   # Proxy ต่างจาก Maltego หรือไม่
```

> **หมายเหตุ:** ผลลัพธ์ของ Transform ขึ้นอยู่กับ Data Source และสิทธิ์ของ Account ชื่อเมนูหรือหน้าตา UI อาจแตกต่างกันตามเวอร์ชันของ Maltego ตรวจสอบเอกสารทางการของ Maltego และของ Provider ทุกครั้งที่อัปเดต
