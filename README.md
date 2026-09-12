# Telegram Group Moderation Bot

บอทดูแลกลุ่ม Telegram ขนาดเล็ก-กลาง: กรองคำต้องห้าม, ระบบ Warning, Mute/Unmute, Anti-Spam

## Features

- Forbidden Word Filter (ไทย/อังกฤษ) เปิด/ปิดได้ พร้อมจัดการรายการคำ
- Warning System (ค่าเริ่มต้น 3 Warning = Mute 10 นาที)
- Mute/Unmute ด้วยการ Reply ข้อความ รองรับเวลา `10s 10m 1h 1d`
- Basic Anti-Spam (ค่าเริ่มต้น 5 ข้อความ / 10 วินาที)
- ตรวจสอบสิทธิ์ Admin จริงผ่าน Telegram (ไม่ใช้ Username)
- Debug Log ละเอียดสำหรับ Render Logs

## Installation

```bash
git clone <your-repo-url>
cd <your-repo>
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env       # ใส่ BOT_TOKEN ของคุณ
python bot.py
```

## BotFather Setup

1. เปิดแชท [@BotFather](https://t.me/BotFather) → พิมพ์ `/newbot`
2. ตั้งชื่อบอทและ username ตามที่ต้องการ
3. คัดลอก Token ที่ได้ไปใส่ในไฟล์ `.env`
4. **สำคัญ**: พิมพ์ `/mybots` → เลือกบอท → `Bot Settings` → `Group Privacy` → กด `Turn off`
   (ถ้าไม่ปิด บอทจะอ่านได้เฉพาะคำสั่ง `/command` เท่านั้น จะไม่เห็นข้อความทั่วไปของสมาชิก)

## Telegram Group Setup

1. เพิ่มบอทเข้ากลุ่ม
2. ตั้งบอทเป็น Admin พร้อมสิทธิ์ **Delete Messages** และ **Restrict Members**
3. ทดสอบด้วย `/status` เพื่อยืนยันว่าบอทมีสิทธิ์ครบ

## Environment Variables

| ตัวแปร | ความหมาย |
|---|---|
| `BOT_TOKEN` | Token จาก @BotFather (ห้าม Commit ขึ้น GitHub) |

### ตัวแปรของระบบข้อมูลสมาชิก (ไม่ตั้งก็ใช้ค่าเริ่มต้นได้)

| ตัวแปร | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `MEMBER_RISK_WINDOW_SECONDS` | `604800` (7 วัน) | ช่วงเวลาที่ใช้คิดคะแนนความเสี่ยง |
| `MEMBER_RISK_MEDIUM_MIN` | `30` | คะแนนขั้นต่ำของระดับ MEDIUM |
| `MEMBER_RISK_HIGH_MIN` | `70` | คะแนนขั้นต่ำของระดับ HIGH |
| `MEMBER_STORE_MESSAGE_CONTENT` | `true` | เก็บเนื้อหาข้อความเป็นหลักฐานหรือไม่ (ปิดได้เพื่อความเป็นส่วนตัว) |
| `MEMBER_EVIDENCE_CONTENT_MAX_CHARS` | `4000` | ความยาวเนื้อหาสูงสุดต่อหลักฐาน |
| `MEMBER_AUTO_INCIDENT` | `true` | เปิดเหตุการณ์อัตโนมัติเมื่อระบบตรวจพบ |
| `MEMBER_AUTO_INCIDENT_MIN_SEVERITY` | `medium` | ความรุนแรงขั้นต่ำที่เปิดเหตุการณ์อัตโนมัติ |
| `MEMBER_AUTO_INCIDENT_DEDUPE_SECONDS` | `900` | รวมเหตุการณ์ซ้ำประเภทเดียวกันในช่วงนี้เป็นเหตุการณ์เดียว |
| `MEMBER_PATTERN_WINDOW_SECONDS` | `3600` | ช่วงเวลาที่ใช้หากิจกรรมที่สัมพันธ์กัน |
| `MEMBER_PATTERN_MIN_ACCOUNTS` | `3` | จำนวนบัญชีขั้นต่ำที่ถือว่าเป็นรูปแบบ |
| `MEMBER_RETENTION_TIMELINE_DAYS` | `0` | วันเก็บไทม์ไลน์ (`0` = ไม่จำกัด) |
| `MEMBER_RETENTION_IDENTITY_DAYS` | `0` | วันเก็บประวัติตัวตน (`0` = ไม่จำกัด) |
| `MEMBER_RETENTION_JOIN_DAYS` | `0` | วันเก็บประวัติเข้า/ออก (`0` = ไม่จำกัด) |
| `MEMBER_RETENTION_RISK_SNAPSHOT_DAYS` | `90` | วันเก็บสแนปช็อตคะแนนความเสี่ยง |

## Render Deployment

1. Push โค้ดขึ้น GitHub
2. เข้า [Render](https://render.com) → `New` → `Background Worker` (ใช้ Long Polling ไม่ต้องเปิด Port)
3. เชื่อม GitHub Repository ที่สร้างไว้
4. ตั้งค่า Service:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python bot.py`
5. ไปที่ `Environment` → เพิ่ม `BOT_TOKEN` = token ของคุณ
6. กด `Deploy`
7. เปิดแท็บ `Logs` → ต้องเห็น `BOT STARTING`, `DATABASE: OK`, `HANDLERS: OK`, `POLLING: STARTED`
8. ทดสอบส่ง `/start` ในกลุ่ม

## Commands

| คำสั่ง | สิทธิ์ | คำอธิบาย |
|---|---|---|
| `/start`, `/help` | ทุกคน | ข้อมูลเบื้องต้น |
| `/status` | ทุกคน | สถานะบอทและสิทธิ์ |
| `/filter_on`, `/filter_off` | Admin | เปิด/ปิดตัวกรองคำ |
| `/addword <คำ>` | Admin | เพิ่มคำต้องห้าม |
| `/delword <คำ>` | Admin | ลบคำต้องห้าม |
| `/listwords` | ทุกคน | ดูรายการคำต้องห้าม |
| `/warnings` (Reply) | Admin | ดู Warning ของสมาชิก |
| `/resetwarn` (Reply) | Admin | รีเซ็ต Warning |
| `/mute 10m` (Reply) | Admin | Mute สมาชิก |
| `/unmute` (Reply) | Admin | ปลด Mute |

## ระบบข้อมูลสมาชิก / เหตุการณ์ / หลักฐาน

ช่วยผู้ดูแลตอบคำถามว่า **บัญชีใดทำอะไร เมื่อไร มีหลักฐานอะไร และผู้ดูแลดำเนินการอะไรต่อ**
โดยใช้เฉพาะข้อมูลที่ Telegram Bot API ให้บอทได้จริง

| คำสั่ง | สิทธิ์ | คำอธิบาย |
|---|---|---|
| `/member <User ID\|@user>` | Admin (ในกลุ่ม) | รายงานกิจกรรมสมาชิก (Reply ได้) |
| `/memberhistory <เป้าหมาย>` | Admin (ในกลุ่ม) | ประวัติ username / ชื่อที่แสดงที่สังเกตได้ |
| `/memberrisk [เป้าหมาย]` | Admin (ในกลุ่ม) | คะแนนความเสี่ยงพร้อมเหตุผล (ไม่ระบุ = อันดับในกลุ่ม) |
| `/timeline <เป้าหมาย> [จำนวน]` | Admin (ในกลุ่ม) | ไทม์ไลน์เหตุการณ์เรียงตามเวลา |
| `/incidents [open\|สถานะ\|ประเภท]` | Admin (ในกลุ่ม) | รายการเหตุการณ์ |
| `/incident <id>` | Admin (ในกลุ่ม) | รายงานเหตุการณ์เต็ม + หลักฐาน + chain of custody |
| `/incident <id> status <สถานะ>` | Admin (ในกลุ่ม) | เปลี่ยนสถานะตาม lifecycle |
| `/incident <id> note\|case\|verify` | Admin (ในกลุ่ม) | เพิ่มโน้ต / เชื่อม Case / ตรวจหลักฐานทั้งหมด |
| `/incident open <CATEGORY> [SEVERITY]` | Admin (ในกลุ่ม) | เปิดเหตุการณ์เอง (Reply ข้อความ) |
| `/evidence <id>\|list\|capture` | Admin (ในกลุ่ม) | คลังหลักฐาน (`capture` ใช้ Reply) |
| `/verifyevidence <id>` | Admin (ในกลุ่ม) | ตรวจ SHA-256 ว่าบันทึกหลักฐานถูกแก้ไขหรือไม่ |
| `/memberreport <เป้าหมาย> [json\|csv]` | Admin (ในกลุ่ม) | รายงาน / ส่งออกเป็นไฟล์ |
| `/memberreport audit [ชม.]` | Admin (ในกลุ่ม) | รายงานการดำเนินการของผู้ดูแล |
| `/memberpatterns [นาที] [บัญชี]` | Admin (ในกลุ่ม) | กิจกรรมที่สัมพันธ์กัน (ต้องตรวจสอบเพิ่ม) |
| `/memberpurge [run\|forget <เป้าหมาย>]` | Admin (ในกลุ่ม) | ดู/บังคับใช้นโยบายการเก็บข้อมูล |

**ทุกคำสั่งใช้ได้เฉพาะผู้ดูแลจริงของกลุ่มนั้น และใช้ในกลุ่มเท่านั้น** — ข้อมูลแยกตามกลุ่ม
ผู้ดูแลกลุ่ม A อ่านเหตุการณ์/หลักฐานของกลุ่ม B ไม่ได้แม้จะเดาหมายเลขถูก

### ต้องตั้งค่าใน Telegram เพิ่ม

- บอทต้องเป็น **ผู้ดูแลกลุ่ม** เพื่อรับเหตุการณ์ `chat_member` (เข้า/ออก/แบน) — ถ้าไม่เป็น
  จะไม่เห็นการเข้า-ออกของสมาชิกและไม่มีข้อมูลลิงก์เชิญเลย
- ต้องปิด **Group Privacy** ตามขั้นตอนด้านบน ไม่งั้นบอทเห็นแค่คำสั่ง `/command`

### รายงานแยก 4 ส่วนเสมอ

ทุกรายงานแยกให้ชัดว่าอะไรคืออะไร ไม่ปนกัน:

1. **ข้อเท็จจริงที่สังเกตได้** — สิ่งที่บอทได้รับจาก Telegram จริง หรือทำเอง
2. **การวิเคราะห์ของระบบ** — คะแนน/ระดับ/การจัดประเภท (ผู้ดูแลไม่เห็นด้วยได้)
3. **การดำเนินการของผู้ดูแล** — ทำอะไรไปแล้ว โดยใคร
4. **ข้อจำกัด / ข้อมูลที่ไม่มี** — สิ่งที่ระบบนี้รู้ไม่ได้ (มีทุกรายงาน ไม่มีการละ)

### สิ่งที่ระบบนี้ทำไม่ได้ (Telegram Bot API ไม่ให้)

- **ไม่มี IP address** — Bot API ไม่เคยให้ IP ของผู้ใช้ ระบบนี้จึงไม่เก็บและไม่เดา
- ไม่มีเบอร์โทร อีเมล ข้อมูลอุปกรณ์ เวอร์ชันแอป ข้อมูลเซสชัน/การเข้าสู่ระบบ cookie หรือ token
- ไม่มีรายชื่อสมาชิกทั้งกลุ่ม และไม่รู้ว่าผู้ใช้อยู่กลุ่มอื่นใด
- ไม่มีข้อมูลย้อนหลังก่อนบอทเข้ากลุ่ม หรือช่วงที่บอทไม่ได้เป็นผู้ดูแล
- **ข้อมูลลิงก์เชิญมีเฉพาะบางกรณี** ที่ Telegram ส่งมา — ไม่มีข้อมูลลิงก์ ≠ ไม่ได้ใช้ลิงก์
- ไม่ยืนยันตัวตนในโลกจริงของเจ้าของบัญชี
- **คะแนนความเสี่ยงไม่ใช่ข้อพิสูจน์** — เป็นเครื่องมือจัดลำดับการตรวจสอบเท่านั้น
- **รูปแบบที่คล้ายกันไม่ใช่ข้อพิสูจน์ว่าเป็นคนเดียวกัน** — ระบบไม่สรุปเรื่องนี้ให้
- แฮช SHA-256 บอกว่า "บันทึกถูกแก้ไขหรือไม่" ไม่ได้บอกว่าใครสร้างเนื้อหา
- ไฟล์สื่อเก็บเฉพาะ `file_unique_id` + metadata ไม่ได้ดาวน์โหลดตัวไฟล์มาเก็บ

## Gemini AI

แท็กชื่อบอท (เช่น `@ชื่อบอทของคุณ`) ตามด้วยคำถามในแชท บอทจะส่งข้อความไปถาม Gemini แล้วตอบกลับในแชทเดียวกัน เช่น:

`@ชื่อบอทของคุณ วันนี้อากาศเป็นอย่างไร`

**หมายเหตุ**: การถามผ่านการแท็กจะไม่ผ่านระบบ Anti-Spam เดิม (ทำงานแบบเดียวกับ Auto-Reply Trigger) หากมีคนแท็กถามรัว ๆ อาจใช้โควตา Gemini API สูงกว่าที่ตั้งใจไว้ — ถ้าต้องการจำกัดสามารถแจ้งให้ทำเพิ่มได้

## Troubleshooting

- **Bot ไม่ตอบ**: ตรวจสอบ `BOT_TOKEN` ใน Render Environment และดูว่า Service กำลัง Running
- **Bot ไม่เห็นข้อความ / ไม่มี `MESSAGE RECEIVED`**: ปิด Privacy Mode ผ่าน @BotFather ตามขั้นตอนด้านบน
- **พบคำต้องห้ามแต่ไม่ลบ**: ดู Log ว่ามี `DELETE ERROR` หรือไม่ → มักเกิดจากบอทยังไม่ได้เป็น Admin
- **Delete error: Forbidden**: บอทไม่ได้เป็น Admin หรือถูกถอดสิทธิ์ Delete Messages
- **Bot ไม่มี Permission**: ให้สิทธิ์ Delete Messages และ Restrict Members ในตั้งค่ากลุ่ม
- **Render Bot ไม่ทำงาน**: ตรวจสอบ Build/Start Command และดู Logs ว่า Error ตรงไหน
- **Conflict: terminated by other getUpdates request**: มีบอทตัวเดียวกันรันซ้ำสองที่ (เช่นรันในเครื่องพร้อมกับ Render) ให้ปิดตัวใดตัวหนึ่ง
