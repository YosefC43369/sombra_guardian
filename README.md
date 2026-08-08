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

## Troubleshooting

- **Bot ไม่ตอบ**: ตรวจสอบ `BOT_TOKEN` ใน Render Environment และดูว่า Service กำลัง Running
- **Bot ไม่เห็นข้อความ / ไม่มี `MESSAGE RECEIVED`**: ปิด Privacy Mode ผ่าน @BotFather ตามขั้นตอนด้านบน
- **พบคำต้องห้ามแต่ไม่ลบ**: ดู Log ว่ามี `DELETE ERROR` หรือไม่ → มักเกิดจากบอทยังไม่ได้เป็น Admin
- **Delete error: Forbidden**: บอทไม่ได้เป็น Admin หรือถูกถอดสิทธิ์ Delete Messages
- **Bot ไม่มี Permission**: ให้สิทธิ์ Delete Messages และ Restrict Members ในตั้งค่ากลุ่ม
- **Render Bot ไม่ทำงาน**: ตรวจสอบ Build/Start Command และดู Logs ว่า Error ตรงไหน
- **Conflict: terminated by other getUpdates request**: มีบอทตัวเดียวกันรันซ้ำสองที่ (เช่นรันในเครื่องพร้อมกับ Render) ให้ปิดตัวใดตัวหนึ่ง
