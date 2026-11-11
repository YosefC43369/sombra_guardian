# Broadcast — ตั้งลิงก์เดียว ยิงออกไปทุกห้อง/ทุกคนอัตโนมัติ

ใส่ **ลิงก์เดียว** แล้วบอตจะ **ยิงลิงก์นั้นออกไปยังห้องกลุ่ม/แชตคนอื่นหลายปลายทางเอง**
ตามรอบเวลาที่ตั้ง ไม่มีวันหยุด จนกว่าจะสั่งปิด ควบคุมผ่านคำสั่ง `/broadcast`

> ต่างจากโมดูล `autolink`: `autolink` โพสต์ลิงก์ **ในห้องที่สั่ง** ส่วน `broadcast`
> ยิงลิงก์ **ออกไปยังปลายทางอื่น** ตามทะเบียนที่สะสมไว้

---

## ⚠️ อ่านก่อนใช้ — ข้อจำกัดจริงของ Telegram (ไม่ใช่ข้อจำกัดของโมดูล)

- บอต **ส่งหาคน** ได้เฉพาะคนที่ **เคยกด Start / เคยทักบอตมาก่อน** เท่านั้น
  (Telegram ห้ามบอต DM คนแปลกหน้าที่ไม่เคยเริ่มแชต — ไม่มีทางข้าม)
- บอต **ส่งเข้ากลุ่ม/แชนเนล** ได้เฉพาะที่ **บอตเป็นสมาชิก** และมีสิทธิ์ส่งข้อความ
- ยิงถี่เกินไป/สแปม = ปลายทางรีพอร์ต แล้ว **บอตโดนแบนทั้งตัว** — โมดูลจึงมี throttle,
  ขั้นต่ำ interval, และดีฟอลต์ปิด เพื่อกันเผลอ

เพื่อสร้างรายชื่อปลายทางโดยไม่ต้องกรอกเอง เปิด `collect` ไว้ แล้วทุกห้อง/คนที่ทักบอต
จะถูกสะสมเข้าทะเบียนอัตโนมัติ

---

## เปิดใช้ครั้งแรก

1. หา user id ตัวเองด้วย `/id` แล้วตั้ง env:
   ```
   BROADCAST_OWNER_IDS=123456789        # หลายคนคั่น comma: 111,222
   ```
   รีสตาร์ตบอต (ไม่ตั้ง = คำสั่ง `/broadcast` ถูกล็อกไว้ ใช้ไม่ได้)
2. ตั้งลิงก์ + ความถี่ แล้วเปิด:
   ```
   /broadcast setlink https://mysite.com
   /broadcast interval 6h
   /broadcast on
   ```

---

## คำสั่งทั้งหมด (เฉพาะเจ้าของบอต)

| คำสั่ง | ความหมาย |
|---|---|
| `/broadcast setlink <url>` | ลิงก์เดียวที่จะยิง |
| `/broadcast interval <เวลา>` | ยิงทุก ๆ (`30m` `6h` `1d`) ขั้นต่ำ 60 วิ |
| `/broadcast message <ข้อความ>` | ข้อความนำหน้าลิงก์ (ว่าง = ล้าง) |
| `/broadcast template <ข้อความ>` | รูปแบบขั้นสูง ตัวแปร `{url}` `{label}` |
| `/broadcast on` · `/broadcast off` | เปิด/ปิดการยิงอัตโนมัติ |
| `/broadcast now` | ยิงทุกปลายทางเดี๋ยวนี้ |
| `/broadcast status` | สถานะ + จำนวนปลายทาง + รอบถัดไป + ตัวอย่างข้อความ |
| `/broadcast silent <on\|off>` | ส่งแบบเงียบ ไม่เด้งแจ้งเตือน |
| `/broadcast preview <on\|off>` | แสดง/ซ่อนพรีวิวลิงก์ |
| `/broadcast delay <ms>` | หน่วงระหว่างปลายทาง (กัน flood) ดีฟอลต์ 50ms |
| `/broadcast collect <on\|off>` | เก็บห้อง/แชตที่บอตเห็นอัตโนมัติ (ดีฟอลต์ on) |
| `/broadcast target add <chat_id\|@user\|t.me/..>` | เพิ่มปลายทางเอง |
| `/broadcast target del <chat_id\|@user>` | ลบปลายทาง |
| `/broadcast target list` | ดูปลายทางทั้งหมด (🤖=เก็บอัตโนมัติ ✋=เพิ่มเอง) |
| `/broadcast target mute <chat_id> <on\|off>` | พัก/เลิกพักปลายทาง |
| `/broadcast target clear` | ล้างปลายทางทั้งหมด |
| `/broadcast test <chat_id\|@user>` | ยิงทดสอบปลายทางเดียว |

---

## ตัวอย่าง

**โปรโมทเว็บเดียว ทุก 6 ชั่วโมง ไปทุกกลุ่มที่บอตอยู่**
```
/broadcast setlink https://mysite.com
/broadcast message 🔥 แวะชมเว็บเราได้เลย
/broadcast interval 6h
/broadcast on
```
ปลายทางสะสมเองจาก `collect` — ดูได้ด้วย `/broadcast target list`

**ข้อความแต่งเองด้วย template**
```
/broadcast template 📣 ลิงก์ประจำวัน ({label})\n{url}
```

**ยิงทันทีโดยไม่รอรอบ / ปิดชั่วคราว**
```
/broadcast now
/broadcast off
```

---

## กลไกความปลอดภัย (กันบอตโดนแบน)

- **ดีฟอลต์ปิด** — ต้อง `on` เองทุกครั้ง, และ `on` ไม่ได้ถ้ายังไม่มีลิงก์/ปลายทาง
- **throttle** ระหว่างปลายทาง + เคารพ `RetryAfter` (flood control) ของ Telegram
- **ล้างปลายทางตายอัตโนมัติ** — โดนบล็อก/เตะ/ห้องถูกลบ (Forbidden) ลบทันที,
  ส่งพลาดสะสมครบ 3 ครั้งก็ลบ
- **interval ขั้นต่ำ** 60 วินาที (ปรับด้วย env)
- จำกัดเฉพาะ **เจ้าของบอต** ใน `BROADCAST_OWNER_IDS`

---

## ตัวแปรสภาพแวดล้อม

| env | ดีฟอลต์ | ความหมาย |
|---|---|---|
| `BROADCAST_OWNER_IDS` | *(ต้องตั้ง)* | user id ที่คุมได้ คั่นด้วย comma/ช่องว่าง |
| `BROADCAST_DB` | `resource/broadcast.json` | ที่อยู่ไฟล์ข้อมูล |
| `BROADCAST_TICK` | `30` | ตรวจรอบทุกกี่วินาที |
| `BROADCAST_MIN_INTERVAL` | `60` | interval ขั้นต่ำ (วินาที) |
| `BROADCAST_MAX_TARGETS` | `5000` | เพดานจำนวนปลายทาง |
| `BROADCAST_MAX_FAILS` | `3` | ส่งพลาดกี่ครั้งติดจึงลบปลายทาง |

---

## โครงสร้างโมดูล

```
broadcast/
├── __init__.py    API หลัก + remember_chat (hook เก็บปลายทาง)
├── store.py       เก็บ config + ทะเบียนปลายทาง (atomic JSON, pure)
├── core.py        สิทธิ์เจ้าของ / due / render / parse ปลายทาง (pure)
├── loop.py        async loop ยิงออกทุกปลายทาง + ล้างตาย + RetryAfter
├── commands.py    handler /broadcast (เจ้าของบอตเท่านั้น)
└── README.md
```

ทดสอบ pure logic: `python -m unittest test_broadcast -v`

## การผูกเข้ากับ `app.py` (ต่อสายไว้ให้แล้ว)

```python
import broadcast

app.add_handler(CommandHandler("broadcast", broadcast.cmd_broadcast))   # main()

_start_background_task(app, "broadcast_task",                           # post_init
                       lambda: broadcast.broadcast_background_loop(app.bot))

broadcast.remember_chat(chat.id, title=..., ctype=chat.type)           # handle_message

# post_shutdown: เพิ่ม "broadcast_task" ในชุดที่ cancel
```
บอต validate ตอนบูตด้วยว่าโมดูล `broadcast` มี API ครบ (`_REQUIRED_MODULE_API`)
