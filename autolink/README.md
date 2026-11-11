# AutoLink — ส่งลิงก์เว็บอัตโนมัติแบบตลอดเวลา

โมดูลสำหรับให้บอต **ส่งลิงก์เว็บเข้าห้องแชตเองอัตโนมัติ ตามรอบเวลาที่ตั้งไว้ ไม่มีวันหยุด**
จนกว่าจะสั่งหยุด ตั้งค่าและควบคุมทั้งหมดผ่านคำสั่ง `/autolink` ในห้อง (เฉพาะแอดมิน)

เหมาะกับ: โปรโมทเว็บ/ช่อง, ปล่อยลิงก์ชุดหนึ่งวนไปเรื่อย ๆ, เตือนลิงก์ประจำวัน/ประจำชั่วโมง

---

## แนวคิด

- **แคมเปญ (campaign)** = ชุดลิงก์ + รอบเวลา + โหมดการวน หนึ่งห้องมีได้หลายแคมเปญ
- บอตจะตรวจทุก ๆ ไม่กี่วินาที ถ้าแคมเปญไหน "ถึงรอบ" ก็ยิงลิงก์ถัดไปทันที แล้วนับรอบใหม่
- ทำงาน **ตลอดเวลา** อยู่ในลูปเบื้องหลัง เริ่มเองตอนบอตบูต และปิดสะอาดตอนบอตปิด

---

## คำสั่งทั้งหมด

> คำสั่งที่ "เปลี่ยนค่า" ต้องเป็น **แอดมินของห้อง** เท่านั้น · `list` / `show` ใครก็ดูได้

| คำสั่ง | ความหมาย |
|---|---|
| `/autolink add <ช่วงเวลา> <url> [url2 ...]` | สร้างแคมเปญใหม่ พร้อมลิงก์ตั้งต้น |
| `/autolink list` | ดูแคมเปญทั้งหมดในห้อง + รอบถัดไป |
| `/autolink show <id>` | ดูรายละเอียดแคมเปญ + รายการลิงก์ |
| `/autolink addurl <id> <url ...>` | เพิ่มลิงก์เข้าแคมเปญ |
| `/autolink delurl <id> <ลำดับ>` | ลบลิงก์ตามลำดับที่เห็นใน `show` |
| `/autolink interval <id> <ช่วงเวลา>` | เปลี่ยนความถี่การส่ง |
| `/autolink mode <id> <sequential\|random\|single>` | โหมดการวนลิงก์ |
| `/autolink title <id> <ชื่อ>` | ตั้งชื่อแคมเปญ |
| `/autolink template <id> <ข้อความ>` | รูปแบบข้อความที่ส่ง (เว้นว่าง = ล้างกลับค่าเริ่มต้น) |
| `/autolink silent <id> <on\|off>` | `on` = ส่งแบบเงียบ ไม่เด้งแจ้งเตือน |
| `/autolink preview <id> <on\|off>` | `on` = แสดงพรีวิวลิงก์ (ดีฟอลต์ on) |
| `/autolink jitter <id> <ช่วงเวลา>` | สุ่มหน่วงเพิ่ม 0–ค่านี้ ต่อการส่ง (กันดูเป็นบอท) |
| `/autolink pause <id>` | หยุดแคมเปญชั่วคราว |
| `/autolink resume <id>` | เล่นต่อ |
| `/autolink now <id>` | ส่งลิงก์ถัดไป **เดี๋ยวนี้** ทันที |
| `/autolink remove <id>` | ลบแคมเปญทิ้ง |
| `/autolink help` | แสดงวิธีใช้ |

### รูปแบบ "ช่วงเวลา"
`45s` = 45 วินาที · `30m` = 30 นาที · `2h` = 2 ชั่วโมง · `1d` = 1 วัน
**เลขเปล่า ๆ นับเป็นนาที** (เช่น `90` = 90 นาที) · ขั้นต่ำ 15 วินาที (ปรับได้ด้วย env)

### โหมดการวนลิงก์ (`mode`)
- **sequential** (ดีฟอลต์) — วนลิงก์ตามลำดับ 1→2→3→1→2…
- **random** — สุ่มลิงก์ทุกครั้ง
- **single** — ยิงลิงก์แรกซ้ำตลอด (เหมาะกับโปรโมทลิงก์เดียว)

### template — ปรับแต่งข้อความ
ตัวแปรที่ใช้ได้: `{url}` `{label}` `{n}` `{total}` `{title}`
พิมพ์ `\n` เพื่อขึ้นบรรทัดใหม่ · ถ้าไม่ตั้ง label ระบบจะใช้ชื่อโดเมน (eTLD+1) ให้อัตโนมัติ

---

## ตัวอย่างการใช้งานจริง

**โปรโมทเว็บเดียว ทุก 3 ชั่วโมง แบบเงียบ ๆ**
```
/autolink add 3h https://mysite.com
/autolink mode 1 single
/autolink silent 1 on
```

**วนลิงก์ 3 อัน ทุก 1 ชั่วโมง พร้อมข้อความสวย ๆ**
```
/autolink add 1h https://a.com https://b.com https://c.com
/autolink title 1 ช่องของเรา
/autolink template 1 📣 {title} ({n}/{total})\n{label}\n{url}
```
ผลที่ส่งออก:
```
📣 ช่องของเรา (1/3)
a.com
https://a.com
```

**ปล่อยลิงก์สุ่มทุก 30 นาที + สุ่มหน่วง 0–5 นาที กันดูเป็นบอท**
```
/autolink add 30m https://x.com https://y.com
/autolink mode 1 random
/autolink jitter 1 5m
```

**ดูสถานะ / หยุด / ยิงเดี๋ยวนี้**
```
/autolink list
/autolink pause 1
/autolink now 1
```

---

## การเก็บข้อมูล

- ไฟล์เดียว: `resource/autolink.json` (เปลี่ยน path ได้ด้วย env `AUTOLINK_DB`)
- เขียนแบบ atomic (temp + `os.replace` + `fsync`) — ไฟฟ้าดับกลางคันไฟล์ไม่พัง
- แยกข้อมูลตาม `chat_id` เก็บเฉพาะลิงก์/ตั้งค่า ไม่เก็บข้อมูลส่วนบุคคล

## ตัวแปรสภาพแวดล้อม (ไม่บังคับ)

| env | ดีฟอลต์ | ความหมาย |
|---|---|---|
| `AUTOLINK_DB` | `resource/autolink.json` | ที่อยู่ไฟล์ฐานข้อมูล |
| `AUTOLINK_TICK` | `15` | ตรวจรอบทุกกี่วินาที |
| `AUTOLINK_MIN_INTERVAL` | `15` | ช่วงเวลาขั้นต่ำที่ตั้งได้ (วินาที) |
| `AUTOLINK_MAX_CAMPAIGNS` | `50` | จำนวนแคมเปญสูงสุดต่อห้อง |
| `AUTOLINK_MAX_LINKS` | `200` | จำนวนลิงก์สูงสุดต่อแคมเปญ |

---

## โครงสร้างโมดูล

```
autolink/
├── __init__.py    เปิด API หลัก (cmd_autolink, autolink_background_loop)
├── store.py       ชั้นเก็บ JSON atomic (pure logic, เทสต์ได้)
├── engine.py      ตรรกะเวลา/เลือกลิงก์/ประกอบข้อความ (pure logic)
├── loop.py        background loop ที่ยิงลิงก์ตลอดเวลา (async)
├── commands.py    handler คำสั่ง /autolink ของ Telegram
└── README.md      เอกสารนี้
```

ทดสอบส่วน pure logic: `python -m unittest test_autolink -v`

---

## การผูกเข้ากับ `app.py` (ต่อสายไว้ให้แล้ว)

ต่อสายกับ `app.py` เรียบร้อยแล้ว ไม่ต้องทำอะไรเพิ่ม — ประกอบด้วย 4 จุด:

```python
import autolink                                    # ส่วน import

# ลงทะเบียนคำสั่ง (ใน main())
app.add_handler(CommandHandler(
    "autolink", lambda u, c: autolink.cmd_autolink(u, c, is_admin)))

# เริ่มลูปเบื้องหลัง (ใน post_init)
_start_background_task(app, "autolink_task",
                       lambda: autolink.autolink_background_loop(app.bot))

# ปิดสะอาดตอน shutdown (ใน post_shutdown) — เพิ่ม "autolink_task" ในชุดที่ cancel
```

บอตยัง validate ตอนบูตด้วยว่าโมดูล `autolink` มี API ครบ (`_REQUIRED_MODULE_API`)
กันกรณีไฟล์บนเซิร์ฟเวอร์อัปเดตไม่ครบแล้วพังกลางคำสั่ง
