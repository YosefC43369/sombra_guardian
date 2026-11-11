# Group Security Intelligence (GSI)

ชั้น **ข่าวกรองความปลอดภัยระดับกลุ่ม** ที่ "เสริม" ระบบป้องกันเดิมของบอต ไม่ได้มาแทน
เฝ้าระวังโครงแอดมิน, ความครบถ้วนของคอนฟิกกลุ่ม, ลิงก์เชิญ, ข้อมูลลับที่หลุด,
ข้อความหลอกลวง (social engineering), รวมเหตุการณ์เป็น incident, เก็บ audit trail
ที่ตรวจการแก้ไขได้ และช่วย backup/กู้คืนการตั้งค่า — ทั้งหมดผ่านคำสั่ง `/security_*`

> **ขอบเขตตามความจริงของ Telegram Bot API:** โมดูลนี้ใช้เฉพาะข้อมูลที่ Bot API เปิดให้
> **ไม่** อ้างว่าเห็น session/อุปกรณ์/IP/กิจกรรมบัญชีส่วนตัวของผู้ใช้ และตรวจคอนฟิก
> บางอย่างได้แค่ "ตามรอบ snapshot" (ช้ากว่าการเปลี่ยนจริง) เพราะ Bot API ไม่ push ทุกเหตุการณ์

---

## ของเดิมที่ reuse (ไม่สร้างซ้ำ)

| ใช้ของเดิม | เพื่อ |
|---|---|
| `integrity_ledger.record_event` | ยึด audit ลง Merkle hash-chain ที่ตรวจการแก้ไขได้ (tamper-evident) |
| `gemini.ask_gemini` | ความเห็นที่สองของ AI สำหรับ social engineering (ออปชัน, redact ก่อนส่ง) |
| `is_admin` (app.py) | ตรวจสิทธิ์แอดมิน "จริง" ของกลุ่ม ไม่เชื่อ id ที่พิมพ์เอง |
| `on_chat_member_update` (app.py) | รับ event เลื่อน/ลดขั้นแอดมิน + ลิงก์เชิญที่ติดมากับการ join |
| ช่องแจ้งเตือนเข้า group | ส่ง alert ตาม convention เดิม (`sg_platform._send_admin_alert`) |

**ไม่ซ้ำ** กับ anti-spam / moderation / member-incident / detection เดิม — คนละโดเมน
(member-incident = วินัยรายสมาชิก, GSI = ความปลอดภัยโครงสร้างกลุ่ม)

---

## คำสั่ง (แอดมินกลุ่มเท่านั้น)

| คำสั่ง | ทำอะไร |
|---|---|
| `/group_security` | แดชบอร์ดภาพรวม (ตั้ง baseline อัตโนมัติครั้งแรก) |
| `/security_audit` | audit ล่าสุด + สถานะ Merkle ledger |
| `/security_admins` | โครงแอดมิน + สิทธิ์สำคัญ + การเปลี่ยนแปลงล่าสุด (poll สด) |
| `/security_integrity` | สถานะความครบถ้วนคอนฟิก (NORMAL/CHANGED/SUSPICIOUS/REQUIRES_REVIEW) |
| `/security_invites` | ทะเบียนลิงก์เชิญ + สถานะ |
| `/security_secrets` | ข้อมูลลับที่พบ (แสดงแบบ redact เสมอ) |
| `/security_incidents` | incident ที่ correlate แล้ว |
| `/security_backup` | สร้าง backup การตั้งค่า |
| `/security_recovery` | จุดกู้คืน · `diff <id>` · `apply <id> <keys> confirm` |
| `/security_report` | รายงานความปลอดภัยรวมฉบับเต็ม |

ทุกคำสั่งเช็ค `is_admin` (สถานะ ADMINISTRATOR/OWNER จาก Telegram จริง) และใช้ได้เฉพาะในกลุ่ม

---

## 11 ความสามารถ ↔ ไฟล์

1. **เฝ้าระวังแอดมิน/สิทธิ์** — `monitor.diff_admins` / `diff_admin_transition` (เลื่อน/ลด/สิทธิ์เปลี่ยน, snapshot เทียบ baseline), event-driven ผ่าน `on_chat_member_update`
2. **ความครบถ้วนคอนฟิก** — `monitor.snapshot_config` / `diff_config` + สถานะ 4 ระดับ, poll ตามรอบ
3. **ข่าวกรองลิงก์เชิญ** — `monitor.diff_invites` + ทะเบียนเชื่อถือใน `service` (ไม่โชว์ลิงก์เต็มใน log)
4. **ตรวจข้อมูลลับ** — `detectors.scan_secrets` (รูปแบบ API key/token/private key/DB/`.env`...) + `redact` (ไม่เก็บ/ไม่ส่งต่อค่าจริง)
5. **Social engineering** — `detectors.analyze_social_eng` (วิเคราะห์เชิงบริบทหลายสัญญาณ + AI เสริมออปชัน) คืน category/score/confidence/เหตุผล/คำแนะนำ
6. **Correlation** — `correlate.correlate` (หน้าต่างเวลา, คะแนนรวม, ตรวจรูปแบบยึดกลุ่ม, ระดับ INFO..CRITICAL + เหตุผล)
7. **Audit trail** — `service.audit` → index เร็ว + `integrity_ledger` (ตรวจการแก้ไขได้, JSON export ผ่าน ledger)
8. **Backup & recovery** — `service.create_backup` / `recovery_diff` / `apply_recovery` (กู้เฉพาะ `title`/`description`/`permissions` ที่ Bot API รองรับจริง, ต้อง `confirm`)
9. **แดชบอร์ด** — `commands.cmd_group_security` ในอินเทอร์เฟซ Telegram เดิม
10. **คำสั่ง** — `commands.py` (10 คำสั่ง, ไม่ชนของเดิม)
11. **แจ้งเตือน** — `service.notify` (throttle + dedupe + ระดับขั้นต่ำ, ไม่โชว์ค่า secret เต็ม)

---

## การตั้งค่า (env, ไม่บังคับ — มีค่า default ทั้งหมด)

| env | default | ความหมาย |
|---|---|---|
| `GSI_DB` | `resource/group_security.json` | ไฟล์ข้อมูล |
| `GSI_TICK` | `120` | รอบลูป (วินาที) |
| `GSI_MAX_FINDINGS` / `_INCIDENTS` / `_AUDIT_INDEX` | 500/300/1000 | เพดานกันไฟล์บวม |

เกณฑ์ต่อกลุ่มปรับได้ผ่าน `store.set_policy` (ไม่ hardcode admin id/secret):
`notify_min_severity`, `notify_throttle_sec`, `snapshot_interval_sec`, `retention_days`,
`secret_scan`, `social_eng_scan`, `social_eng_use_ai`, `correlation_window_sec`,
`correlation_min_events`, `delete_detected_secrets` ฯลฯ

---

## การผูกกับ app.py (ต่อสายไว้ให้แล้ว)

```python
import group_security_intelligence as gsi

gsi.register_commands(app, is_admin)                              # main(): 10 คำสั่ง

_start_background_task(app, "gsi_task",                           # post_init: loop snapshot
                       lambda: gsi.background_loop(app.bot))

# handle_message (กลุ่ม): schedule ไม่บล็อก event loop
asyncio.create_task(gsi.on_message(context.bot, chat.id, user.id, text,
    username=user.username, message_id=message.message_id, delete_cb=_gsi_delete))

# on_chat_member_update: event แอดมิน + ลิงก์เชิญ
asyncio.create_task(gsi.on_admin_update(context.bot, chat.id,
    gsi.member_to_dict(old), gsi.member_to_dict(new), actor_id=...))

# post_shutdown: เพิ่ม "gsi_task" ในชุด cancel
# _REQUIRED_MODULE_API: เพิ่มรายการ "group_security_intelligence"
```

---

## ผลการทดสอบ

`python -m unittest test_group_security_intelligence -v` → **35/35 ผ่าน**
ครอบคลุม: ตรวจ+redact secret, social engineering เชิงบริบท, diff แอดมิน (เลื่อน/ลด/สิทธิ์),
integrity 4 ระดับ, invite diff (ไม่หลุดลิงก์เต็ม), correlation (รูปแบบยึดกลุ่ม/นอกหน้าต่าง),
audit, notify throttle, poll baseline→promotion, backup→recovery diff→apply, retention prune

รันรวมทั้ง repo: 861 ผ่าน (ที่ error คือ `telegram`/`pytest` ไม่ได้ติดตั้งใน env ทดสอบ — ไม่เกี่ยวกับโมดูลนี้)

---

## ข้อจำกัด (ตามความจริง Telegram Bot API)

- คอนฟิกหลายอย่างตรวจได้แค่ **ตามรอบ snapshot** ไม่ real-time (Bot API ไม่ push)
- เห็น **เฉพาะลิงก์เชิญที่ API เปิดให้** (ที่ติดมากับการ join หรือที่บันทึกเอง) — ไม่เห็นลิงก์ที่สร้างนอกสายตา
- กู้คืนได้เฉพาะ **title / description / permissions** — กู้ข้อความที่ถูกลบ/ประวัติ/ลิงก์ที่เพิกถอน/ข้อมูลบัญชีผู้ใช้ **ไม่ได้**
- audit ยึดด้วย Merkle hash-chain (`integrity_ledger`) — ตรวจการแก้ไขได้ แต่ **ไม่ใช่** storage ที่กันแก้ไขได้สมบูรณ์หากฐานข้อมูลเองถูกแทนที่
- ไม่เห็น session/อุปกรณ์/IP ของผู้ใช้ — และไม่อ้างว่าเห็น

## คำแนะนำด้านความปลอดภัย

- เปิด `delete_detected_secrets` เฉพาะกลุ่มที่บอตมีสิทธิ์ลบ และยอมรับ false positive ได้
- ตั้ง `notify_min_severity` ให้เหมาะ กันแจ้งเตือนล้น
- สร้าง `/security_backup` เป็นระยะ (เช่น หลังตั้งค่ากลุ่มเสร็จ) เพื่อมีจุดกู้คืน
- เปิด `social_eng_use_ai` เฉพาะเมื่อยอมให้ส่งข้อความไป AI provider (redact แล้ว) ตามนโยบายกลุ่ม
