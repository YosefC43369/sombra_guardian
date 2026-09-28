# Blue Team Suite — ตารางตั้งค่า (env) และข้อจำกัด

## Environment variables

อ่านผ่าน `envutil` (ค่าว่าง = ไม่ได้ตั้ง) ค่าเริ่มต้นปลอดภัยทั้งหมด

| ตัวแปร | ค่าเริ่มต้น | ความหมาย |
|--------|-----------|----------|
| `BLUETEAM_ENABLED` | `true` | kill switch หลัก — `false` = ทั้งชุดหยุดทำงาน |
| `BLUETEAM_LINKGUARD_ENABLED` | `true` | เปิด/ปิดโมดูล Link Guard (แยกขายเป็น tier) |
| `BLUETEAM_SCAMGUARD_ENABLED` | `true` | เปิด/ปิด Scam & Impersonation |
| `BLUETEAM_JOINGUARD_ENABLED` | `true` | เปิด/ปิด Join Guard / Anti-Raid |
| `BLUETEAM_EXTERNAL_ENABLED` | `false` | อนุญาตบริการภายนอก (VT/GSB/urlscan) ระดับโกลบอล — ต้อง opt-in ต่อกลุ่มด้วย |
| `BLUETEAM_ACTIVE_PROBE_ENABLED` | `false` | อนุญาต active probe ชั้น 3 (มี SSRF guard) — opt-in |
| `BLUETEAM_HMAC_SECRET` | (สุ่มต่อ DB) | คีย์ HMAC สำหรับ callback ด่านยืนยัน; ถ้าไม่ตั้ง จะสุ่มและเก็บใน `bt_meta` |
| `BLUETEAM_RETENTION_DAYS` | `90` | เก็บ event/cache/review นานกี่วัน |
| `BLUETEAM_CAMPAIGN_BUFFER` | `512` | ขนาด ring buffer SimHash ต่อกลุ่ม |
| `BLUETEAM_JOIN_BUFFER` | `512` | ขนาด ring buffer เหตุการณ์เข้ากลุ่มต่อกลุ่ม |
| `BLUETEAM_PROBE_CONCURRENCY` | `4` | งาน probe พร้อมกันสูงสุด |
| `BLUETEAM_PROBE_PER_HOST_RATE` | `1.0` | req/s ต่อโฮสต์สำหรับ probe |
| `BLUETEAM_PROBE_TIMEOUT_S` | `8.0` | timeout ต่อ hop |
| `BLUETEAM_PROBE_MAX_HOPS` | `5` | จำนวน redirect สูงสุด |
| `BLUETEAM_PROBE_MAX_BYTES` | `65536` | ขนาด body สูงสุดที่อ่าน (64KB) |
| `BLUETEAM_LINKCHECK_COOLDOWN_S` | `15` | คูลดาวน์ `/linkcheck` ต่อสมาชิก |
| `VIRUSTOTAL_API_KEY` / `GOOGLE_SAFEBROWSING_API_KEY` / `URLSCAN_API_KEY` | (ว่าง) | คีย์บริการภายนอก (ใช้เมื่อ opt-in เท่านั้น) |

การตั้งค่าต่อกลุ่ม (เปิด/ปิด/โหมด/เกณฑ์/ความไว) เก็บใน `bt_group_policy` ผ่านคำสั่งแอดมิน

## ข้อจำกัดที่ควรทราบ (Telegram Bot API)

* **ไม่มีอายุบัญชี/IP ของผู้ใช้**: Bot API ไม่ให้ข้อมูลวันที่สร้างบัญชีหรือ IP ดังนั้น
  Join Guard ใช้ **สัญญาณเชิงพฤติกรรมของกลุ่ม** (อัตราเข้า, ชื่อคล้ายกัน, ลิงก์เชิญเดียวกัน,
  churn) ไม่ใช่คุณสมบัติของบัญชีรายตัว
* **การระบุลิงก์เชิญจำกัด**: Telegram ให้ `invite_link` เฉพาะบางกรณี (บอทต้องเป็นแอดมิน
  และเห็นลิงก์นั้น) — ที่ไม่มีจะถือว่า UNAVAILABLE ไม่ใช่ "ไม่ได้ใช้ลิงก์"
* **ต้องเป็นแอดมินจึงจะลบ/จำกัดสิทธิ์ได้**: หากบอทไม่ใช่แอดมิน การกระทำจะกลายเป็น no-op
  ที่ log ไว้ (ระบบไม่พัง แต่ไม่มีผล)
* **callback_data ≤ 64 ไบต์**: ด่านยืนยันออกแบบให้ ~31 ไบต์ โดยเก็บ chat/user id ไว้ใน HMAC
* **`chat_member` ต้องเปิด**: ต้องรับ `Update.ALL_TYPES` (app.py ตั้งไว้แล้ว) มิฉะนั้น
  Join Guard จะไม่เห็นการเข้ากลุ่ม

## ความคาดหวังเรื่อง false positive

* คะแนนคือเครื่องมือจัดลำดับ ไม่ใช่ข้อพิสูจน์ — โหมดเริ่มต้นเป็น MONITOR/WARN (ไม่ลบ)
* ปรับ **ความไว** (relaxed/balanced/strict) และใช้ **allow-list วลี/โดเมน** เพื่อลด FP
* แอดมินและสมาชิกที่เชื่อถือได้รับการยกเว้น; สแกมเข้า **คิวตรวจสอบ** ให้มนุษย์ตัดสิน
* คาดหวังว่าจะมี FP บ้างในโหมด strict — แนะนำเริ่มที่ balanced แล้วปรับจากสถิติใน `/blueteam`
