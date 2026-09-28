# Blue Team Suite — คู่มือแอดมิน

> ทุกโมดูลเริ่มต้นแบบ **ปิด/เฝ้าระวัง** จนกว่าจะเปิดเอง การแบนถาวรต้องมีมนุษย์ยืนยันเสมอ

## เริ่มใช้งานเร็ว

```
/blueteam setup            # เปิดวิซาร์ด เลือก preset
/blueteam setup balanced   # ใช้ชุดค่า "สมดุล" กับกลุ่มนี้
/blueteam                  # ดูแดชบอร์ดสรุป 24 ชม.
/blueteam 7d               # สรุป 7 วัน
```

Preset: `starter` (เฝ้าระวังล้วน) · `balanced` (เตือน+ลบเสี่ยงสูง) · `strict` (ลบ+จำกัดสิทธิ์)

## /linkguard — ป้องกันลิงก์อันตราย

```
/linkguard status
/linkguard on | off
/linkguard mode MONITOR|WARN|DELETE|DELETE+RESTRICT
/linkguard threshold 70          # เกณฑ์คะแนน 0-100
/linkguard allow <domain>        # ยกเว้นโดเมน (มี audit)
/linkguard deny  <domain>        # บล็อกโดเมน
/linkguard list | history | stats | feed
```

`/linkcheck <url>` — สมาชิกใช้ได้ (จำกัดความถี่, ตอบเป็นข้อความส่วนตัว) แสดงระดับความเสี่ยง
เหตุผลสูงสุด 3 ข้อ และคำแนะนำ URL ถูก defang เพื่อกันเผลอกด

## /scamguard — สแกม & การปลอมตัว

```
/scamguard status | on | off
/scamguard mode MONITOR|WARN|DELETE|DELETE+RESTRICT
/scamguard sensitivity relaxed|balanced|strict
/scamguard rules            # สถานะ rule pack + checksum
/scamguard rules reload     # โหลดกฎใหม่จาก reference_data/blueteam
/scamguard test <ข้อความ>   # ทดสอบว่าข้อความจะถูกจับไหม
/scamguard vip add <@user> [ชื่อ] | list | del <@user>
/scamguard review           # คิวรอตรวจสอบ
/scamguard stats
```

การจับสแกมจะ **เข้าคิวให้แอดมินตัดสิน** (ไม่ใช่แบนอัตโนมัติ) — ปุ่ม: ไม่ใช่สแปม / ลบ / mute /
แบน (แบนยืนยันสองขั้น)

## /joinguard — ป้องกันการบุกกลุ่ม (raid)

```
/joinguard status | on | off
/joinguard mode MONITOR|WARN|DELETE|DELETE+RESTRICT
/joinguard verify button|emoji
/joinguard timeout 120           # วินาที
/joinguard threshold <n>
/joinguard lockdown              # ล็อกกลุ่มด้วยตนเอง
/joinguard unlock                # ปลดล็อก กู้คืนสิทธิ์เดิม
/joinguard list | undo | stats
```

เมื่อพบ raid: จำกัดสิทธิ์ผู้เข้าใหม่ + ให้ทำ **ด่านยืนยันตัวตน** (กดอีโมจิที่ถูกต้อง) —
ปุ่มลงลายเซ็น HMAC ผูกกับ user id คนอื่นกดแทนไม่ได้ และ replay ไม่ได้ สถานะล็อกดาวน์
คงอยู่หลังบอทรีสตาร์ท และมี dead-man switch ปลดอัตโนมัติเมื่อครบเวลาสูงสุด

## หมายเหตุความเป็นส่วนตัว

* เก็บเท่าที่จำเป็น มี retention (`BLUETEAM_RETENTION_DAYS`) และรองรับการลบข้อมูลสมาชิก
* บริการภายนอก (VirusTotal/Safe Browsing/urlscan) เป็น **opt-in ต่อกลุ่ม** และปิดค่าเริ่มต้น
* คะแนนคือเครื่องมือช่วยจัดลำดับตรวจสอบ ไม่ใช่ข้อสรุปความผิดของสมาชิก
