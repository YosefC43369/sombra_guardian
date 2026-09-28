# Blue Team Suite — Threat Model & Security Posture

## สิ่งที่ระบบทำ (และไม่ทำ)

ทุกโมดูลเป็น **การวิเคราะห์เชิงรับ (passive)** เท่านั้น:

* ✅ อ่านข้อความ/เหตุการณ์เข้ากลุ่มที่บอทเห็นอยู่แล้ว วิเคราะห์ และให้คะแนนอธิบายได้
* ❌ ไม่รันไฟล์ ไม่รัน JavaScript ไม่สร้างเครื่องมือโจมตี (กติกาข้อ 9)
* ❌ ไม่แบนถาวรอัตโนมัติ — ต้องมีมนุษย์ยืนยัน เว้นแต่แอดมินเปิดโหมดอัตโนมัติเอง
* คะแนนคือ **เครื่องมือจัดลำดับการตรวจสอบ ไม่ใช่ข้อพิสูจน์ความผิด** ทุก Assessment
  แนบบรรทัดข้อจำกัดเสมอ

## การควบคุมความปลอดภัยตามภัยคุกคาม

| ภัย | การป้องกันในโค้ด |
|-----|------------------|
| **SSRF** ผ่าน active probe | `netprobe.is_safe_ip` ปฏิเสธ private/loopback/link-local/CGNAT/reserved/multicast/metadata/IPv4-mapped; `screen_host` resolve แล้วตรวจ **ทุก** A/AAAA; ปักหมุด IP ที่ตรวจแล้วและตรวจซ้ำทุก hop (กัน DNS rebinding); จำกัด hop/ขนาด(64KB)/เวลา; GET เท่านั้น; ไม่ส่ง cookie; probe เป็น opt-in และปิดค่าเริ่มต้น |
| **ReDoS** จาก rule pack | `rules._redos_safe` ปฏิเสธ nested quantifier ตอนโหลด; คอมไพล์ล่วงหน้า; จำกัดความยาว input (`MAX_SCAN_CHARS`) |
| **Callback tampering / replay / คนอื่นกด** | `challenge`: HMAC-SHA256 ผูก (chat_id,user_id,nonce,choice), เทียบแบบ constant-time; สถานะ one-time + หมดอายุ + จำกัดครั้งใน `bt_challenge`; user_id ผูกในลายเซ็นและเทียบกับผู้กดที่ Telegram ยืนยัน |
| **SQL injection** | ทุก query เป็น parameterized; ชื่อคอลัมน์/ตารางเป็นค่าคงที่ในโค้ด |
| **ข้อมูลผู้ใช้ทำให้แอดมินเผลอกด/ถูก inject** | ตอบกลับเป็น plain text เสมอ (ไม่ใช้ parse_mode กับข้อมูลผู้ใช้); defang ทุก URL (`hxxps://ex[.]com`) |
| **ข้อมูลข้ามกลุ่ม** | ทุกตาราง/คำสั่ง scoped ด้วย `chat_id`; คำสั่งอ่อนไหว fail-closed ผ่าน `is_admin` ของแพลตฟอร์ม |
| **PII / privacy** | เก็บเท่าที่จำเป็น (ไม่เก็บเนื้อหาข้อความใน ledger/anchor — เก็บ fingerprint), retention ตั้งค่าได้, รองรับ `purge_user`; ส่ง URL ออกภายนอก (VT/GSB/urlscan) เป็น opt-in ต่อกลุ่มและปิดค่าเริ่มต้น |
| **โมดูลใหม่พังทำ flow เดิมพัง** | ทุก event handler ห่อ try/except; การกระทำผ่าน action ที่ degrade เป็น no-op; ปลั๊กอิน isolate failure |
| **หน่วยความจำบานปลาย** | ring buffer + LRU มีเพดาน (campaign/join/correlator); retention job |

## ขอบเขต fail-open / fail-closed

* **คำสั่งแอดมิน**: fail-closed — ถ้า `is_admin` ล้มเหลว/ไม่ผ่าน ปฏิเสธ
* **การวิเคราะห์**: fail-safe — ถ้าวิเคราะห์พลาด ไม่ลงโทษ (ไม่ลบ/ไม่แบน) และ log ไว้
* **การลงโทษ**: ค่าเริ่มต้นทุกกลุ่มคือ `OFF`/`MONITOR` จนกว่าแอดมินจะเปิด; DELETE_RESTRICT
  = จำกัดสิทธิ์ (mute) เท่านั้น ไม่ใช่แบนถาวร
