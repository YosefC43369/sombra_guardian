# Blue Team Suite — สถาปัตยกรรม (v0.7.0)

แพ็กเกจ `blueteam/` เพิ่มโมดูลป้องกันเชิงรับ 3 ตัว โดย **ต่อเข้ากับแพลตฟอร์มเดิม**
(Event Bus + Workflow Engine + Plugins) แบบ additive — ไม่แตะ flow มอเดอเรตเดิมของ
`app.py` และแยก failure ออกจากกันทั้งหมด

## ภาพรวมการไหลของข้อมูล

```
app.py (handler เดิม)
  ├─ handle_message ──emit──► "message.received" ─┐
  └─ on_chat_member_update ─emit─► "member.joined"/"member.left" ─┐
                                                                  │
                                    workflows.EventBus ◄──────────┘
                                          │ (fan-out)
                    ┌─────────────────────┴───────────────────────┐
                    ▼                                              ▼
      plugin: blueteam-suite                          workflow engine (SOAR)
        └─ BlueTeamRuntime                              playbooks:
            ├─ on_message → LinkGuard + ScamGuard         link.flagged  → create_incident + anchor_integrity
            ├─ on_member_joined → JoinGuard               scam.detected → create_incident + anchor_integrity
            ├─ correlator                                 raid.detected → alert + incident + anchor
            └─ TelegramActions (delete/restrict/…)        blueteam.correlated → alert + incident + anchor
```

* **การวิเคราะห์** เกิดใน subscriber ของ Event Bus (นอกเส้นทาง handler เดิม) จึงไม่
  หน่วงการมอเดอเรตเดิม และถ้าพัง ก็ไม่กระทบ flow เดิม (กติกาข้อ 10)
* **การดำเนินการ** (ลบ/จำกัดสิทธิ์/เตือน) ทำผ่าน `TelegramActions` ที่ `sg_platform`
  ต่อให้ตอนบูต — ถ้าไม่ได้ต่อก็กลายเป็น no-op ที่ log ไว้ (เทสต์ได้ออฟไลน์)
* **หลักฐาน/เหตุการณ์** ไหลต่อเป็น event → workflow → `member_incident` +
  `integrity_ledger` (ผนึกแบบ tamper-evident) — ใช้ระบบเดิมทั้งหมด

## เลเยอร์ในแพ็กเกจ

| ไฟล์ | หน้าที่ |
|------|---------|
| `models.py` | `Verdict`/`Signal`/`Assessment` — คะแนนอธิบายได้ + monotonic (แยกข้อเท็จจริง/การวิเคราะห์) |
| `textkit.py` | normalize (ใช้ `detection.normalize_text` ซ้ำ), confusable skeleton, SimHash, Damerau-Levenshtein, Jaro-Winkler |
| `urlkit.py` | ดึง/ถอดพราง/canonicalize/defang URL, eTLD+1 (fallback ในตัว), ถอด IP เลขฐาน, text_link mismatch |
| `rules.py` | โหลด rule pack แบบมี version+checksum + ReDoS-lint (reload ได้) |
| `store.py` | SQLite (WAL, parameterized, chat-scoped) — ตาราง `bt_*`, retention + purge |
| `config.py` | feature flags/kill switch/tunables ผ่าน `envutil` |
| `linkguard.py` | วิเคราะห์ลิงก์ 3 ชั้น (offline → reputation → active probe) |
| `reputation.py` | allow/deny ต่อกลุ่ม + ฟีด URLhaus/OpenPhish |
| `netprobe.py` | active probe แบบมี SSRF guard (opt-in, ปิดค่าเริ่มต้น) |
| `scamguard.py` | ตรวจสแกม TH/EN + campaign clustering + สัญญาณพฤติกรรม + preset ความไว |
| `impersonation.py` | ตรวจปลอมเป็นแอดมิน/VIP (skeleton + JW/DL, dHash ถ้ามี Pillow) |
| `joinguard.py` | อัตราเข้ากลุ่ม (EWMA+z), state machine (hysteresis), cluster ชื่อ |
| `challenge.py` | ด่านยืนยันตัวตน callback แบบ HMAC (กันปลอม/replay/คนอื่นกด) |
| `correlator.py` | เชื่อมสัญญาณข้ามโมดูลในหน้าต่างเวลา (memory-bounded) |
| `dashboard.py` | สรุป 24h/7d + วิซาร์ดตั้งค่า |
| `runtime.py` | ตัวประสานงาน (นโยบายต่อกลุ่ม, event handlers, การดำเนินการ) |
| `commands.py` | ตรรกะคำสั่ง (คืน string ทดสอบได้) |

## จุดเชื่อม (แก้ไฟล์เดิมน้อยที่สุด แบบ additive)

* `app.py` — เพิ่ม emit 3 จุด: `message.received`, `member.joined`, `member.left`
* `sg_platform.py` — ต่อ `TelegramActions` + ลงทะเบียน callback `^bt1:` (ทั้งคู่ defensive)
* `migrations/m0003_blueteam.py` — schema ใหม่ (non-destructive, reversible)
* `plugins/builtin/blueteam_suite.py` — ปลั๊กอิน (auto-discovered)
* `config.py` (ENV_REGISTRY), `.env.example`, `__version__.py`
