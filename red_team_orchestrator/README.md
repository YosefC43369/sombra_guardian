# Red Team Orchestrator (`red_team_orchestrator`)

ชั้นประสานงานกลาง — ทำให้โมดูลที่มีอยู่ **ทำงานร่วมกันเป็นชิ้นเดียว** ผ่าน task/plan/
execute เดียว **ไม่สแกนเอง ไม่สร้างบอต/scanner ใหม่ ไม่ bypass scope**

---

## สถาปัตยกรรม (3 ส่วน + render)

```
red_team_orchestrator/
├── store.py     tasks + plan + results + audit trail (atomic JSON) + states + cancel/dedup
├── registry.py  ทะเบียนโมดูล + adapters (เรียก run function จริง) + normalize → unified finding
├── engine.py    วงจรชีวิต task: validate → plan → approve → run(ordered,timeout,cancel) → correlate → AI
├── report.py    render plan/summary/report (JSON/TXT/MD)
└── commands.py  /rt_* ผูกกับ dispatcher เดิม
```

## การค้นพบโมดูล (module discovery)

`registry.REGISTRY` ลงทะเบียนโมดูลเดิมแต่ละตัวเป็น `ModuleSpec` {name, kind(passive/active),
requires_program, adapter, available_check}. `available_check` ลอง import จริง — โมดูลที่ import
ไม่ได้จะถูกข้ามเอง (orchestrator ไม่พัง). adapter เรียก **run function จริง** ของโมดูล
(`passive_recon.run_recon`, `vuln_probe.run_probe`, `wva.run_assessment`, `api.run_assessment`,
`active_scan.run_scan`) — ไม่ reimplement

## การเลือกโมดูล (pipelines)

| task type | ลำดับโมดูล |
|---|---|
| `website` | passive_recon → vuln_probe → web_vulnerability_assessment |
| `api` | passive_recon → api_security_assessment |
| `recon` | passive_recon |
| `portscan` | active_scan |

เลือกเฉพาะที่ **มีจริง + ลงทะเบียน** · ระบุ module เองได้ (subset) · ไม่รันทุกโมดูลกับทุกคำขอ

## การสร้างแผน (execution plan)

`build_plan()` คืน: selected_modules, execution_order, passive/active modules, authorization_required,
scope_authorized (จาก `simple_scope.program_for`), approval_required, expected_outputs, operational_risks

## การบังคับ authorization (ไม่ bypass)

- โมดูล **active** (vuln_probe/wva/api/active_scan) ต้องมี `program_id` ที่ `simple_scope.program_for(target)`
  คืน (คือต้อง `/allowscan <target>` ก่อน — ใช้ scope_policy เดิม) — ถ้าไม่มี task จะ **FAILED NOT_AUTHORIZED**
  พร้อมอธิบาย ไม่รันโมดูล active
- โมดูล **passive** (passive_recon) ไม่ต้องมี program (แยก permission ชัด)
- ด่านจริงตอนยิงยังเป็นของแต่ละโมดูล (`evaluate_target` + SSRF guard) — orchestrator ไม่แตะด่านนั้น

## approve / cancel

- `require_approval=true` (ดีฟอลต์) → task เข้าสถานะ **AWAITING_APPROVAL** รอ `/rt_approve <id>`
- cancel ระหว่างรัน: `/rt_cancel <id>` → engine เช็ค flag ก่อนแต่ละโมดูล → **CANCELLED**

## การรวมผล (unified finding)

ทุกโมดูล → schema กลางเดียว:
`{finding_id, title, description, category, severity, confidence, affected_asset,
evidence_refs, detection_source, remediation, verification_status, raw}`
(คง raw เดิมไว้ใน `raw`) · correlate ตัดซ้ำข้ามโมดูล (เก็บ severity สูงสุด) · evidence sanitize

## สถานะ task

`PENDING → VALIDATING → AWAITING_APPROVAL → RUNNING → COMPLETED | PARTIALLY_COMPLETED | FAILED | CANCELLED`
- แยก "scan ล้มเหลว" ออกจาก "สำเร็จแต่ไม่พบอะไร" (ไม่รายงานว่าสำเร็จถ้าล้ม) · โมดูลเดียวล้มไม่ล้มทั้ง task
- timeout ต่อโมดูล (`asyncio.wait_for`) · กันรันซ้ำ (type+target เดียวกันที่ยัง active)

## AI (ออปชัน, ทนล้มเหลว)

`use_ai=true` → ส่ง unified findings เข้า `gemini.ask_gemini` สรุป/จัดลำดับ/อธิบายความเชื่อมโยง
(ไม่สร้าง AI client ใหม่) · ถ้า AI ล้ม รายงานยังออกได้ · AI ไม่กุผล/ไม่อ้าง exploit สำเร็จ

## Telegram

```
/rt_assess <website|api|recon|portscan> <target> [modules…] [key=value]
/rt_plan <type> <target>        ดูแผนก่อน (ไม่สร้าง task)
/rt_approve <task_id>           อนุมัติ + รัน (background, ไม่บล็อก event loop)
/rt_status [task_id]  /rt_cancel <task_id>  /rt_report <task_id>
```
ในกลุ่ม = แอดมิน · ใน DM = เปิด · progress + สรุปส่งเข้า `SECURITY_REPORT_CHAT_ID` (reuse) + แชตที่สั่ง
· token/secret ไม่ถูกเก็บลง task/log/report (redact)

**ตัวอย่าง:**
```
/allowscan https://authorized-example.com
/rt_assess website https://authorized-example.com
/rt_approve RT-2026-000001
/rt_status RT-2026-000001
/rt_report RT-2026-000001
```

## Configuration (reuse env เดิม + เพิ่มเท่าที่จำเป็น)

| env | ดีฟอลต์ | ความหมาย |
|---|---|---|
| `ORCHESTRATOR_MAX_CONCURRENT_TASKS` | 2 | จำนวน task RUNNING พร้อมกัน |
| `ORCHESTRATOR_MODULE_TIMEOUT` | 900 | timeout ต่อโมดูล (วินาที) |
| `ORCHESTRATOR_REQUIRE_APPROVAL` | true | บังคับอนุมัติก่อนรัน |
| `ORCHESTRATOR_RETRY_LIMIT` | 2 | (สำรองสำหรับ retry policy) |
| `RT_ORCH_DB` | `resource/rt_orchestrator.json` | ที่อยู่ไฟล์ task |

## เพิ่มโมดูลใหม่ในอนาคต

1. เขียน `adapt_<name>(ctx)` ใน `registry.py` → เรียก run function จริงผ่าน `_run_with(...)` + ตัว normalize
2. เพิ่มใน `REGISTRY` (kind, requires_program, available_check)
3. ใส่ชื่อใน `PIPELINES[...]` ของ task type ที่เกี่ยวข้อง — จบ (ไม่ต้องแตะ engine/commands)

## เวิร์กโฟลว์เต็ม

receive (/rt_assess) → validate target → build plan → (AWAITING_APPROVAL → /rt_approve) →
RUNNING → รันโมดูลตามลำดับ (gate ด้วย scope ของแต่ละโมดูล, timeout, เช็ค cancel) →
collect ModuleResults → normalize → correlate → AI (ออปชัน) → COMPLETED/PARTIAL/FAILED →
summary + report (JSON/MD) → SECURITY_REPORT_CHAT_ID + แชตที่สั่ง · ทุกขั้นบันทึก audit trail

## ผลทดสอบ (รันจริง)

`python -m unittest test_red_team_orchestrator` → **18/18 ผ่าน**: registry/selection/normalize,
plan + **scope enforcement** (บล็อก active ที่ยังไม่ allow), approval, duplicate prevention,
run (completed/partial/all-fail), **timeout isolation**, **cancellation**, correlation dedup,
**secret redaction**. รวม repo ไม่มี regression.

## ข้อจำกัด

- ประสาน safe-validation modules เท่านั้น (detection ไม่ exploit) · active ต้อง `/allowscan` ก่อน
- dependency เป็นลำดับ pipeline แบบ static (ไม่มี DAG ซับซ้อน — ตามสเปค "อย่าใส่ workflow framework เกินจำเป็น")
- token ส่งผ่าน options ตอนรัน (ควรทำใน DM); ไม่ถูกเก็บลง record · ต้องมี httpx ตอนรันจริง
