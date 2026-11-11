# Advanced Risk Prioritization Engine & Safe Payload Expansion

การ **enhance** แพลตฟอร์มเดิม (ไม่ใช่ของใหม่) — เพิ่มเอนจินจัดลำดับความเสี่ยงหลายปัจจัย,
ขยาย payload library ที่มีอยู่, และ **Payload Execution Transparency** โดยต่อยอดโมดูล/
รายงาน/evidence เดิม

> เอนจินความเสี่ยง "ตัวเดียว" ของแพลตฟอร์ม · แยกจากการ **รันทดสอบ** · ไม่สร้าง scanner/
> orchestrator/correlation/evidence/AI client/report generator ใหม่

---

## 1. สถาปัตยกรรม

```
findings (orchestrator unified schema)  +  correlation (asc)  +  evidence (evidence_management)
        ▼
  model.py       ให้คะแนนหลายปัจจัย (pure, documented formula)
  engine.py      ประกอบปัจจัย/บริบท + จัดลำดับ + historical + AI ออปชัน + analyze_task
  transparency.py  payload executed/suggested/verified + เชื่อม evidence
  store.py       atomic JSON + snapshot
  report.py      risk report + PAYLOAD EXECUTION DETAILS (TXT/JSON)
  commands.py    /risk_*
```

payload library (ขยาย registry เดิม — **ไม่สร้างใหม่**): `web_vulnerability_assessment/
payload_engine.py` + `payloads/<category>/*.json`

---

## 2. Risk scoring methodology (ข้อ 3–4)

ปัจจัยอิสระ 4 ด้าน แต่ละด้าน normalize เป็น [0,1]:

| ปัจจัย | มาจาก |
|---|---|
| **technical severity** | severity เดิมของ scanner (+ CVSS ถ้ามี, ผสมเฉลี่ย) |
| **exploitability** | verification status + accessibility + auth required + reproducible − theoretical |
| **asset criticality** | exposure (internet-facing/internal) + importance + #related assets/findings + API sensitivity |
| **evidence confidence** | #หลักฐานอิสระ + integrity + verified + contradictory + source reliability |

**สูตร (documented, น้ำหนักปรับได้):**

```
base = 100 × ( 0.40·severity + 0.25·exploitability + 0.20·asset + 0.15·evidence )   (น้ำหนักรวม = 1)
floor: severity≥HIGH และ verified → score ≥ 75   (ไม่ลดเกรดของร้ายแรงที่ยืนยันแล้ว)
```

ตัวอย่างผลลัพธ์:

```json
{"finding_id": "FND-000001", "technical_severity": "HIGH", "cvss": null,
 "exploitability": "MODERATE", "asset_criticality": "HIGH", "evidence_confidence": 0.62,
 "exposure": "INTERNET_FACING", "verification_status": "POTENTIAL",
 "risk_priority": "NEEDS_VERIFICATION", "risk_score": 73,
 "score_explanation": ["severity=0.80×w0.40 -> 32.0", "..."],
 "recommended_action": "ทดสอบยืนยันเพิ่มแบบปลอดภัยก่อนจัดลำดับแก้ไข"}
```

**หลักที่บังคับใช้:**
* technical severity แยกจาก overall risk · severity เดิมของ scanner **คงไว้** (`original_severity`)
* penalize ความไม่แน่นอน (evidence/exploitability ต่ำ) แต่ **ไม่ปัดตก** ของร้ายแรง → ใช้
  `NEEDS_VERIFICATION`
* อธิบายได้ทุกคะแนน (`score_explanation`) · บันทึก `model_version` · ไม่กุ CVSS/EPSS/KEV
  (ใช้เฉพาะที่มีจริงพร้อม source/timestamp)

---

## 3. Risk prioritization categories (ข้อ 5)

`CRITICAL · HIGH · MEDIUM · LOW · INFORMATIONAL · NEEDS_VERIFICATION`

* bucket จากคะแนน: ≥85 CRITICAL · ≥70 HIGH · ≥45 MEDIUM · ≥20 LOW · else INFORMATIONAL
* **NEEDS_VERIFICATION**: finding ที่มีนัย (severity≥MEDIUM) แต่ยังไม่ยืนยัน + evidence
  confidence < threshold — แยก "ช่องโหว่ที่ยืนยันแล้ว" ออกจาก "observation ที่ต้องทดสอบเพิ่ม"

---

## 4. Correlation-based risk context (ข้อ 6)

integrate กับ attack_surface_correlation: ดึง asset context (related assets/findings,
shared infrastructure) เพิ่ม asset criticality · ความสัมพันธ์ที่ยังไม่ยืนยันถูกถือเป็น
**hypothesis** (ไม่สรุปว่าการรวม finding = attack path ที่ใช้งานได้จริง)

---

## 5. Payload library (ข้อ 7–11) — ขยาย registry เดิม

`payload_engine.py` ถูก **ต่อยอด** (backward-compatible): payload เดิม (มีแค่ REQUIRED_FIELDS)
ยังใช้ได้ · เพิ่ม metadata เสริม (ออปชัน), โปรไฟล์, dedup เชิงเนื้อหา, coverage report,
context-aware selection

**หมวดที่รองรับ (16):** sqli · xss · ssti · csrf · ssrf · lfi · misconfiguration ·
authentication · exposure · **idor · cors · jwt · file_upload · open_redirect · api · headers**

**metadata ต่อ test case** (`payloads/<cat>/expanded.json`):

```json
{"id": "XSS-CTX-011", "category": "xss", "subcategory": "html_attribute_context",
 "name": "...", "test_string": "RTXSS\" x=RT011", "expected": "Quote stays encoded",
 "risk": "MEDIUM", "safety": "SAFE", "payload_type": "inert_marker",
 "detection_method": "response_context_analysis", "requires_authorization": true,
 "non_destructive": true, "verification_method": "safe_context_validation",
 "evidence_type": "http_response", "context": "html_attribute", "encoding": "none",
 "profile": "SAFE_STANDARD", "module": "web_vulnerability_assessment", ...}
```

**safe profiles (ข้อ 9):** `SAFE_MINIMAL ⊆ SAFE_STANDARD ⊆ SAFE_EXTENDED` — ทุกโปรไฟล์
bounded + non-destructive + scope-aware · `PayloadSet.for_profile()` / `select_for_context()`
เลือก test ที่เข้ากับบริบท (context/content-type) แทนการยิงทุกตัว

**quality control (ข้อ 11):** `coverage_report()` / `audit_report()` รายงาน test cases, หมวดที่
มี/ขาด, จำนวนต่อ profile/subcategory, **duplicates** (dedup ตาม (category, test_string,
subcategory)), **rejected** (ไม่ผ่าน safety/schema — fail closed) · `/risk_payloads`

**safety (ข้อ 15):** payload ทุกตัวต้อง `safety=SAFE` + `non_destructive=True` + ไม่เข้ารูปแบบ
ต้องห้าม (DROP/UNION-extract/คำสั่งระบบ/ไฟล์ลับ/time-based/DoS/internal SSRF/data-theft JS) —
บังคับที่ `is_unsafe()` เดิม · SSRF/redirect ใช้ marker ภายนอกที่ได้รับอนุญาต (`*.invalid`) ·
traversal ใช้ sentinel ที่ไม่มีจริง · IDOR/JWT ใช้ test account/token สังเคราะห์

---

## 6. Detection & verification (ข้อ 10 + additional §4)

ไม่ประกาศช่องโหว่จาก status code/keyword/scanner label อย่างเดียว:
* reflected payload อย่างเดียว ≠ confirmed XSS → `REQUIRES_REVIEW`
* HTTP 200 บน path อ่อนไหว ≠ sensitive-file disclosure (ต้องตรวจเนื้อหา)
* endpoint เข้าถึงได้ ≠ ช่องโหว่

verification_result: `VERIFIED` (มีหลักฐานตามเกณฑ์) · `REQUIRES_REVIEW` · `POTENTIAL` ·
`FALSE_POSITIVE` · `INCONCLUSIVE` · `NOT_EXECUTED`

---

## 7. Payload Execution Transparency (additional §1–5)

`transparency.build_transparency(findings, payload_set)` บันทึก **payload ที่ส่งจริง** ต่อ
finding (จาก `test_case_id` + `request` ที่โมดูลเดิมบันทึกไว้) — ไม่กุค่า, ไม่อ้างว่าส่งถ้าแค่
เลือก/แนะนำ

| กลุ่ม | ความหมาย |
|---|---|
| **executed_payloads** | ส่งจริง — ค่าที่ส่ง (redact), response evidence, execution_status, http_status |
| **suggested_payloads** | registry/AI แนะนำเพิ่ม — ติดป้าย **NOT_EXECUTED** + เหตุผล (ไม่ใช่ช่องโหว่) |
| **verification_results** | executed ที่ผ่านเกณฑ์ยืนยัน (VERIFIED + มีหลักฐาน) |

executed record ครบฟิลด์ตามสเปค: `finding_id, vulnerability_type, severity, target_url,
http_method, parameter, injection_point, payload_id, payload_name, payload_category,
payload_value, payload_encoding, payload_profile, execution_timestamp, execution_status,
http_status_code, response_evidence, verification_result, confidence, source_module`

**รายงาน (ข้อ §5):** `report.payload_execution_txt()` สร้างหัวข้อ `PAYLOAD EXECUTION DETAILS`
ใน TXT · `payload_execution_json()` ให้โครงสร้าง `payload_execution.{executed_payloads,
suggested_payloads, verification_results, evidence_references}` ใน JSON — ต่อยอด report เดิม

**evidence (§6):** `transparency.link_to_evidence()` ส่ง executed payload เข้า
evidence_management (http_request evidence) — SHA-256, timestamp, source attribution, redact
secret · raw evidence แยกจากบทวิเคราะห์ของ AI

---

## 8. AI (ข้อ 13) & Telegram (§7)

* AI reuse `gemini.ask_gemini` — อธิบายการจัดลำดับ/ชี้จุดที่ต้องยืนยัน · ห้ามกุหลักฐาน/
  ยกระดับ observation · **deterministic เมื่อ AI ไม่พร้อม**
* `/risk_assess <task_id>` · `/risk_status` · `/risk_report <result_id>` · `/risk_payloads
  [category]` — reuse บอต + `SECURITY_REPORT_CHAT_ID` + admin perms · payload ยาว/หลักฐานมาก
  ส่งเป็นไฟล์แทน inline

---

## 9. Orchestrator integration (ข้อ 14)

run_task เดิมเพิ่มขั้นตอน (gated, ทนล้มเหลว): findings → correlation → evidence → **risk** →
แนบ pointer `task["risk"]` (ผลเต็มเก็บแยกใน risk store) · `/risk_assess`,
`risk.analyze_task(task_id)` ทำ on-demand ได้ (ไม่รันทดสอบใหม่) · risk prioritization **แยกจาก
vulnerability execution**

---

## 10. Configuration (ข้อ 16)

| env | ดีฟอลต์ | ความหมาย |
|---|---|---|
| `RISK_ENGINE_ENABLED` | `true` | เปิด/ปิดเอนจิน |
| `RISK_MODEL_VERSION` | `2` | เวอร์ชันโมเดล |
| `RISK_CONFIDENCE_THRESHOLD` | `0.70` | ต่ำกว่า + ยังไม่ยืนยัน = NEEDS_VERIFICATION |
| `RISK_AI_ANALYSIS_ENABLED` | `false` | ให้ AI อธิบาย |
| `RISK_DB` / `RISK_MAX_RESULTS` | `resource/...` / `200` | ที่เก็บ / retention |
| `PAYLOAD_PROFILE` | `SAFE_STANDARD` | โปรไฟล์ทดสอบเริ่มต้น |
| `WVA_PAYLOAD_DIR` | `payloads` | ราก payload registry |

---

## 11. Testing

```bash
python -m unittest test_risk_prioritization    # หรือ pytest test_risk_prioritization.py
```

ครอบคลุม 24 ด้าน: risk scoring/severity preservation/confidence/asset/evidence/explanation/
missing-data/historical/correlation/AI fallback · payload discovery/dupe/metadata/coverage/
context-select/profile/limits/scope/false-positive/evidence-gen · orchestrator + evidence +
telegram integration + module compatibility — local fixtures, ไม่สแกนภายนอก

---

## 12. Known limitations

* CVSS/EPSS/KEV ใช้เฉพาะที่มีใน finding metadata จริง (ไม่ดึง feed ภายนอก/ไม่กุ)
* exploitability/accessibility อนุมานจาก verification + metadata ที่มี — ไม่ทดสอบ exploit จริง
* executed-payload transparency อ่านจากสิ่งที่โมดูลเดิมบันทึก (`request`/`test_case_id`) — ถ้า
  โมดูลไม่บันทึกค่าที่ส่ง จะไม่มี executed record (ไม่เดา)
* `attack path` เป็นการสังเกตความสัมพันธ์ ไม่ใช่ข้อพิสูจน์ว่ารวมแล้ว exploit ได้ (hypothesis)
