# Red Team Evidence Management & Intelligence Repository

คลังหลักฐานกลางของการประเมิน Red Team ที่ได้รับอนุญาต — **เก็บ · รักษา · ตรวจสอบ · จัด
ระเบียบ · เชื่อมโยง · นำเสนอ** หลักฐานทางเทคนิคที่โมดูลเดิมผลิตขึ้น พร้อม provenance,
integrity verification, traceability และรายงานคุณภาพเชิงนิติวิทยา

> เป็น **ส่วนจัดการข้อมูลหลักฐาน** ไม่ใช่ scanner — ไม่สแกน ไม่ exploit ไม่สร้าง
> orchestrator/correlation engine ใหม่ รับเฉพาะผลที่โมดูลที่ได้รับอนุญาตเก็บไว้แล้ว

---

## 1. สถาปัตยกรรม

```
module outputs (passive_recon · wva · api · active_scan)  +  unified findings  +  asc correlation
        │  ingest.from_*  (submission builders, pure)
        ▼
  schema.py   validate โครงสร้าง/อ้างอิง     ← ทุก record มี source + assessment
  redact.py   redact credential/cookie/token/PII  (reuse classify.sanitize)
  integrity.py  SHA-256 + chain-of-custody hash chain (reuse integrity_ledger Merkle)
  store.py    atomic JSON (append-only) + custody + integrity history
        ▼
  service.py  ingest ชุด · verify · finding↔evidence map · timeline · AI (reuse gemini)
  timeline.py · report.py (executive + technical appendix) · commands.py (/evd_*)
```

| ไฟล์ | หน้าที่ | เทสต์ไม่ต่อเน็ต |
|---|---|---|
| `schema.py` | unified evidence schema + validation + id | ✅ |
| `redact.py` | redaction (reuse `classify.sanitize`) + ติดตามว่า redact จริง | ✅ |
| `integrity.py` | SHA-256 + COC hash chain + verify (reuse `integrity_ledger`) | ✅ |
| `store.py` | atomic JSON store (append-only, custody, integrity history) | ✅ |
| `ingest.py` | ingestion มาตรฐาน + file safety + ตัวแปลง output โมดูลเดิม | ✅ |
| `timeline.py` | ไทม์ไลน์การประเมิน | ✅ |
| `service.py` | orchestration + AI ออปชัน | ✅ (AI absent) |
| `report.py` | executive summary + technical appendix | ✅ |
| `commands.py` | `/evd_*` (reuse บอต + report chat + admin perms) | — |

**reuse (ไม่ทำซ้ำ):** `web_vulnerability_assessment.classify.sanitize/sanitize_headers` ·
`integrity_ledger` (Merkle/`canonical_json`) · `hashlib` SHA-256 (แบบ `findings.py`) ·
unified finding schema · asc correlation result · `gemini.ask_gemini` · atomic store pattern ·
บอต + `SECURITY_REPORT_CHAT_ID` + admin permission

---

## 2. Evidence types

**A. Reconnaissance** — `dns_observation` `whois_rdap` `subdomain` `certificate`
`http_response_meta` `technology_fingerprint` `infrastructure` `service_metadata`
**B. Vulnerability** — `vulnerability_result` `http_request` `http_response`
`detection_method` `reproduction`
**C. API** — `api_endpoint` `api_auth_result` `access_control_result` `api_response`
`api_spec_observation`
**D. Infrastructure/correlation** — `asset_relationship` `shared_infrastructure`
`certificate_relationship` `dns_relationship` `technology_association` `correlation_reference`
**E. Operational** — `execution_log` `module_status` `authorization_decision`
`approval_record` `assessment_timestamp` `error_record`
**ไฟล์/raw** — `json_record` `txt` `csv` `html` `xml` `log_file` `screenshot`
`pdf_report` `raw_excerpt`

---

## 3. Unified evidence schema

```json
{
  "evidence_id": "EVD-2026-000001",
  "assessment_id": "RT-2026-000001",
  "finding_ids": ["FND-000001"],
  "asset_ids": ["ASSET-000001"],
  "source_module": "web_vulnerability_assessment",
  "evidence_type": "http_response",
  "title": "Observed HTTP Response",
  "description": "redacted response metadata",
  "collected_at": "2026-11-01T00:00:00+00:00",
  "collected_at_inferred": false,
  "content_hash": "<sha256>",
  "hash_algorithm": "SHA-256",
  "size_bytes": 128,
  "storage_reference": null,
  "integrity_status": "verified",
  "verification_status": "suspected",
  "confidence": 0.6,
  "redaction_applied": true,
  "redaction_notes": "ข้อมูลอ่อนไหว ... ถูก redact ก่อนเก็บ",
  "metadata": {},
  "created_at": "...",
  "custody": [ /* chain-of-custody events */ ]
}
```

`finding_ids` / `asset_ids` เป็น **list** — evidence หนึ่งรองรับหลาย finding/asset ได้เมื่อ
สมเหตุผล · เก็บ timestamp เดิมเมื่อมี (`collected_at`) และระบุเมื่อ *อนุมาน* (`collected_at_inferred`)

**verification_status:** `observed` · `suspected` · `verified` · `reproduced` ·
`not_reproducible` · `inconclusive` — แยกจาก **integrity_status:** `verified` ·
`unverified` · `compromised` · `missing_artifact` · `no_artifact`

> **evidence ที่มีอยู่ไม่ทำให้ finding = confirmed โดยอัตโนมัติ** — สถานะมาจาก
> `verification_status` ตามจริงเท่านั้น

---

## 4. Ingestion workflow (ข้อ 5)

```python
import evidence_management as evd

rec = evd.submit({
    "assessment_id": "RT-2026-000001",
    "source_module": "web_vulnerability_assessment",
    "evidence_type": "http_response",
    "title": "response", "finding_ids": ["FND-1"],
    "description": "Authorization: Bearer <token>...",   # จะถูก redact
}, content="<raw or file bytes>", actor="user:123")
# -> record พร้อม evidence_id, content_hash, custody เริ่มต้น
```

ลำดับ: validate โครงสร้าง → validate อ้างอิง → บันทึก source → **redact** → **SHA-256** →
เก็บ record → custody (`created→collected→validated→stored`) → คืน evidence_id

**File safety** (`ingest.validate_artifact_path`): ตรวจ allow-list นามสกุล + ขนาด +
กัน **path traversal** (`realpath`+`commonpath`) ก่อนอ่านไฟล์ใด ๆ — ไม่เชื่อ input ดิบ

---

## 5. Hashing & integrity (ข้อ 6)

* ทุก artifact/เนื้อหา inline → **SHA-256** (`integrity.hash_content`, reuse `canonical_json`
  ให้ hash reproducible)
* `verify()` recompute hash เทียบของเดิม → `hash_match` จริง (ไม่สมมติว่าผ่าน)
* เนื้อหาเปลี่ยนผิดคาด → mark `compromised`, บันทึก verify timestamp, **เก็บ integrity
  history เดิมไว้** (ไม่เขียนทับเงียบ), ลง custody event
* redaction เป็น deterministic → hash ครอบ "เนื้อหาที่เก็บจริง (หลัง redact)"; `verify`
  redact เนื้อหาที่ส่งมาด้วยวิธีเดียวกันก่อนเทียบ จึงตรวจกับเนื้อหาต้นฉบับได้

> **ข้อจำกัด (บันทึกตามสเปค):** hash พิสูจน์แค่ว่าเนื้อหาเหมือนตอนบันทึก — *ไม่* พิสูจน์ว่า
> ใครเก็บหรือเก็บเมื่อไร และ chain-of-custody *ไม่ได้* ทำให้รับฟังตามกฎหมายโดยอัตโนมัติ

---

## 6. Chain of custody (ข้อ 7)

hash chain เชิงเส้นแบบ append-only ต่อ evidence:

```
event_hash = sha256(canonical(event ไม่รวม hash) + previous_event_hash)
```

event: `evidence_created · evidence_collected · evidence_validated · evidence_stored ·
evidence_accessed · evidence_exported · evidence_integrity_verified ·
evidence_marked_suspicious · evidence_archived`

```json
{"event_id": "COC-000001", "evidence_id": "EVD-2026-000001",
 "event_type": "evidence_collected", "actor": "red_team_orchestrator",
 "timestamp": "...", "action": "Evidence received from assessment module",
 "previous_event_hash": null, "event_hash": "<sha256>", "metadata": {}}
```

`integrity.verify_custody_chain()` ตรวจความต่อเนื่อง + คืน **Merkle root** (RFC 6962, reuse
`integrity_ledger`) — เปลี่ยน/สลับเหตุการณ์ใด ๆ ตรวจพบ (`broken_at`)

---

## 7. Finding ↔ evidence mapping (ข้อ 9)

`service.evidence_for_finding(finding_id)` จัดกลุ่มตามบทบาท: `primary` · `supporting` ·
`verification` · `contradictory` · `historical` · `remediation` (กำหนดเองผ่าน
`metadata.evidence_role` หรืออนุมานจากชนิด/สถานะ)

```
FND-1 (SQL Injection Indicator)
  primary:       EVD-...001 (vulnerability_result)
  supporting:    EVD-...002 (redacted response excerpt)
  verification:  EVD-...003 (verified reproduction)
```

> ไม่ยกระดับเป็น confirmed เพราะมี evidence — สถานะยังมาจาก `verification_status`

---

## 8. Evidence correlation (ข้อ 10)

integrate กับ attack_surface_correlation: `ingest.from_correlation_result()` แปลง correlation
เป็น evidence `correlation_reference` ที่อ้าง `correlation_id`/`result_id`/asset — ความสัมพันธ์
`hypothesis=True` ถูก map เป็น `verification_status="suspected"` (ไม่สร้าง correlation engine ที่สอง)

---

## 9. Assessment timeline (ข้อ 11)

`service.get_timeline(assessment_id, task=...)` ประกอบ: assessment_started →
authorization_validated → module_executed → finding_discovered → evidence_collected →
evidence verified → correlations_generated → ai_analysis_completed → assessment_completed

แยก **เวลาจริง** จาก **เวลาอนุมาน** (`timestamp_inferred=True` เมื่อข้อมูลต้นทางไม่มี timestamp)

---

## 10. Verification (ข้อ 12)

`service.verify(evidence_id, content=..., base_dir=...)` → ตรวจ hash, artifact existence/
readability, custody chain, metadata — **ไม่แก้ evidence เดิม** คืนผลมีโครงสร้าง:

```json
{"evidence_id": "EVD-2026-000001", "verification_result": "passed",
 "hash_match": true, "artifact_exists": true, "metadata_valid": true,
 "custody_chain_ok": true, "custody_merkle_root": "...", "verified_at": "...", "issues": []}
```

---

## 11. Search & retrieval (ข้อ 13)

`store.search(assessment_id=, finding_id=, asset_id=, source_module=, evidence_type=,
integrity_status=, verification_status=, collected_after=, collected_before=, text=)` +
`by_assessment` / `by_finding`

---

## 12. AI integration (ข้อ 14)

`service.ai_explain_evidence(finding_id)` — reuse `gemini.ask_gemini` (ไม่สร้าง client ใหม่)
ส่งเฉพาะ reference + เนื้อหาที่ redact แล้ว · AI ห้ามกุ evidence/timestamp/HTTP response, ห้าม
ยกระดับ observation เป็น confirmed · **ถ้า AI ไม่พร้อม storage/verify ยังทำงานครบ**

---

## 13. Reporting (ข้อ 15) & Telegram (ข้อ 16)

* **Executive Evidence Summary** — ต่อ finding: severity, asset, evidence summary, verification,
  risk, remediation (`report.executive_summary`)
* **Technical Evidence Appendix** — ต่อ evidence: id, source, เวลา, excerpt, hash, verification,
  related findings, custody refs + merkle, redaction notes (`report.technical_appendix`)

คำสั่ง (reuse บอต + `SECURITY_REPORT_CHAT_ID` + admin perms):

| คำสั่ง | ทำอะไร |
|---|---|
| `/evd_collect <task_id>` | ingest evidence จาก task ที่เก็บไว้ (ไม่สแกนใหม่) |
| `/evd_list <assessment_id>` · `/evd_get <evidence_id>` | ดู evidence |
| `/evd_verify <evidence_id\|assessment_id>` | ตรวจ integrity/custody |
| `/evd_finding <finding_id>` | finding → evidence mapping |
| `/evd_timeline <task_id>` · `/evd_report <assessment_id>` | ไทม์ไลน์ / รายงาน |

> ไม่ส่ง raw artifact ใหญ่เข้า Telegram · ไม่โชว์ secret (redact มาก่อน) · กลุ่มต้องเป็นแอดมิน

---

## 14. Storage & access control (ข้อ 17)

atomic JSON (`resource/evidence_management.json`) · **append-only** (ไม่มี API ลบ evidence —
กันลบโดยไม่ได้รับอนุญาต; มีเฉพาะ archive ผ่าน custody) · artifact bytes ไม่ถูกเก็บซ้ำในนี้
(เก็บ `storage_reference` + hash) · การเข้าถึง/ส่งออกถูกบันทึกเป็น custody event ·
permission เดิมของบอต (admin ในกลุ่ม, DM ผ่าน) gate ทุกคำสั่งที่อ่อนไหว

---

## 15. Configuration (ข้อ 18)

| env | ดีฟอลต์ | ความหมาย |
|---|---|---|
| `EVIDENCE_MANAGEMENT_ENABLED` | `true` | เปิด/ปิดคลัง |
| `EVIDENCE_HASH_ALGORITHM` | `sha256` | อัลกอริทึม hash |
| `EVIDENCE_MAX_FILE_SIZE_MB` | `25` | ขนาด artifact สูงสุด |
| `EVIDENCE_VERIFY_ON_INGEST` | `true` | ตั้ง integrity ตอน ingest |
| `EVIDENCE_AUDIT_TRAIL_ENABLED` | `true` | บันทึก access/export |
| `EVIDENCE_REDACTION_ENABLED` | `true` | redact ก่อนเก็บ |
| `EVIDENCE_RETENTION_DAYS` | `365` | ระยะเก็บ |
| `EVIDENCE_DB` / `EVIDENCE_MAX_RECORDS` | `resource/...` / `5000` | ที่เก็บ / retention cap |

---

## 16. How future modules submit evidence

```python
import evidence_management as evd

# รายการเดียว
evd.submit({"assessment_id": "RT-...", "source_module": "my_module",
            "evidence_type": "json_record", "title": "...", "finding_ids": [...],
            "metadata": {...}}, content=raw_bytes_or_str, actor="my_module")

# หลายรายการ / จาก task
evd.service.submit_many([...], actor="my_module")
evd.service.ingest_task(task, module_outputs={...}, correlation=asc_result)
```

เพิ่ม evidence_type ใหม่ใน `schema.EVIDENCE_TYPES` และ (ถ้าต้องการ) submission builder ใน
`ingest.py` · ข้อกำหนด: ใส่ `assessment_id` + `source_module` + `evidence_type` เสมอ (traceability),
ให้ค่าที่ redact ได้ผ่านไป redact, ไม่ตั้ง verification เกินจริง

---

## 17. Safety & integrity notes

* passive data-processing ล้วน — ไม่สแกน/ไม่ยิง payload/ไม่แตะระบบปลายทาง
* preserve original evidence — ไม่เขียนทับเงียบ, เก็บ integrity history, append-only custody
* ไม่กุผลการตรวจ — `verify()` ใช้ผลจริงเสมอ
* redact credential/cookie/token/PII ก่อนเก็บ/ส่ง และบันทึกว่า redaction เกิดขึ้น
* hash/COC มีขอบเขต — ดูหมายเหตุข้อ 5 (ไม่พิสูจน์ผู้เก็บ/เวลา, ไม่รับฟังตามกฎหมายอัตโนมัติ)

---

## Testing

```bash
python -m unittest test_evidence_management      # หรือ pytest test_evidence_management.py
```

ครอบคลุม 22 ด้านตามสเปค: ingestion, id, metadata validation, SHA-256, hash verify, tamper
detection, chain of custody, audit-chain verify, finding↔evidence mapping, multi-ref, redaction,
file-type/size/path-traversal, missing artifact, retrieval, orchestrator + correlation
integration, AI fallback, report, telegram permissions, unauthorized access — fixtures สังเคราะห์
ล้วน ไม่ต่อเน็ต ไม่ใช้ credential จริง
