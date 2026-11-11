# Attack Surface Correlation Engine

เอนจิน **เชื่อมโยง/วิเคราะห์พื้นที่โจมตี** (Attack Surface Management) — รวมข้อมูล asset,
โครงสร้างพื้นฐาน, เทคโนโลยี, endpoint และ security finding ที่ **โมดูลเดิมเก็บมาแล้ว** เข้า
เป็นภาพเดียว หาความสัมพันธ์ สร้างกราฟ และสรุป insight

> เป็น **ส่วนวิเคราะห์ข้อมูล (data correlation)** ไม่ใช่ scanner/recon ตัวใหม่ — ไม่สแกน
> ไม่ยิง payload ไม่ exploit ทุกข้อมูลมาจากผลที่โมดูลที่ได้รับอนุญาตเก็บไว้แล้วเท่านั้น

---

## 1. สถาปัตยกรรม (Architecture)

```
module outputs (passive_recon / wva / api / active_scan)  +  unified findings (orchestrator)
        │
        ▼
  normalize.py   ── normalize + dedupe assets (pure, stdlib)      ← traceable กลับทุกแหล่ง
        ▼
  relate.py      ── correlation rules + กันผลบวกลวง (pure)
        ▼
  graph.py       ── attack surface graph (nodes/edges, lightweight)
        ▼
  insights.py    ── analytical insights + historical comparison (pure)
        ▼
  engine.py      ── ประสานทั้งหมด + AI อธิบาย (ออปชัน) + เก็บผล
        ▼
  report.py / commands.py  ── รายงาน (concise/markdown/json/graph) + /asc_* ผ่านบอตเดิม
```

ไฟล์:

| ไฟล์ | หน้าที่ | เทสต์ได้โดยไม่ต่อเน็ต |
|---|---|---|
| `normalize.py` | normalize/dedupe asset, แกะ output ของแต่ละโมดูล | ✅ (stdlib + urlkit) |
| `relate.py` | correlation rules engine + shared-infra guard | ✅ |
| `graph.py` | สร้างกราฟ (dict nodes/edges — ไม่มี graph DB) | ✅ |
| `insights.py` | insight เชิงวิเคราะห์ + เทียบ snapshot | ✅ |
| `store.py` | เก็บผล + snapshot (atomic JSON, pattern เดิม) | ✅ |
| `engine.py` | orchestration + AI ออปชัน + integration | ✅ (AI mock/absent) |
| `report.py` | เรนเดอร์รายงาน | ✅ |
| `commands.py` | `/asc_*` (reuse บอต + report chat) | — |

**หลักการที่ load-bearing:** ทุกความสัมพันธ์ต้อง **มีหลักฐาน** หรือถูกระบุชัดว่าเป็น
**สมมติฐาน (`hypothesis=True`)** — และการใช้ IP/CDN/เทคโนโลยีร่วมกัน **ไม่ถือเป็นหลักฐาน
ความเป็นเจ้าของเดียวกัน**

---

## 2. Supported asset types

`root_domain` · `subdomain` · `ip` · `hostname` · `website` · `http_service` ·
`api_endpoint` · `dns_record` · `certificate` · `network_service` · `technology` · `finding`

normalized asset:

```json
{
  "asset_id": "ASSET-000001",
  "asset_type": "subdomain",
  "value": "api.example.com",
  "parent_domain": "example.com",
  "ip_addresses": ["203.0.113.10"],
  "technologies": ["nginx 1.25.0"],
  "source_modules": ["passive_recon", "web_vulnerability_assessment"],
  "first_seen": "2026-11-01T00:00:00+00:00",
  "last_seen": "2026-11-05T00:00:00+00:00",
  "confidence": 0.9,
  "observations": [{"source_module": "passive_recon", "observed_iso": "...", "evidence": "..."}],
  "metadata": {}
}
```

**Dedupe:** asset ถูกตัดซ้ำตาม `(asset_type, normalized value)` — การเจอซ้ำจะ **ผสาน**
`source_modules`, คง `observations` ทุกแหล่ง (ไม่ลบประวัติ), อัปเดต `first_seen`/`last_seen`
และเลือก `confidence` สูงสุด hostname/url/ip ถูก normalize ก่อนเทียบ (ดู `normalize_hostname`,
`normalize_url`, `normalize_ip`, `endpoint_key`)

> **ไม่รวม asset เพียงเพราะใช้ IP/โครงสร้างพื้นฐานร่วมกัน** — การรวม asset ทำตามค่า
> normalized เท่านั้น ความสัมพันธ์ "ใช้ร่วมกัน" เป็น *edge* ไม่ใช่การรวมเป็นตัวเดียว

---

## 3. Correlation rules & relationship types

| rule | relationship | ownership | หลักฐาน |
|---|---|---|---|
| `same_verified_parent_domain` | `contains` | confirmed | subdomain suffix ตรงกับ parent จริง |
| `host_resolves_to_ip` | `resolves_to` | confirmed/observed_shared_infra | A/AAAA record |
| `dns_record_of_host` | `has_dns_record` | confirmed | DNS record |
| `host_secured_by_certificate` | `secured_by` | confirmed | host อยู่ใน SAN/CN |
| `host_serves_site` | `serves` | confirmed | host ↔ website/http_service |
| `host_exposes_api_endpoint` | `exposes_endpoint` | confirmed | host ↔ api_endpoint |
| `ip_exposes_service` | `exposes_service` | confirmed | active_scan port |
| `finding_on_asset` / `finding_on_host` | `has_finding` | confirmed | finding ↔ asset ที่กระทบ |
| `shared_ip_address` | `shared_infrastructure` | **observed_shared_infra** (hypothesis) | หลายโดเมนต่างเจ้าของใช้ IP เดียว |
| `shared_certificate` | `shared_infrastructure` | **observed_shared_infra** (hypothesis) | SAN ครอบหลาย registered domain |
| `shared_application_technology` | `shared_technology` | observed/observed_shared_infra (hypothesis) | เทคโนโลยีเดียวกันบนหลายโฮสต์ |

correlation record:

```json
{
  "correlation_id": "CORR-000001",
  "rule": "same_verified_parent_domain",
  "relationship": "contains",
  "source": "ASSET-000001", "target": "ASSET-000002",
  "confidence": 1.0,
  "ownership": "confirmed",
  "hypothesis": false,
  "evidence": ["api.example.com เป็น subdomain ของ example.com (suffix ตรง)"],
  "source_modules": ["passive_recon"],
  "explanation": "...",
  "detected_iso": "..."
}
```

### การกันผลบวกลวง (false-relationship prevention)

* **shared IP / CDN / cert / technology** → `ownership = "observed_shared_infra"`,
  `hypothesis = True`, confidence ต่ำกว่า และ **ไม่ใช้ relationship `contains`** เด็ดขาด
* โฮสต์ภายใต้ **registered domain เดียวกัน** ที่ใช้ IP เดียว → ไม่ถูกตั้งเป็น shared-infra
  ข้ามเจ้าของ (ไปอยู่ใน `contains`/`resolves_to` แทน)
* **ไม่มีการแพร่ความเปราะบาง** — asset ที่เชื่อมกับ asset ที่มี finding ไม่ถูกตั้ง finding
  ของตัวเอง

---

## 4. Confidence scoring (แยกแนวคิดตามสเปค)

เก็บคอนเซ็ปต์เหล่านี้ **แยกกัน** ไม่ปนกัน:

* **technical severity** ของ finding — มาจากโมดูลต้นทาง (ไม่ถูกเอนจินนี้ยกระดับ)
* **finding confidence** — ความมั่นใจว่า finding นั้นจริง (จากโมดูลต้นทาง)
* **relationship strength (`confidence` ของ correlation)** — ความมั่นใจว่า *ความสัมพันธ์* นั้น
  มีจริง (เช่น has_finding linkage = 0.9 แม้ finding confidence = 0.4)
* **asset criticality** — ไม่ถูกคิดแทน ผู้ใช้/Risk module กำหนดเอง
* **business impact** — ไม่ถูกคิดแทน

`CORRELATION_CONFIDENCE_THRESHOLD` กรองเฉพาะ **relationship strength** ที่ต่ำกว่าเกณฑ์ออกจาก
รายงาน (ดีฟอลต์ 0.70)

> correlation **ไม่** ยกระดับ severity ของ finding โดยอัตโนมัติ

---

## 5. Graph data format

กราฟน้ำหนักเบา (dict) — ไม่ใช้ graph database (ปริมาณข้อมูล/สถาปัตยกรรมเดิมไม่จำเป็น):

```json
{
  "graph_id": "GRAPH-000001",
  "generated_iso": "...",
  "nodes": [{"id": "ASSET-000001", "type": "root_domain", "label": "example.com",
             "confidence": 0.95, "source_modules": ["passive_recon"],
             "finding_refs": [], "metadata": {}}],
  "edges": [{"source": "ASSET-000001", "target": "ASSET-000002",
             "relationship": "contains", "confidence": 1.0, "ownership": "confirmed",
             "hypothesis": false, "explanation": "...", "evidence": [...]}],
  "stats": {"node_count": 0, "edge_count": 0, "nodes_by_type": {},
            "relationships_by_type": {}, "hypothesis_edges": 0, "confirmed_edges": 0}
}
```

ทุก node มาจาก asset จริง ทุก edge มาจาก correlation ที่ผ่านกฎแล้ว (ไม่มี node/edge จาก
สมมติฐานที่ไม่มีหลักฐาน) `graph.degree_map()` ช่วยหา asset ศูนย์กลาง (hub)

---

## 6. Cross-module integration

เอนจิน **consume** output ที่โมดูลเดิมเก็บมาแล้ว:

| โมดูล | ใช้ข้อมูล |
|---|---|
| `passive_recon` | domain, subdomain, DNS, IP, cert, HTTP meta, technology, infrastructure |
| `web_vulnerability_assessment` | findings (category/endpoint/severity/evidence/state) + target |
| `api_security_assessment` | API host, endpoint (method/path), auth/authz findings, evidence |
| `active_scan` | host (ip/hostname), network service (ip:port/service) |
| `red_team_orchestrator` | unified findings (`affected_asset`, `detection_source`, `evidence_refs`) |

> Group Security Intelligence และข่าวกรองที่ไม่เกี่ยวกับ asset เว็บ **ไม่ถูกปน** เข้ากับ
> asset ของการประเมินเว็บ เอนจินรองรับเฉพาะโมดูลที่ **มีอยู่จริง** และไม่พังหากโมดูลออปชัน
> บางตัวไม่ได้ติดตั้ง

### การผูกกับ Orchestrator (non-invasive)

1. **อัตโนมัติ** — หลัง pipeline เสร็จ `red_team_orchestrator` ส่ง native output ที่เก็บไว้
   ชั่วคราว (in-memory ผ่าน `ctx["asset_sink"]`, ไม่ persist ลง task) + unified findings ให้เอนจิน
   แล้วแนบ pointer ย่อไว้ที่ `task["correlation"]` (gated ด้วย `ATTACK_SURFACE_CORRELATION_ENABLED`)
2. **วิเคราะห์ข้อมูลเก่า (ไม่สแกนใหม่)** — `await asc.analyze_task(task_id)` อ่าน task ที่เก็บไว้
   แล้ว correlate จาก findings โดยไม่ต้องรันโมดูลใหม่

```python
import attack_surface_correlation as asc

# จาก native outputs ที่มีในมือ (รวย asset ที่สุด)
result = await asc.correlate(
    {"passive_recon": recon_report, "web_vulnerability_assessment": wva_assessment},
    findings=unified_findings, target="example.com")

# หรือจาก task ที่ orchestrator เก็บไว้แล้ว (ไม่สแกนใหม่)
result = await asc.analyze_task("RT-2026-000001")
```

---

## 7. Historical comparison

ถ้ามี snapshot ก่อนหน้าของ target เดียวกัน (เก็บใน store) เอนจินจะเทียบให้:

* `new_assets` / `not_observed_now` / `persisting_assets`
* `new_relationships` / `removed_relationships`
* `new_findings` / `resolved_or_unobserved_findings` / `reappearing_findings`
* `changed_ip_associations` (host → IP เปลี่ยน)

> แยก **"ยืนยันว่าถูกถอน"** ออกจาก **"ไม่ถูกสังเกตรอบนี้"** ไม่ได้จาก snapshot เดียว จึงรายงาน
> เป็น `not_observed_now` / `resolved_or_unobserved` — และ **ไม่ลบประวัติเดิม**

---

## 8. AI analysis integration

reuse **`gemini.ask_gemini`** เดิม (ไม่สร้าง client/การตั้งค่า API ใหม่) — ส่งผล correlation ที่
โครงสร้างแล้วให้ AI อธิบายความสัมพันธ์/สรุปพื้นที่โจมตี/ชี้สาเหตุร่วมที่เป็นไปได้/อธิบายความไม่แน่นอน

AI **ห้าม**: กุ asset/ความสัมพันธ์/หลักฐาน · อ้างความเป็นเจ้าของจากโครงสร้างร่วม · ถือ
สมมติฐานเป็นช่องโหว่ที่ยืนยันแล้ว

> เมื่อ AI ไม่พร้อม (ไม่มี key/ล้มเหลว) **ผล correlation ยังออกครบแบบ deterministic** —
> `ai_summary = None` เท่านั้น เปิด/ปิดด้วย `CORRELATION_AI_ANALYSIS_ENABLED`

---

## 9. Telegram reporting

reuse บอตเดิม + `SECURITY_REPORT_CHAT_ID` (ผ่าน `web_vulnerability_assessment.notify.report_chat_id`)
— ไม่สร้างบอต/handler ซ้ำ

| คำสั่ง | ทำอะไร |
|---|---|
| `/asc_correlate <task_id>` | correlate ข้อมูลที่เก็บไว้ (ไม่สแกนใหม่) + ส่งรายงาน |
| `/asc_status [result_id]` | ผลล่าสุด / ตามไอดี |
| `/asc_report <result_id>` | แนบไฟล์ `.md` / `.json` / `_graph.json` |

รายงานสั้น (concise) มี: assets รวม, หมวด asset, ความสัมพันธ์รวม, correlated findings,
โครงสร้างพื้นฐานร่วมที่สำคัญ, insight ความเชื่อมั่นสูง, สาเหตุร่วมที่เป็นไปได้, การเปลี่ยนแปลงจาก
ประวัติ

ลงทะเบียน: `asc.register_commands(app, is_admin)` (ต่อสายใน `app.py` แล้ว)

---

## 10. Configuration

reuse ระบบ env เดิม (อ่านตอนรัน, validate เสมอ):

| env | ดีฟอลต์ | ความหมาย |
|---|---|---|
| `ATTACK_SURFACE_CORRELATION_ENABLED` | `true` | เปิด/ปิดเอนจิน |
| `CORRELATION_CONFIDENCE_THRESHOLD` | `0.70` | เกณฑ์ relationship strength ขั้นต่ำ |
| `CORRELATION_MAX_ASSETS` | `10000` | เพดาน asset ต่อรอบ |
| `CORRELATION_HISTORY_ENABLED` | `true` | เปิดการเทียบประวัติ |
| `CORRELATION_AI_ANALYSIS_ENABLED` | `false` | ให้ AI อธิบายผล |
| `ASC_DB` | `resource/attack_surface_correlation.json` | ที่เก็บผล |
| `ASC_MAX_RESULTS` | `200` | retention |

---

## 11. How future modules can provide data

เพิ่ม extractor ใน `normalize.py` แล้วลงทะเบียนใน `engine._EXTRACTORS`:

```python
# normalize.py
def extract_my_module(output: dict, b: AssetBuilder) -> None:
    for item in (output or {}).get("items", []):
        b.add("hostname", item["host"], source_module="my_module",
              confidence=0.8, evidence="my_module observation")

# engine.py
_EXTRACTORS["my_module"] = normalize.extract_my_module
```

ข้อกำหนด extractor: (1) ทน input ขาด/เพี้ยน (ห้าม throw ให้ pipeline ล้ม) (2) ใส่
`source_module` เสมอ (traceability) (3) ไม่สร้างความสัมพันธ์เอง — แค่สร้าง asset แล้วปล่อยให้
`relate.py` ทำกฎ (4) ความสัมพันธ์ใหม่ที่ไม่มีหลักฐานต้องติด `hypothesis=True`

โมดูลที่ยังไม่มีแต่รองรับในอนาคต: Source Code Auditor, Dependency Auditor, Secret Scanner,
Cloud Posture, Evidence Management, Risk Prioritization — เอนจินไม่พึ่งพาว่าต้องมีครบทุกตัว

---

## 12. Safety & data integrity

* **passive data-processing ล้วน** — ไม่สแกน, ไม่ส่ง payload, ไม่ exploit, ไม่ auth, ไม่แตะ
  ระบบปลายทาง
* ข้อมูลทั้งหมดมาจากผลที่ได้รับอนุญาตแล้วของโมดูลเดิม/แหล่ง passive ที่อนุมัติ
* validate/sanitize input ที่นำเข้า — record เพี้ยนตัวเดียวไม่ทำให้ทั้ง pipeline ล้ม
* ทุก record **traceable** กลับไปที่โมดูลต้นทาง (`source_modules` + `observations` + `evidence`)

---

## Testing

```bash
python -m unittest test_attack_surface_correlation       # หรือ: pytest test_attack_surface_correlation.py
```

ครอบคลุม: normalization, domain/DNS/cert/tech/API relationship, shared-IP guard, dedupe,
confidence/threshold, false-relationship prevention, graph, historical comparison, missing/
malformed input, orchestrator integration, AI fallback, telegram report — ใช้ fixture สังเคราะห์
ล้วน (ไม่ต่อเน็ต)
