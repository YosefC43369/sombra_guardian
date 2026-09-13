"""
redteam_report.py — Phase 20/21: Red Team Reporting & Remediation Hand-off.

Read-only rendering layer over redteam.py, mirroring bb_report.py /
member_report.py. Owns NO tables and has no db_init. Every number comes
from redteam.py's public reads, so a report can never disagree with the
records.

THE FOUR-LAYER SEPARATION (mandatory, applied by every report here):

  RAW TELEMETRY / OUTPUT        — what a tool or target actually produced
  SYSTEM OBSERVATION            — what the system recorded factually
  AI ANALYSIS                   — advisory narrative, never a fact
  RED TEAM LEAD DECISION        — human classifications and approvals

These are never blended. In particular, AI ANALYSIS is always rendered
under its own explicit heading and is drawn only from rt_ai_analysis;
technical findings and evidence are drawn only from the factual tables.

Design constraints (matches bb_report.py / member_report.py):
  - Standard library only. No network/LLM/Telegram calls; the command
    handler and the admin check live in app.py.
  - No analysis of its own: classifications, risk scores, gap outcomes
    and hashes all come from redteam.py unchanged.
"""

import csv
import io
import json
import time
from typing import Optional, List, Dict, Any

import redteam as rt

SECTION_EXEC = "1) EXECUTIVE SUMMARY"
SECTION_SCOPE = "2) SCOPE & RULES OF ENGAGEMENT"
SECTION_VERIFIED = "3) VERIFIED CRITICAL & HIGH FINDINGS"
SECTION_LEADS = "4) UNVERIFIED LEADS & EXPOSURES"
SECTION_DEFENSE = "5) DEFENSIVE CONTROL EFFECTIVENESS"
SECTION_TIMELINE = "6) TIMELINE OF EVENTS"
SECTION_EVIDENCE = "7) EVIDENCE & PROOF OF CONCEPT"
SECTION_REMEDIATION = "8) REMEDIATION RECOMMENDATIONS"
SECTION_AI = "9) AI ANALYSIS (advisory — not a technical finding)"

DISCLAIMER = (
    "รายงานนี้ครอบคลุมเฉพาะเป้าหมายและช่วงเวลาที่ระบุใน Rules of Engagement เท่านั้น "
    "การจัดระดับ VERIFIED_RISK ทุกข้อผ่านการตรวจสอบโดยผู้นำทีม (human review) พร้อมหลักฐาน "
    "ส่วน LEAD/EXPOSURE เป็นข้อสังเกตที่ยังต้องตรวจสอบเพิ่ม และส่วน AI ANALYSIS เป็นเพียง "
    "คำแนะนำเชิงวิเคราะห์ ไม่ใช่ข้อเท็จจริงทางเทคนิค"
)

_UNAVAILABLE = "N/A"


def _ts(value: Optional[int]) -> str:
    if not value:
        return _UNAVAILABLE
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(value)))


def _short(text: Optional[str], n: int = 140) -> str:
    if not text:
        return ""
    t = str(text).replace("\n", " ")
    return t if len(t) <= n else t[:n] + "…"


# ---------------- Report data assembly ----------------

def get_report_data(engagement_id: int) -> Optional[dict]:
    engagement = rt.get_engagement(engagement_id)
    if not engagement:
        return None
    return {
        "engagement": engagement,
        "operators": rt.list_operators(engagement_id),
        "scope": rt.list_scope(engagement_id),
        "targets": rt.list_targets(engagement_id, limit=rt.MAX_PAGE_LIMIT),
        "stats": rt.get_engagement_stats(engagement_id),
        "verified": rt.list_findings(engagement_id, classification="VERIFIED_RISK",
                                     limit=rt.MAX_PAGE_LIMIT),
        "exposures": rt.list_findings(engagement_id, classification="EXPOSURE",
                                      limit=rt.MAX_PAGE_LIMIT),
        "leads": rt.list_findings(engagement_id, classification="LEAD",
                                  limit=rt.MAX_PAGE_LIMIT),
        "vectors": rt.list_vectors(engagement_id, limit=rt.MAX_PAGE_LIMIT),
        "defense": rt.list_defense_checks(engagement_id, limit=rt.MAX_PAGE_LIMIT),
        "timeline": rt.get_timeline(engagement_id, limit=rt.MAX_PAGE_LIMIT),
        "ai": rt.list_ai_analysis(engagement_id, limit=rt.MAX_PAGE_LIMIT),
        "disclaimer": DISCLAIMER,
    }


def format_report(data: dict) -> str:
    e = data["engagement"]
    stats = data["stats"]
    lines = [
        f"🎯 RED TEAM ASSESSMENT REPORT — {e['code']}",
        f"Engagement: {e['name']}",
        f"สถานะ: {e['status']}", "",
    ]

    # 1) Executive summary (SYSTEM OBSERVATION, counts only)
    lines.append(SECTION_EXEC)
    by_sev = stats["by_severity"]
    lines.append(f"  • เป้าหมายที่ลงทะเบียน: {stats['targets']} | หลักฐาน: {stats['evidence']}")
    lines.append(f"  • VERIFIED_RISK: {stats['by_class'].get('VERIFIED_RISK', 0)} · "
                 f"EXPOSURE: {stats['by_class'].get('EXPOSURE', 0)} · "
                 f"LEAD: {stats['by_class'].get('LEAD', 0)} · "
                 f"UNKNOWN: {stats['by_class'].get('UNKNOWN', 0)}")
    lines.append(f"  • ความรุนแรง: CRITICAL {by_sev.get('CRITICAL', 0)} · "
                 f"HIGH {by_sev.get('HIGH', 0)} · MEDIUM {by_sev.get('MEDIUM', 0)} · "
                 f"LOW {by_sev.get('LOW', 0)}")
    lines.append(f"  • ช่องโหว่การป้องกันที่พบ (Defensive gaps): {stats['defensive_gaps']} | "
                 f"คิวรอตรวจสอบ: {stats['open_reviews']}")

    # 2) Scope & RoE (RED TEAM LEAD DECISION / administrative facts)
    lines.append("")
    lines.append(SECTION_SCOPE)
    lines.append(f"  • RoE reference: {e.get('roe_reference') or _UNAVAILABLE}")
    lines.append(f"  • หน้าต่างทดสอบ: {_ts(e.get('window_start'))} → {_ts(e.get('window_end'))}")
    lines.append(f"  • หมดอายุ: {_ts(e.get('expires_at'))}")
    lines.append(f"  • อนุมัติโดย (operator id): {e.get('approved_by') or _UNAVAILABLE}")
    ops = ", ".join(str(o["operator_id"]) for o in data["operators"]) or _UNAVAILABLE
    lines.append(f"  • ผู้ปฏิบัติงานที่ได้รับอนุญาต: {ops}")
    if data["scope"]:
        lines.append("  • ขอบเขต (scope rules):")
        for r in data["scope"]:
            lines.append(f"      - {r['rule_type']} {r['target_type']} {r['pattern']}")
    else:
        lines.append("  • ยังไม่มี scope rule")

    # 3) Verified critical & high (RED TEAM LEAD DECISION + evidence)
    lines.append("")
    lines.append(SECTION_VERIFIED)
    verified = data["verified"]
    if not verified:
        lines.append("  • ไม่มี finding ที่ยืนยันแล้ว (VERIFIED_RISK)")
    for f in verified:
        lines.append(f"  • #{f['finding_id']} [{f['severity']}] {f['title']} "
                     f"(confidence {f['confidence']})")
        lines.append(f"      เหตุผลระดับความรุนแรง: {_short(f.get('severity_rationale'), 200)}")
        lines.append(f"      หลักฐานแนบ: {rt.count_finding_evidence(f['finding_id'])} รายการ | "
                     f"ยืนยันโดย operator {f.get('reviewed_by') or _UNAVAILABLE}")

    # 4) Unverified leads & exposures (SYSTEM OBSERVATION, not decisions)
    lines.append("")
    lines.append(SECTION_LEADS)
    unverified = data["exposures"] + data["leads"]
    if not unverified:
        lines.append("  • ไม่มี lead/exposure ค้างตรวจสอบ")
    for f in unverified:
        lines.append(f"  • #{f['finding_id']} [{f['classification']}/{f['severity']}] {f['title']}")
    if data["vectors"]:
        lines.append("  เส้นทางโจมตีที่เป็นไปได้ (potential attack paths):")
        for v in data["vectors"]:
            lines.append(f"      - V#{v['vector_id']} [{v['status']}] {v['title']} "
                         f"(impact {v['impact_score']})")

    # 5) Defensive control effectiveness (both signals preserved)
    lines.append("")
    lines.append(SECTION_DEFENSE)
    if not data["defense"]:
        lines.append("  • ยังไม่มีการตรวจสอบการตอบสนองเชิงป้องกัน")
    for d in data["defense"]:
        mark = "⚠️ GAP" if d["outcome"] == "DEFENSIVE_GAP_DETECTED" else "✅ DETECTED"
        lines.append(f"  • {mark} — Red: {_short(d['red_action'], 80)}")
        lines.append(f"      Telemetry: {_short(d['telemetry_result'], 80)}")

    # 6) Timeline (kinds kept distinct)
    lines.append("")
    lines.append(SECTION_TIMELINE)
    if not data["timeline"]:
        lines.append("  • ไม่มีเหตุการณ์")
    for t in data["timeline"][:40]:
        actor = f" โดย {t['actor_id']}" if t.get("actor_id") is not None else ""
        lines.append(f"  • {_ts(t['created_at'])} [{t['kind']}] {t['action']}{actor}"
                     f"{(' — ' + t['detail']) if t.get('detail') else ''}")

    # 7) Evidence & PoC (RAW/OBSERVATION facts + integrity)
    lines.append("")
    lines.append(SECTION_EVIDENCE)
    evidence = rt.list_evidence(engagement_id=e["engagement_id"], limit=rt.MAX_PAGE_LIMIT)
    if not evidence:
        lines.append("  • ไม่มีหลักฐาน")
    for ev in evidence[:30]:
        lines.append(f"  • EV#{ev['evidence_id']} [{ev['kind']}] {_ts(ev['collected_at'])} "
                     f"finding={ev.get('finding_id') or _UNAVAILABLE}")
        lines.append(f"      SHA-256: {ev['sha256']} | ตรวจล่าสุด: "
                     f"{ev.get('last_verify_result') or 'ยังไม่ตรวจ'}")

    # 8) Remediation recommendations (from verified findings)
    lines.append("")
    lines.append(SECTION_REMEDIATION)
    if not verified:
        lines.append("  • ยังไม่มีข้อค้นพบที่ยืนยันแล้วสำหรับออกคำแนะนำแก้ไข")
    for f in verified:
        lines.append(f"  • #{f['finding_id']} {f['title']} → "
                     f"{_short(f.get('description'), 160) or 'ดูรายละเอียดใน finding'}")

    # 9) AI analysis — explicitly separated, advisory only
    lines.append("")
    lines.append(SECTION_AI)
    if not data["ai"]:
        lines.append("  • ไม่มีบทวิเคราะห์จาก AI")
    for a in data["ai"][:10]:
        lines.append(f"  • [{a['subject_kind']}] {_short(a['content'], 200)}")
    lines.append("  ⚠️ ส่วนนี้เป็นบทวิเคราะห์ของ AI ล้วน แยกออกจากข้อเท็จจริงทางเทคนิคข้างต้น")

    lines.append("")
    lines.append(f"ℹ️ {data['disclaimer']}")
    return "\n".join(lines)


# ---------------- Phase 21: remediation hand-off package ----------------

def build_remediation_package(engagement_id: int) -> Optional[dict]:
    """Exportable package for the client Blue/Purple team. Contains only
    VERIFIED_RISK findings plus their evidence hashes — the items the
    client should act on, each with raw-log verification hashes so the
    defender can confirm nothing was altered in transit."""
    engagement = rt.get_engagement(engagement_id)
    if not engagement:
        return None
    items = []
    for f in rt.list_findings(engagement_id, classification="VERIFIED_RISK",
                              limit=rt.MAX_PAGE_LIMIT):
        target = rt.get_target(f["target_id"]) if f.get("target_id") else None
        evidence = rt.list_evidence(finding_id=f["finding_id"], limit=rt.MAX_PAGE_LIMIT)
        items.append({
            "finding_id": f["finding_id"],
            "title": f["title"],
            "severity": f["severity"],
            "confidence": f["confidence"],
            "target": (target["value"] if target else _UNAVAILABLE),
            "severity_rationale": f.get("severity_rationale"),
            "remediation": f.get("description") or "",
            "evidence_hashes": [{"evidence_id": ev["evidence_id"], "kind": ev["kind"],
                                 "sha256": ev["sha256"],
                                 "last_verify_result": ev.get("last_verify_result")}
                                for ev in evidence],
        })
    return {
        "engagement_code": engagement["code"],
        "engagement_id": engagement_id,
        "roe_reference": engagement.get("roe_reference"),
        "generated_at": int(time.time()),
        "verified_findings": items,
        "note": "Contains only human-verified findings (VERIFIED_RISK) with raw-log "
                "verification hashes. Leads/exposures are excluded by design.",
    }


def export_report_json(engagement_id: int) -> Optional[str]:
    data = get_report_data(engagement_id)
    if data is None:
        return None
    e = data["engagement"]
    payload = {
        "report": "red_team_assessment",
        "generated_at": int(time.time()),
        "engagement": {"id": e["engagement_id"], "code": e["code"], "name": e["name"],
                       "status": e["status"], "roe_reference": e.get("roe_reference")},
        # The four layers, kept as distinct keys so a consumer cannot
        # mistake an AI narrative for a technical fact.
        "scope_and_roe": {"operators": [o["operator_id"] for o in data["operators"]],
                          "scope_rules": data["scope"]},
        "red_team_lead_decisions": {"verified_findings": data["verified"]},
        "system_observations": {"exposures": data["exposures"], "leads": data["leads"],
                                "targets": data["targets"], "vectors": data["vectors"],
                                "defensive_control_checks": data["defense"]},
        "raw_evidence": rt.list_evidence(engagement_id=engagement_id, limit=rt.MAX_PAGE_LIMIT),
        "timeline": data["timeline"],
        "ai_analysis_advisory_only": data["ai"],
        "disclaimer": data["disclaimer"],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str)


def export_findings_csv(engagement_id: int) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["finding_id", "classification", "severity", "confidence", "title",
                "target_id", "reviewed_by", "created_at_utc", "evidence_count"])
    for f in rt.list_findings(engagement_id, limit=rt.MAX_PAGE_LIMIT):
        w.writerow([f["finding_id"], f["classification"], f["severity"], f["confidence"],
                    (f["title"] or "").replace("\n", " "), f.get("target_id") or "",
                    f.get("reviewed_by") or "", _ts(f["created_at"]),
                    rt.count_finding_evidence(f["finding_id"])])
    return buf.getvalue()


def format_remediation_package(pkg: dict) -> str:
    lines = [f"📦 REMEDIATION HAND-OFF — {pkg['engagement_code']}",
             f"RoE: {pkg.get('roe_reference') or _UNAVAILABLE}",
             f"สร้างเมื่อ: {_ts(pkg['generated_at'])}", ""]
    if not pkg["verified_findings"]:
        lines.append("ยังไม่มี VERIFIED_RISK สำหรับส่งมอบ")
    for it in pkg["verified_findings"]:
        lines.append(f"• #{it['finding_id']} [{it['severity']}] {it['title']} "
                     f"→ target {it['target']}")
        lines.append(f"    การแก้ไข: {_short(it['remediation'], 200) or 'ระบุใน finding'}")
        for h in it["evidence_hashes"]:
            lines.append(f"    proof EV#{h['evidence_id']} [{h['kind']}] "
                         f"sha256={h['sha256'][:32]}…")
    lines.append("")
    lines.append("ℹ️ " + pkg["note"])
    return "\n".join(lines)
