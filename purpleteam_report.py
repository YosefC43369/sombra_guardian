"""
purpleteam_report.py — Phase 12: Purple Team Reporting & Coverage Hand-off.

Read-only rendering layer over purpleteam.py, mirroring redteam_report.py /
bb_report.py / member_report.py. Owns NO tables and has no db_init. Every
number comes from purpleteam.py's public reads, so a report can never
disagree with the records.

THE FOUR-LAYER SEPARATION (mandatory, applied by every report here):

  RAW TELEMETRY / OUTPUT        — what a sensor actually produced
  SYSTEM OBSERVATION            — what the system recorded factually
                                  (outcomes, latencies, coverage counts)
  METRIC / DERIVATION           — rates and MTTD computed from the above
  HUMAN DECISION                — analyst-set outcomes and tuning lifecycle

These are never blended. Coverage and metrics are DERIVED from the
append-only detection log by purpleteam.py; this layer only formats them.

Design constraints (matches redteam_report.py):
  - Standard library only. No network/LLM/Telegram calls; the command
    handler and the admin check live in app.py.
  - No analysis of its own: outcomes, coverage states, rates and MTTD all
    come from purpleteam.py unchanged.
"""

import csv
import io
import json
import time
from typing import Optional, List, Dict, Any

import purpleteam as pt

SECTION_EXEC = "1) EXECUTIVE SUMMARY"
SECTION_ENG = "2) BACKING ENGAGEMENT & AUTHORIZATION"
SECTION_COVERAGE = "3) ATT&CK DETECTION COVERAGE"
SECTION_METRICS = "4) DETECTION EFFECTIVENESS METRICS"
SECTION_GAPS = "5) DETECTION GAPS & TUNING STATUS"
SECTION_TIMELINE = "6) EXERCISE TIMELINE"

DISCLAIMER = (
    "รายงานนี้วัดเฉพาะเทคนิค (MITRE ATT&CK) และช่วงเวลาที่จำลองไว้ในแบบฝึกนี้เท่านั้น "
    "ค่าความครอบคลุม (coverage) และเวลาเฉลี่ยในการตรวจจับ (MTTD) คำนวณจากบันทึกรอบการตรวจจับ "
    "แบบ append-only การยืนยันว่า tuning ใช้ได้ผล (VALIDATED) ทุกครั้งต้องมีมนุษย์อ้างอิงรอบ "
    "ตรวจจับที่ตรวจพบจริง — ระบบไม่ยืนยันเองโดยอัตโนมัติ"
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


def _pct(ratio: Optional[float]) -> str:
    if ratio is None:
        return _UNAVAILABLE
    return f"{ratio * 100:.1f}%"


def _mttd(seconds: Optional[float]) -> str:
    if seconds is None:
        return _UNAVAILABLE
    seconds = float(seconds)
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.1f}h"


# ---------------- Report data assembly ----------------

def get_report_data(exercise_id: int) -> Optional[dict]:
    exercise = pt.get_exercise(exercise_id)
    if not exercise:
        return None
    import redteam as rt
    engagement = rt.get_engagement(exercise["engagement_id"])
    return {
        "exercise": exercise,
        "engagement": engagement,
        "emulations": pt.list_emulations(exercise_id, limit=pt.MAX_PAGE_LIMIT),
        "detections": pt.list_detections(exercise_id, limit=pt.MAX_PAGE_LIMIT),
        "coverage": pt.get_technique_coverage(exercise_id),
        "metrics": pt.get_exercise_metrics(exercise_id),
        "tuning": pt.list_tuning(exercise_id, limit=pt.MAX_PAGE_LIMIT),
        "timeline": pt.get_timeline(exercise_id, limit=pt.MAX_PAGE_LIMIT),
        "disclaimer": DISCLAIMER,
    }


def format_report(data: dict) -> str:
    x = data["exercise"]
    m = data["metrics"]
    engagement = data.get("engagement")
    lines = [
        f"🟣 PURPLE TEAM EXERCISE REPORT — {x['code']}",
        f"Exercise: {x['name']}",
        f"สถานะ: {x['status']} | Framework: {x['framework']}", "",
    ]

    # 1) Executive summary (SYSTEM OBSERVATION + DERIVED metrics)
    lines.append(SECTION_EXEC)
    lines.append(f"  • เทคนิคที่วัด: {m['techniques']} | "
                 f"ตรวจจับได้เต็ม (DETECTION): {m['techniques_with_detection']} "
                 f"({_pct(m['coverage_ratio'])})")
    lines.append(f"  • รอบการตรวจจับ: {m['detection_rounds']} | "
                 f"อัตราตรวจจับ: {_pct(m['detection_rate'])} | "
                 f"อัตราป้องกัน: {_pct(m['prevention_rate'])}")
    lines.append(f"  • ช่องโหว่การตรวจจับ (gaps): {m['gaps']} | "
                 f"MTTD เฉลี่ย: {_mttd(m['mttd_mean'])} "
                 f"(มัธยฐาน {_mttd(m['mttd_median'])}, n={m['mttd_samples']})")

    # 2) Backing engagement & authorization
    lines.append("")
    lines.append(SECTION_ENG)
    if engagement:
        lines.append(f"  • Engagement: {engagement['code']} (#{engagement['engagement_id']})")
        lines.append(f"  • สถานะ RoE: {engagement['status']} | "
                     f"RoE ref: {engagement.get('roe_reference') or _UNAVAILABLE}")
    else:
        lines.append(f"  • engagement_id={x['engagement_id']} (ไม่พบระเบียน)")
    lines.append(f"  • เริ่ม: {_ts(x.get('started_at'))} | "
                 f"สิ้นสุด: {_ts(x.get('completed_at'))}")

    # 3) ATT&CK detection coverage (per technique, grouped by tactic)
    lines.append("")
    lines.append(SECTION_COVERAGE)
    coverage = data["coverage"]
    if not coverage:
        lines.append("  (ยังไม่มีเทคนิคที่จำลอง)")
    else:
        current_tactic = None
        for c in coverage:
            if c["tactic"] != current_tactic:
                current_tactic = c["tactic"]
                lines.append(f"  ── {current_tactic or 'UNSPECIFIED TACTIC'} ──")
            name = f" {c['technique_name']}" if c["technique_name"] else ""
            lines.append(
                f"    • {c['technique_id']}{name}: {c['coverage']} "
                f"(best={c['best_outcome'] or 'N/A'}, rounds={c['rounds']}, "
                f"MTTD={_mttd(c['mttd'])})")

    # 4) Detection effectiveness metrics (DERIVED)
    lines.append("")
    lines.append(SECTION_METRICS)
    by_outcome = m["by_outcome"]
    lines.append("  • ผลตามชนิด: " + (", ".join(
        f"{k}={v}" for k, v in sorted(by_outcome.items())) or "ยังไม่มีข้อมูล"))
    hist = m["coverage_histogram"]
    lines.append(f"  • สถานะ coverage: DETECTION={hist.get('DETECTION',0)} · "
                 f"PARTIAL={hist.get('PARTIAL',0)} · TELEMETRY={hist.get('TELEMETRY',0)} · "
                 f"NONE={hist.get('NONE',0)}")

    # 5) Detection gaps & tuning status (HUMAN DECISION lifecycle)
    lines.append("")
    lines.append(SECTION_GAPS)
    tuning = data["tuning"]
    if not tuning:
        lines.append("  (ยังไม่มี tuning ticket — ไม่มีช่องโหว่ที่ต้องปรับ)")
    else:
        counts = m["tuning_by_status"]
        lines.append("  • สรุปสถานะ: " + ", ".join(
            f"{k}={v}" for k, v in sorted(counts.items())))
        for t in tuning:
            origin = t["origin"] or ""
            lines.append(
                f"    • #{t['tuning_id']} [{t['status']}] "
                f"{t.get('technique_id') or '-'} {_short(t['title'], 80)}"
                + (f" ({origin})" if origin else ""))

    # 6) Timeline
    lines.append("")
    lines.append(SECTION_TIMELINE)
    timeline = data["timeline"]
    if not timeline:
        lines.append("  (ว่าง)")
    else:
        for ev in timeline[:40]:
            lines.append(f"    • {_ts(ev['created_at'])} {ev['kind']} / {ev['action']}"
                         + (f" — {_short(ev['detail'], 80)}" if ev.get('detail') else ""))

    lines.append("")
    lines.append(data["disclaimer"])
    return "\n".join(lines)


# ---------------- Exports ----------------

def export_report_json(exercise_id: int) -> Optional[str]:
    data = get_report_data(exercise_id)
    if data is None:
        return None
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)


def export_coverage_csv(exercise_id: int) -> str:
    """One row per technique: the DeTT&CT-style coverage table, suitable
    for a spreadsheet or import into a coverage tracker."""
    coverage = pt.get_technique_coverage(exercise_id)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["technique_id", "tactic", "technique_name", "coverage",
                     "best_outcome", "rounds", "mttd_seconds"])
    for c in coverage:
        writer.writerow([c["technique_id"], c["tactic"], c["technique_name"],
                         c["coverage"], c["best_outcome"] or "",
                         c["rounds"], "" if c["mttd"] is None else c["mttd"]])
    return buf.getvalue()


# ATT&CK Navigator layer colours, keyed by coverage state.
_NAV_COLORS = {
    pt.Coverage.DETECTION.value: "#2e7d32",   # green
    pt.Coverage.PARTIAL.value: "#f9a825",     # amber
    pt.Coverage.TELEMETRY.value: "#1565c0",   # blue (telemetry only)
    pt.Coverage.NONE.value: "#c62828",        # red
}
_NAV_SCORE = {
    pt.Coverage.DETECTION.value: 3,
    pt.Coverage.PARTIAL.value: 2,
    pt.Coverage.TELEMETRY.value: 1,
    pt.Coverage.NONE.value: 0,
}


def export_attack_navigator_layer(exercise_id: int) -> Optional[str]:
    """Emit a MITRE ATT&CK Navigator layer (v4.5) so the coverage can be
    visualised on the ATT&CK matrix. Techniques are coloured by their
    derived coverage state. Pure data transform; no network call."""
    exercise = pt.get_exercise(exercise_id)
    if not exercise:
        return None
    coverage = pt.get_technique_coverage(exercise_id)
    techniques = []
    for c in coverage:
        state = c["coverage"]
        techniques.append({
            "techniqueID": c["technique_id"],
            "tactic": (c["tactic"] or "").lower().replace(" ", "-") or None,
            "score": _NAV_SCORE.get(state, 0),
            "color": _NAV_COLORS.get(state, ""),
            "comment": (f"{state}; best={c['best_outcome'] or 'N/A'}; "
                        f"rounds={c['rounds']}"),
            "enabled": True,
        })
    layer = {
        "name": f"Purple Team {exercise['code']} — coverage",
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (f"Detection coverage for purple-team exercise "
                        f"{exercise['code']} ({exercise['name']})."),
        "techniques": techniques,
        "gradient": {
            "colors": [_NAV_COLORS[pt.Coverage.NONE.value],
                       _NAV_COLORS[pt.Coverage.DETECTION.value]],
            "minValue": 0, "maxValue": 3,
        },
        "legendItems": [
            {"label": "Detection", "color": _NAV_COLORS[pt.Coverage.DETECTION.value]},
            {"label": "Partial", "color": _NAV_COLORS[pt.Coverage.PARTIAL.value]},
            {"label": "Telemetry only", "color": _NAV_COLORS[pt.Coverage.TELEMETRY.value]},
            {"label": "No coverage", "color": _NAV_COLORS[pt.Coverage.NONE.value]},
        ],
    }
    return json.dumps(layer, ensure_ascii=False, indent=2)
