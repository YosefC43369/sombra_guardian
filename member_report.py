"""
member_report.py — Phase 9: Member Intelligence Reporting & Export

Read-only rendering layer for member_intel.py and member_incident.py,
mirroring dashboard.py / bb_report.py on the moderation side of this bot.

Design constraints (matches dashboard.py / bb_report.py):
  - Owns NO tables. There is deliberately no db_init function here.
    Every number comes from member_intel.py's / member_incident.py's
    public read APIs, so a report can never disagree with the records.
  - Standard library only. No network/API calls, no LLM calls, no
    background threads, no Telegram calls. The command handler and the
    administrator permission check live in app.py.
  - No analysis logic of its own: risk scores come from
    member_intel.assess_risk(), correlation from find_correlated_activity(),
    integrity from member_incident.verify_evidence(). This module never
    recomputes, re-weights or re-interprets any of them.

THE FOUR-SECTION RULE (mandatory, applied by every report here)

Every rendered report separates:

  1. ข้อเท็จจริงที่สังเกตได้ (OBSERVED FACTS)
     Things the bot actually received from Telegram or performed itself:
     ids, timestamps, message ids, observed names, join/leave events,
     recorded events.

  2. การวิเคราะห์ของระบบ (SYSTEM ANALYSIS)
     Scores, levels, correlations, classifications. Computed, not
     observed: an administrator may disagree with all of it. Always
     carries the risk/pattern disclaimer.

  3. การดำเนินการของผู้ดูแล (ADMINISTRATIVE ACTIONS)
     What was done afterwards, and by whom when the bot observed it.

  4. ข้อจำกัด / ข้อมูลที่ไม่มี (LIMITATIONS / UNKNOWN DATA)
     What this system cannot know. Never omitted, never shortened to
     "none" -- Telegram's Bot API limits apply to every report, so this
     section is present even when the report is otherwise complete.

Mixing those four is the failure mode this whole layer exists to
prevent: a risk score rendered next to a timestamp, with no separation,
reads to a human like a fact.
"""

import csv
import io
import json
import time
import logging
from typing import Optional, List, Dict, Any

import member_intel as mi
import member_incident as mic

logger = logging.getLogger("modbot.member_report")

SECTION_FACTS = "1️⃣ ข้อเท็จจริงที่สังเกตได้ (OBSERVED FACTS)"
SECTION_ANALYSIS = "2️⃣ การวิเคราะห์ของระบบ (SYSTEM ANALYSIS)"
SECTION_ACTIONS = "3️⃣ การดำเนินการของผู้ดูแล (ADMINISTRATIVE ACTIONS)"
SECTION_LIMITS = "4️⃣ ข้อจำกัด / ข้อมูลที่ไม่มี (LIMITATIONS / UNKNOWN DATA)"

# The honest, fixed list of what the Telegram Bot API does not give a
# bot. Rendered in the LIMITATIONS section of every report, because these
# limits hold no matter how much data the report contains.
BOT_API_LIMITATIONS = (
    "Telegram Bot API ไม่ให้ IP address ของผู้ใช้ — ระบบนี้จึงไม่มีและไม่เก็บ IP",
    "ไม่ให้เบอร์โทร อีเมล ข้อมูลอุปกรณ์ เวอร์ชันแอป หรือข้อมูลการเข้าสู่ระบบ/เซสชัน",
    "ไม่ให้รายชื่อสมาชิกทั้งกลุ่ม และไม่บอกว่าผู้ใช้อยู่กลุ่มอื่นใดอีก",
    "ไม่มีข้อมูลย้อนหลังก่อนที่บอทจะเข้ากลุ่ม หรือช่วงที่บอทไม่ได้เป็นผู้ดูแล",
    "ข้อมูลลิงก์เชิญมีเฉพาะบางกรณีที่ Telegram ส่งมาให้ (บอทต้องเป็นผู้ดูแล)",
    "ถ้าปิด Group Privacy ไม่สำเร็จ บอทจะเห็นเฉพาะคำสั่ง ไม่เห็นข้อความทั่วไป",
    "ไม่สามารถยืนยันตัวตนในโลกจริงของเจ้าของบัญชีได้",
)

# Exports are bounded by the same cap the underlying reads enforce
# (member_intel.MAX_PAGE_LIMIT), so an export never silently claims to be
# complete while the read layer truncated it.
MAX_EXPORT_ROWS = mi.MAX_PAGE_LIMIT


# ---------------- Formatting helpers ----------------

def _ts(value: Optional[int]) -> str:
    """UTC, explicitly labelled. The rest of the bot logs and buckets in
    UTC (analytics.py's hour histogram, security.py's timestamps), so a
    report that quietly switched to local time would not line up with the
    logs an admin reads next to it."""
    if not value:
        return mi.UNAVAILABLE
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(value)))


def _name(value: Optional[str]) -> str:
    return value if value else mi.UNAVAILABLE


def _at(username: Optional[str]) -> str:
    return f"@{username}" if username else mi.UNAVAILABLE


def _limits_section(extra: Optional[List[str]] = None) -> List[str]:
    lines = [SECTION_LIMITS]
    for item in BOT_API_LIMITATIONS:
        lines.append(f"  • {item}")
    for item in extra or []:
        lines.append(f"  • {item}")
    return lines


def _duration(seconds: int) -> str:
    if seconds % 86400 == 0:
        return f"{seconds // 86400} วัน"
    if seconds % 3600 == 0:
        return f"{seconds // 3600} ชม."
    return f"{seconds} วินาที"


# ---------------- Member Activity Report ----------------

def get_member_activity_data(chat_id: int, user_id: int,
                             timeline_limit: int = 20) -> dict:
    """Facts + analysis for one account, straight from member_intel's
    public reads plus this chat's incident/action counts."""
    profile = mi.get_member_profile(chat_id, user_id, timeline_limit=timeline_limit)
    incidents = mic.list_incidents(chat_id, user_id=user_id, limit=timeline_limit)
    actions = mic.list_admin_actions(chat_id, target_user_id=user_id, limit=timeline_limit)
    evidence = mic.list_evidence(chat_id=chat_id, user_id=user_id, limit=timeline_limit)
    profile["incidents"] = incidents
    profile["admin_actions"] = actions
    profile["evidence"] = evidence
    return profile


def format_member_activity_report(data: dict) -> str:
    """Member Activity Report as plain text (no parse_mode), matching the
    /bb... command family's style so usernames and message text -- which
    are untrusted and may contain markup characters -- are never
    interpreted as formatting."""
    member = data.get("member") or {}
    user_id = member.get("user_id") or data.get("identity_timeline", {}).get("user_id")
    lines = [f"👤 รายงานกิจกรรมสมาชิก | User ID: {user_id}",
             f"รหัสบันทึกภายใน: {data.get('member_ref', mi.UNAVAILABLE)}", ""]

    lines.append(SECTION_FACTS)
    if not data.get("known"):
        lines.append("  • บอทไม่มีบันทึกของบัญชีนี้ในกลุ่มนี้")
        lines.append("    (หมายถึง 'ไม่เคยสังเกตเห็น' ไม่ใช่ 'ไม่มีประวัติ')")
    else:
        lines.append(f"  • Username ปัจจุบัน: {_at(member.get('username'))}")
        lines.append(f"  • ชื่อที่แสดงปัจจุบัน: {_name(member.get('display_name'))}")
        lines.append(f"  • สถานะสมาชิกที่สังเกตได้: {member.get('membership_status')}")
        lines.append(f"  • เห็นครั้งแรก: {_ts(member.get('first_seen_at'))}")
        lines.append(f"  • เห็นครั้งล่าสุด: {_ts(member.get('last_seen_at'))}")
        lines.append(f"  • เข้ากลุ่มล่าสุด: {_ts(member.get('joined_at'))}")
        lines.append(f"  • ออกจากกลุ่ม/ถูกนำออกล่าสุด: {_ts(member.get('left_at'))}")
        # "ออก" covers leaving and being removed: the registry counts a
        # ban as a departure, so labelling it "left" alone would imply the
        # account chose to go. The per-event rows below say which it was.
        lines.append(f"  • เข้า/ออกที่สังเกตได้: เข้า {member.get('join_count', 0)} ครั้ง, "
                     f"ออก/ถูกนำออก {member.get('leave_count', 0)} ครั้ง "
                     f"(ดูรายการด้านล่างว่าเป็นกรณีใด)")
        lines.append(f"  • ข้อความที่บอทเห็น: {member.get('observed_message_count', 0)} ข้อความ "
                     f"(ข้อความแรก {_ts(member.get('first_message_at'))})")

    joins = data.get("join_history") or []
    if joins:
        lines.append("")
        lines.append("  ประวัติการเข้า/ออก (ที่สังเกตได้):")
        for row in joins[:10]:
            lines.append(f"    - {_ts(row.get('observed_at'))} | {row.get('kind')} | "
                         f"{row.get('old_status')} -> {row.get('new_status')} | "
                         f"ลิงก์เชิญ: {row.get('invite_attribution', mi.UNAVAILABLE)}")

    timeline = data.get("timeline") or []
    if timeline:
        lines.append("")
        lines.append("  ไทม์ไลน์ล่าสุด:")
        for row in timeline:
            actor = row.get("actor_user_id")
            actor_text = f" | โดย {actor}" if actor is not None else ""
            detail = row.get("detail") or ""
            lines.append(f"    - {_ts(row.get('created_at'))} | {row.get('event_type')}"
                         f"{actor_text}{(' | ' + detail) if detail else ''}")
    else:
        lines.append("")
        lines.append("  ไทม์ไลน์: ยังไม่มีเหตุการณ์ที่บันทึกไว้")

    lines.append("")
    lines.extend(_risk_analysis_lines(data.get("risk") or {}))

    lines.append("")
    lines.extend(_actions_lines(data.get("incidents") or [], data.get("admin_actions") or [],
                                data.get("evidence") or []))

    lines.append("")
    lines.extend(_limits_section([
        "รายงานนี้ครอบคลุมเฉพาะกลุ่มนี้ ไม่รวมพฤติกรรมในกลุ่มอื่น",
    ]))
    return "\n".join(lines)


def _risk_analysis_lines(risk: dict) -> List[str]:
    lines = [SECTION_ANALYSIS]
    if not risk:
        lines.append("  • ไม่มีผลการวิเคราะห์")
        return lines
    window = risk.get("window_seconds") or 0
    lines.append(f"  • คะแนนความเสี่ยง (ช่วง {_duration(int(window))} ล่าสุด): "
                 f"{risk.get('score', 0)}/100 = {risk.get('level', 'LOW')}")
    reasons = risk.get("reasons") or []
    if reasons:
        lines.append("  • เหตุผลที่ทำให้ได้คะแนนนี้:")
        for reason in reasons:
            lines.append(f"    - {reason.get('label')} × {reason.get('count')} "
                         f"= +{reason.get('points')} คะแนน")
    else:
        lines.append("  • ไม่พบสัญญาณความเสี่ยงในช่วงเวลาที่กำหนด")
    lines.append(f"  • ตัวนับสะสมของ security.py (คนละตัวกับด้านบน): "
                 f"{risk.get('cumulative_risk_score', 0)}/100 จาก "
                 f"{risk.get('cumulative_event_count', 0)} เหตุการณ์")
    lines.append(f"  ⚠️ {risk.get('disclaimer', mi.RISK_DISCLAIMER)}")
    return lines


def _actions_lines(incidents: List[dict], actions: List[dict],
                   evidence: List[dict]) -> List[str]:
    lines = [SECTION_ACTIONS]
    if incidents:
        lines.append(f"  • เหตุการณ์ (Incident): {len(incidents)} รายการ")
        for row in incidents[:10]:
            lines.append(f"    - #{row['incident_id']} | {row['category']} | "
                         f"{row['severity']} | {row['status']} | "
                         f"เปิด {_ts(row['opened_at'])}")
    else:
        lines.append("  • เหตุการณ์ (Incident): ไม่มี")

    if actions:
        lines.append(f"  • การดำเนินการที่บันทึกไว้: {len(actions)} รายการ")
        for row in actions[:10]:
            admin = row.get("admin_user_id")
            who = f"ผู้ดูแล {admin}" if admin is not None else "ระบบ/บอท"
            status = "สำเร็จ" if row.get("executed") else "ไม่สำเร็จ (ทำไม่ได้จริง)"
            lines.append(f"    - {_ts(row['created_at'])} | {row['action']} | {who} | "
                         f"{status}")
    else:
        lines.append("  • การดำเนินการที่บันทึกไว้: ไม่มี")

    lines.append(f"  • หลักฐานที่เก็บไว้: {len(evidence)} รายการ")
    return lines


# ---------------- Member Risk Report (group-level triage) ----------------

def get_member_risk_data(chat_id: int, top_n: int = 10,
                         window_seconds: Optional[int] = None) -> dict:
    assessments = mi.top_risk_members(chat_id, limit=top_n, window_seconds=window_seconds)
    return {
        "chat_id": chat_id,
        "window_seconds": (window_seconds or mi.RISK_WINDOW_SECONDS),
        "thresholds": {"medium_min": mi.RISK_MEDIUM_MIN, "high_min": mi.RISK_HIGH_MIN},
        "members": [a.as_dict() for a in assessments],
        "retention": mi.retention_settings(),
    }


def format_member_risk_report(data: dict) -> str:
    window = int(data.get("window_seconds") or 0)
    lines = [f"⚠️ รายงานความเสี่ยงสมาชิก (ช่วง {_duration(window)} ล่าสุด)", ""]

    lines.append(SECTION_FACTS)
    lines.append("  • รายชื่อด้านล่างคัดจากบัญชีที่มีเหตุการณ์ที่บอทบันทึกไว้จริงในช่วงนี้")
    lines.append("  • บัญชีที่ไม่มีเหตุการณ์จะไม่ปรากฏ (ไม่ใช่ว่าได้คะแนน 0 จากการตรวจแล้ว)")

    lines.append("")
    lines.append(SECTION_ANALYSIS)
    thresholds = data.get("thresholds") or {}
    lines.append(f"  • เกณฑ์: MEDIUM ≥ {thresholds.get('medium_min')} , "
                 f"HIGH ≥ {thresholds.get('high_min')} (ตั้งค่าได้)")
    members = data.get("members") or []
    if not members:
        lines.append("  • ไม่มีบัญชีที่มีสัญญาณความเสี่ยงในช่วงนี้")
    for item in members:
        lines.append(f"  • User ID {item['user_id']} — {item['score']}/100 ({item['level']})")
        for reason in (item.get("reasons") or [])[:5]:
            lines.append(f"      - {reason.get('label')} × {reason.get('count')} "
                         f"= +{reason.get('points')}")
    lines.append(f"  ⚠️ {mi.RISK_DISCLAIMER}")

    lines.append("")
    lines.append(SECTION_ACTIONS)
    lines.append("  • รายงานนี้เป็นการจัดลำดับเพื่อตรวจสอบ ไม่ได้ดำเนินการใดกับบัญชีใด")

    lines.append("")
    retention = data.get("retention") or {}
    lines.extend(_limits_section([
        "คะแนนคิดจากช่วงเวลาที่กำหนดเท่านั้น เหตุการณ์ที่เก่ากว่านั้นไม่ถูกนับ",
        f"การเก็บข้อมูล: ไทม์ไลน์ {retention.get('timeline_days', 0)} วัน, "
        f"สแนปช็อตความเสี่ยง {retention.get('risk_snapshot_days', 0)} วัน "
        "(0 = เก็บไม่จำกัด)",
    ]))
    return "\n".join(lines)


def format_single_risk_report(user_id: int, assessment) -> str:
    """Risk report for one account, under the four mandatory headings.

    Public counterpart to format_member_risk_report() so a caller never
    has to assemble sections itself -- keeping the four-section rule
    enforced here rather than in each command handler."""
    risk = assessment.as_dict() if hasattr(assessment, "as_dict") else dict(assessment)
    lines = [f"⚠️ ความเสี่ยงของ User ID {user_id}", ""]

    lines.append(SECTION_FACTS)
    lines.append("  • คะแนนคิดจากเหตุการณ์ที่บอทบันทึกไว้จริงในกลุ่มนี้เท่านั้น")
    lines.append(f"  • คำนวณเมื่อ: {_ts(risk.get('computed_at'))}")

    lines.append("")
    lines.extend(_risk_analysis_lines(risk))

    lines.append("")
    lines.append(SECTION_ACTIONS)
    lines.append("  • รายงานนี้ไม่ได้ดำเนินการใดกับบัญชี — ใช้ /incident เพื่อเปิดเหตุการณ์")

    lines.append("")
    lines.extend(_limits_section([
        "คะแนนไม่ครอบคลุมพฤติกรรมในกลุ่มอื่น หรือช่วงที่บอทไม่ได้อยู่ในกลุ่ม",
    ]))
    return "\n".join(lines)


# ---------------- Identity History Report ----------------

def format_identity_history_report(chat_id: int, user_id: int) -> str:
    data = mi.build_identity_timeline(chat_id, user_id)
    lines = [f"🪪 ประวัติตัวตนที่สังเกตได้ | User ID: {user_id}",
             f"รหัสบันทึกภายใน: {data['member_ref']}", ""]

    lines.append(SECTION_FACTS)
    lines.append(f"  • Username ปัจจุบัน: {data['current_username']}")
    lines.append(f"  • ชื่อที่แสดงปัจจุบัน: {data['current_display_name']}")
    if not data["known"]:
        lines.append("  • บอทไม่มีบันทึกของบัญชีนี้ในกลุ่มนี้")
    else:
        lines.append(f"  • ข้อมูลก่อน {_ts(data['unknown_before'])} — ไม่ทราบ "
                     "(ก่อนที่บอทจะเริ่มสังเกต)")
    if data["entries"]:
        lines.append("")
        lines.append("  การเปลี่ยนแปลงที่สังเกตได้ (เรียงจากเก่าไปใหม่):")
        for entry in data["entries"]:
            label = "username" if entry["field"] == "username" else "ชื่อที่แสดง"
            lines.append(f"    - {_ts(entry['observed_at'])} | {label}: "
                         f"{entry['from']} → {entry['to']}")
    else:
        lines.append("")
        lines.append("  • ไม่เคยสังเกตเห็นการเปลี่ยน username หรือชื่อที่แสดง")

    lines.append("")
    lines.append(SECTION_ANALYSIS)
    lines.append("  • ไม่มีการวิเคราะห์ในรายงานนี้ — เป็นบันทึกสิ่งที่สังเกตได้อย่างเดียว")
    lines.append("  • User ID คือรหัสที่คงที่; username และชื่อที่แสดงเปลี่ยนได้และนำกลับมาใช้ซ้ำได้")

    lines.append("")
    lines.append(SECTION_ACTIONS)
    lines.append("  • ไม่มี (รายงานนี้ไม่ดำเนินการใดกับบัญชี)")

    lines.append("")
    lines.extend(_limits_section([
        "บันทึกไว้เฉพาะการเปลี่ยนแปลงที่บอทเห็นตอนที่ผู้ใช้ส่งข้อความหรือมีเหตุการณ์สมาชิก",
        "ถ้าผู้ใช้เปลี่ยนชื่อแล้วเงียบไป บอทจะยังไม่เห็นการเปลี่ยนนั้นจนกว่าจะเห็นอีกครั้ง",
    ]))
    return "\n".join(lines)


# ---------------- Timeline Report ----------------

def format_timeline_report(chat_id: int, user_id: int, limit: int = 30,
                           since: Optional[int] = None) -> str:
    rows = mi.get_timeline(chat_id, user_id, limit=limit, since=since)
    member = mi.get_member(chat_id, user_id)
    lines = [f"🕒 ไทม์ไลน์สมาชิก | User ID: {user_id}", ""]

    lines.append(SECTION_FACTS)
    if member:
        lines.append(f"  • เห็นครั้งแรก: {_ts(member['first_seen_at'])} | "
                     f"ล่าสุด: {_ts(member['last_seen_at'])}")
    if not rows:
        lines.append("  • ยังไม่มีเหตุการณ์ที่บันทึกไว้สำหรับบัญชีนี้")
    for row in reversed(rows):  # oldest first: a timeline reads forwards
        bits = [_ts(row["created_at"]), row["event_type"]]
        if row.get("message_id"):
            bits.append(f"msg={row['message_id']}")
        if row.get("actor_user_id") is not None:
            bits.append(f"โดย={row['actor_user_id']}")
        if row.get("incident_id"):
            bits.append(f"incident=#{row['incident_id']}")
        if row.get("detail"):
            bits.append(row["detail"])
        lines.append("  • " + " | ".join(str(b) for b in bits))

    lines.append("")
    lines.append(SECTION_ANALYSIS)
    lines.append("  • ไทม์ไลน์เป็นบันทึกเหตุการณ์ที่สังเกตได้ ไม่ใช่การตีความ")
    lines.append("  • ช่องว่างในไทม์ไลน์ = ไม่มีเหตุการณ์ที่บันทึกไว้ ไม่ใช่ 'ไม่มีอะไรเกิดขึ้น'")

    lines.append("")
    lines.append(SECTION_ACTIONS)
    admin_events = [r for r in rows if r.get("actor_user_id") is not None]
    if admin_events:
        lines.append(f"  • เหตุการณ์ที่มีผู้ดูแลเกี่ยวข้อง: {len(admin_events)} รายการ "
                     "(ดูรายละเอียดใน /memberreport)")
    else:
        lines.append("  • ไม่มีเหตุการณ์ที่ระบุผู้ดูแลที่เกี่ยวข้องได้")

    lines.append("")
    lines.extend(_limits_section([
        f"แสดงไม่เกิน {mi.MAX_PAGE_LIMIT} รายการต่อครั้ง",
    ]))
    return "\n".join(lines)


# ---------------- Incident Report ----------------

def format_incident_list(chat_id: int, incidents: List[dict],
                         stats: Optional[dict] = None) -> str:
    lines = ["🚨 รายการเหตุการณ์ (Incident)", ""]
    lines.append(SECTION_FACTS)
    if not incidents:
        lines.append("  • ไม่มีเหตุการณ์ที่ตรงกับเงื่อนไข")
    for row in incidents:
        lines.append(f"  • #{row['incident_id']} | {row['status']} | {row['category']} | "
                     f"{row['severity']} | User {row['user_id']} | "
                     f"เปิด {_ts(row['opened_at'])}")
        if row.get("summary"):
            lines.append(f"      สรุป: {row['summary']}")

    lines.append("")
    lines.append(SECTION_ANALYSIS)
    if stats:
        by_status = ", ".join(f"{k}:{v}" for k, v in sorted(stats["by_status"].items()))
        by_category = ", ".join(f"{k}:{v}" for k, v in sorted(stats["by_category"].items()))
        lines.append(f"  • ตามสถานะ: {by_status or '-'}")
        lines.append(f"  • ตามประเภท: {by_category or '-'}")
        lines.append(f"  • หลักฐานทั้งกลุ่ม: {stats['evidence_total']} รายการ")
    else:
        lines.append("  • ไม่มีสถิติประกอบ")
    lines.append(f"  ⚠️ {mic.INCIDENT_DISCLAIMER}")

    lines.append("")
    lines.append(SECTION_ACTIONS)
    lines.append("  • เปลี่ยนสถานะได้ด้วย /incident <id> status <OPEN|UNDER_REVIEW|"
                 "CONFIRMED|DISMISSED|ARCHIVED>")

    lines.append("")
    lines.extend(_limits_section())
    return "\n".join(lines)


def format_incident_report(bundle: dict) -> str:
    """Full Incident Report: the record, its evidence, the actions taken
    and the custody trail, under the four mandatory headings."""
    incident = bundle["incident"]
    lines = [f"🚨 รายงานเหตุการณ์ #{incident['incident_id']}", ""]

    lines.append(SECTION_FACTS)
    lines.append(f"  • บัญชีที่เกี่ยวข้อง: User ID {incident['user_id']}")
    lines.append(f"  • ชื่อตอนบันทึก: {_at(incident.get('username_snapshot'))} / "
                 f"{_name(incident.get('display_name_snapshot'))}")
    lines.append(f"  • กลุ่ม (Chat ID): {incident['chat_id']}")
    lines.append(f"  • เปิดเมื่อ: {_ts(incident['opened_at'])} | "
                 f"อัปเดตล่าสุด: {_ts(incident['updated_at'])}")
    lines.append(f"  • ที่มา: {'ระบบตรวจพบอัตโนมัติ' if incident['source'] == 'SYSTEM' else 'ผู้ดูแลสร้างเอง'}")
    opened_by = incident.get("opened_by")
    lines.append(f"  • เปิดโดย: {opened_by if opened_by is not None else 'ระบบ/บอท'}")
    if incident.get("trigger_rules"):
        lines.append(f"  • กฎที่ทำให้เกิด: {incident['trigger_rules']}")

    evidence = bundle.get("evidence") or []
    lines.append(f"  • หลักฐานที่แนบ: {len(evidence)} รายการ")
    for row in evidence[:15]:
        content = row.get("content_snapshot")
        if content:
            preview = content.replace("\n", " ")[:120]
            body = f"เนื้อหา: {preview}"
        else:
            body = f"เนื้อหา: ไม่ได้เก็บ ({row.get('content_omitted_reason') or mi.UNAVAILABLE})"
        lines.append(f"    - EV#{row['evidence_id']} | {row['kind']} | "
                     f"{_ts(row['captured_at'])} | msg={row.get('message_id') or mi.UNAVAILABLE}")
        lines.append(f"      ชื่อตอนบันทึก: {_at(row.get('username_snapshot'))} / "
                     f"{_name(row.get('display_name_snapshot'))}")
        lines.append(f"      {body}")
        lines.append(f"      SHA-256: {row['sha256'][:32]}… | ตรวจล่าสุด: "
                     f"{row.get('last_verify_result') or 'ยังไม่ตรวจ'} "
                     f"{_ts(row.get('last_verified_at')) if row.get('last_verified_at') else ''}")

    lines.append("")
    lines.append(SECTION_ANALYSIS)
    lines.append(f"  • ประเภทที่ระบบจัดไว้: {incident['category']}")
    lines.append(f"  • ระดับความรุนแรงที่ระบบ/ผู้ดูแลกำหนด: {incident['severity']}")
    lines.append(f"  • สถานะปัจจุบัน: {incident['status']}")
    lines.append(f"  ⚠️ {mic.INCIDENT_DISCLAIMER}")
    lines.append(f"  ⚠️ {mic.INTEGRITY_DISCLAIMER}")

    lines.append("")
    lines.append(SECTION_ACTIONS)
    actions = bundle.get("admin_actions") or []
    if actions:
        for row in actions:
            admin = row.get("admin_user_id")
            who = f"ผู้ดูแล {admin}" if admin is not None else "ระบบ/บอท"
            status = "สำเร็จ" if row.get("executed") else "ไม่สำเร็จ"
            lines.append(f"  • {_ts(row['created_at'])} | {row['action']} | {who} | {status}"
                         f"{' | ' + row['reason'] if row.get('reason') else ''}")
    else:
        lines.append("  • ยังไม่มีการดำเนินการที่บันทึกไว้")

    notes = bundle.get("notes") or []
    if notes:
        lines.append("  บันทึกของผู้ตรวจสอบ:")
        for row in notes:
            lines.append(f"    - {_ts(row['created_at'])} | โดย {row['author_user_id']}: "
                         f"{row['note']}")

    custody = bundle.get("custody") or []
    if custody:
        lines.append("  ห่วงโซ่การดูแลหลักฐาน (Chain of Custody, เรียงจากเก่าไปใหม่):")
        for row in custody:
            actor = row.get("actor_user_id")
            who = f"ผู้ดูแล {actor}" if actor is not None else "ระบบ/บอท"
            target = f"EV#{row['evidence_id']}" if row.get("evidence_id") else \
                     (f"INC#{row['incident_id']}" if row.get("incident_id") else "-")
            lines.append(f"    - {_ts(row['created_at'])} | {row['action']} | {target} | "
                         f"{who}{' | ' + row['detail'] if row.get('detail') else ''}")

    if incident.get("bb_case_id"):
        lines.append(f"  • เชื่อมกับ Case: #{incident['bb_case_id']} (ดู /bbcase)")

    lines.append("")
    lines.extend(_limits_section([
        "หลักฐานเป็นสแนปช็อตของสิ่งที่บอทเห็นในกลุ่ม ไม่ใช่สำเนาจากเซิร์ฟเวอร์ Telegram",
        "ข้อความที่ถูกลบก่อนบอทเห็น หรือส่งตอนบอทออฟไลน์ จะไม่มีในหลักฐานนี้",
        "ไฟล์สื่อเก็บเฉพาะรหัสอ้างอิงและ metadata ไม่ได้ดาวน์โหลดตัวไฟล์มาเก็บ",
    ]))
    return "\n".join(lines)


# ---------------- Evidence Report ----------------

def format_evidence_report(record: dict, custody: List[dict]) -> str:
    lines = [f"📎 รายงานหลักฐาน EV#{record['evidence_id']}", ""]

    lines.append(SECTION_FACTS)
    lines.append(f"  • กลุ่ม (Chat ID): {record['chat_id']}")
    lines.append(f"  • บัญชี: User ID {record['user_id']} "
                 f"(รหัสบันทึก {record.get('member_ref') or mi.UNAVAILABLE})")
    lines.append(f"  • ชื่อตอนบันทึก: {_at(record.get('username_snapshot'))} / "
                 f"{_name(record.get('display_name_snapshot'))}")
    lines.append(f"  • Message ID: {record.get('message_id') or mi.UNAVAILABLE}")
    lines.append(f"  • บันทึกเมื่อ: {_ts(record['captured_at'])}")
    captured_by = record.get("captured_by")
    lines.append(f"  • บันทึกโดย: {captured_by if captured_by is not None else 'ระบบ/บอท'}")
    lines.append(f"  • ประเภท: {record['kind']}")
    if record.get("content_snapshot"):
        lines.append("  • เนื้อหาที่เก็บไว้:")
        lines.append(f"      {record['content_snapshot']}")
    else:
        lines.append(f"  • เนื้อหา: ไม่ได้เก็บ "
                     f"({record.get('content_omitted_reason') or mi.UNAVAILABLE})")
    if record.get("media_kind"):
        lines.append(f"  • สื่อ: {record['media_kind']} | "
                     f"mime={record.get('media_mime_type') or mi.UNAVAILABLE} | "
                     f"ขนาด={record.get('media_size') or mi.UNAVAILABLE} | "
                     f"file_unique_id={record.get('media_file_unique_id') or mi.UNAVAILABLE}")
    if record.get("incident_id"):
        lines.append(f"  • ผูกกับเหตุการณ์: #{record['incident_id']}")

    lines.append("")
    lines.append(SECTION_ANALYSIS)
    lines.append(f"  • SHA-256 ที่บันทึกไว้: {record['sha256']}")
    lines.append(f"  • ผลตรวจความครบถ้วนล่าสุด: "
                 f"{record.get('last_verify_result') or 'ยังไม่ได้ตรวจ'}"
                 f"{' เมื่อ ' + _ts(record.get('last_verified_at')) if record.get('last_verified_at') else ''}")
    lines.append(f"  ⚠️ {mic.INTEGRITY_DISCLAIMER}")

    lines.append("")
    lines.append(SECTION_ACTIONS)
    if custody:
        for row in custody:
            actor = row.get("actor_user_id")
            who = f"ผู้ดูแล {actor}" if actor is not None else "ระบบ/บอท"
            lines.append(f"  • {_ts(row['created_at'])} | {row['action']} | {who}"
                         f"{' | ' + row['detail'] if row.get('detail') else ''}")
    else:
        lines.append("  • ไม่มีบันทึกการดูแลหลักฐาน")

    lines.append("")
    lines.extend(_limits_section([
        "แฮชยืนยันว่า 'บันทึกนี้ไม่ถูกแก้' เท่านั้น ไม่ได้ยืนยันว่าใครสร้างเนื้อหา",
    ]))
    return "\n".join(lines)


def format_integrity_result(evidence_id: int, result) -> str:
    lines = [f"🔐 ผลตรวจความครบถ้วนของหลักฐาน EV#{evidence_id}", ""]
    lines.append(SECTION_FACTS)
    if not result.ok:
        lines.append(f"  • ตรวจไม่ได้: {result.reason}")
        lines.append("")
        lines.extend(_limits_section())
        return "\n".join(lines)
    lines.append(f"  • ตรวจเมื่อ: {_ts(result.verified_at)}")
    lines.append(f"  • แฮชที่บันทึกไว้:  {result.stored_sha256}")
    lines.append(f"  • แฮชที่คำนวณใหม่: {result.recalculated_sha256}")

    lines.append("")
    lines.append(SECTION_ANALYSIS)
    if result.match:
        lines.append("  • ✅ ตรงกัน — บันทึกหลักฐานไม่ถูกแก้ไขหลังจากบันทึก")
    else:
        lines.append("  • ❌ ไม่ตรงกัน — บันทึกหลักฐานถูกเปลี่ยนแปลงหลังจากบันทึกไว้")
        lines.append("    (อาจมาจากการแก้ฐานข้อมูลโดยตรง เขียนไม่สมบูรณ์ หรือไฟล์เสียหาย)")
    lines.append(f"  ⚠️ {mic.INTEGRITY_DISCLAIMER}")

    lines.append("")
    lines.append(SECTION_ACTIONS)
    lines.append("  • ผลการตรวจนี้ถูกบันทึกไว้ในห่วงโซ่การดูแลหลักฐานแล้ว")

    lines.append("")
    lines.extend(_limits_section([
        "การตรวจนี้ไม่บอกว่าใครเป็นผู้แก้ไข หากผลไม่ตรงกัน",
    ]))
    return "\n".join(lines)


# ---------------- Admin Audit Report ----------------

def format_admin_audit_report(chat_id: int, actions: List[dict],
                              hours: int = 168) -> str:
    lines = [f"🧾 รายงานการดำเนินการของผู้ดูแล ({hours} ชม. ที่ผ่านมา)", ""]

    lines.append(SECTION_FACTS)
    if not actions:
        lines.append("  • ไม่มีการดำเนินการที่บันทึกไว้ในช่วงนี้")
    for row in actions:
        admin = row.get("admin_user_id")
        who = f"ผู้ดูแล {admin}" if admin is not None else "ระบบ/บอท (ไม่มีผู้ดูแลระบุได้)"
        status = "สำเร็จ" if row.get("executed") else "ไม่สำเร็จ"
        target = row.get("target_user_id")
        lines.append(f"  • {_ts(row['created_at'])} | {row['action']} | {who} | "
                     f"เป้าหมาย: {target if target is not None else mi.UNAVAILABLE} | {status}")
        if row.get("reason"):
            lines.append(f"      เหตุผล: {row['reason']}")
        if row.get("incident_id"):
            lines.append(f"      เหตุการณ์: #{row['incident_id']}")

    lines.append("")
    lines.append(SECTION_ANALYSIS)
    executed = sum(1 for r in actions if r.get("executed"))
    by_bot = sum(1 for r in actions if r.get("admin_user_id") is None)
    lines.append(f"  • ทั้งหมด {len(actions)} รายการ | สำเร็จ {executed} | "
                 f"ระบบทำเอง {by_bot}")

    lines.append("")
    lines.append(SECTION_ACTIONS)
    lines.append("  • รายงานนี้เป็นบันทึกการดำเนินการ ไม่ได้ดำเนินการใดเพิ่ม")

    lines.append("")
    lines.extend(_limits_section([
        "บันทึกเฉพาะการดำเนินการที่บอททำเอง หรือที่บอทสังเกตเห็นผ่าน Telegram",
        "ผู้ดูแลที่ลบข้อความ/แบนจากแอปโดยตรง บอทอาจไม่ได้รับเหตุการณ์นั้น",
    ]))
    return "\n".join(lines)


# ---------------- Pattern Report ----------------

def format_pattern_report(data: dict) -> str:
    lines = [f"🔗 รายงานรูปแบบกิจกรรมที่สัมพันธ์กัน "
             f"(ช่วง {_duration(int(data.get('window_seconds') or 0))})", ""]

    lines.append(SECTION_FACTS)
    lines.append(f"  • เกณฑ์: ต้องมีอย่างน้อย {data.get('min_accounts')} บัญชี")
    lines.append("  • ระบบเก็บเฉพาะลายนิ้วมือ (แฮช) ของข้อความ ไม่ได้เก็บตัวข้อความไว้เปรียบเทียบ")

    lines.append("")
    lines.append(SECTION_ANALYSIS)
    identical = data.get("identical_messages") or []
    hosts = data.get("shared_url_hosts") or []
    if not identical and not hosts:
        lines.append("  • ไม่พบรูปแบบที่เข้าเกณฑ์ในช่วงนี้")
    for item in identical:
        lines.append(f"  • [อาจเป็นรูปแบบ] ข้อความเหมือนกัน (fp {item['fingerprint']}) — "
                     f"{item['account_count']} บัญชี, {item['message_count']} ข้อความ")
        lines.append(f"      บัญชี: {', '.join(str(u) for u in item['user_ids'][:20])}")
        lines.append(f"      ช่วงเวลา: {_ts(item['first_seen'])} → {_ts(item['last_seen'])}")
        lines.append(f"      ผลสรุป: {item['verdict']} (ต้องให้ผู้ดูแลตรวจสอบ)")
    for item in hosts:
        lines.append(f"  • [อาจเป็นแคมเปญลิงก์] ปลายทาง {item['url_host']} — "
                     f"{item['account_count']} บัญชี, {item['message_count']} ข้อความ")
        lines.append(f"      บัญชี: {', '.join(str(u) for u in item['user_ids'][:20])}")
        lines.append(f"      ผลสรุป: {item['verdict']} (ต้องให้ผู้ดูแลตรวจสอบ)")
    lines.append(f"  ⚠️ {data.get('disclaimer', mi.PATTERN_DISCLAIMER)}")

    lines.append("")
    lines.append(SECTION_ACTIONS)
    lines.append("  • ไม่มีการดำเนินการอัตโนมัติจากรายงานนี้")

    lines.append("")
    lines.extend(_limits_section([
        "ข้อความที่เหมือนกันเกิดได้จากการส่งต่อ คัดลอกประกาศ หรือคำตอบสั้นทั่วไป",
        "ระบบนี้ไม่สามารถและไม่พยายามสรุปว่าบัญชีต่าง ๆ เป็นบุคคลเดียวกัน",
    ]))
    return "\n".join(lines)


# ---------------- Export: JSON / CSV ----------------

def export_member_json(chat_id: int, user_id: int, timeline_limit: int = 100) -> str:
    """Machine-readable member export.

    The four-section rule applies to structured output too: the payload
    keys are observed_facts / system_analysis / administrative_actions /
    limitations, so a consumer cannot accidentally treat a risk score as
    an observed fact."""
    profile = mi.get_member_profile(chat_id, user_id, timeline_limit=timeline_limit)
    incidents = mic.list_incidents(chat_id, user_id=user_id, limit=timeline_limit)
    evidence = mic.list_evidence(chat_id=chat_id, user_id=user_id, limit=timeline_limit)
    actions = mic.list_admin_actions(chat_id, target_user_id=user_id, limit=timeline_limit)

    payload = {
        "report": "member_export",
        "generated_at": int(time.time()),
        "chat_id": int(chat_id),
        "user_id": int(user_id),
        "member_ref": profile["member_ref"],
        "observed_facts": {
            "known_to_bot": profile["known"],
            "member": profile["member"],
            "identity_timeline": profile["identity_timeline"],
            "join_history": profile["join_history"],
            "timeline": profile["timeline"],
            "evidence": evidence,
        },
        "system_analysis": {
            "risk": profile["risk"],
            "incident_categories_are_administrative_labels": True,
        },
        "administrative_actions": {
            "incidents": incidents,
            "admin_actions": actions,
        },
        "limitations": list(BOT_API_LIMITATIONS),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str)


def export_timeline_csv(chat_id: int, user_id: int, limit: int = MAX_EXPORT_ROWS) -> str:
    rows = mi.get_timeline(chat_id, user_id, limit=min(limit, MAX_EXPORT_ROWS))
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["created_at_utc", "event_type", "actor_user_id", "message_id",
                     "incident_id", "detail"])
    for row in reversed(rows):  # oldest first, so the CSV reads as a timeline
        writer.writerow([
            _ts(row["created_at"]), row["event_type"],
            row.get("actor_user_id") if row.get("actor_user_id") is not None else "",
            row.get("message_id") or "", row.get("incident_id") or "",
            (row.get("detail") or "").replace("\n", " "),
        ])
    return buffer.getvalue()


def export_incident_csv(chat_id: int, limit: int = MAX_EXPORT_ROWS) -> str:
    rows = mic.list_incidents(chat_id, limit=min(limit, MAX_EXPORT_ROWS))
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["incident_id", "opened_at_utc", "status", "category", "severity",
                     "user_id", "opened_by", "resolved_at_utc", "bb_case_id", "summary"])
    for row in rows:
        writer.writerow([
            row["incident_id"], _ts(row["opened_at"]), row["status"], row["category"],
            row["severity"], row["user_id"],
            row.get("opened_by") if row.get("opened_by") is not None else "system",
            _ts(row.get("resolved_at")) if row.get("resolved_at") else "",
            row.get("bb_case_id") or "", (row.get("summary") or "").replace("\n", " "),
        ])
    return buffer.getvalue()


def export_evidence_csv(chat_id: int, incident_id: Optional[int] = None,
                        limit: int = MAX_EXPORT_ROWS) -> str:
    rows = mic.list_evidence(incident_id=incident_id, chat_id=chat_id,
                             limit=min(limit, MAX_EXPORT_ROWS))
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["evidence_id", "incident_id", "captured_at_utc", "kind", "user_id",
                     "username_snapshot", "display_name_snapshot", "message_id",
                     "content_stored", "content_omitted_reason", "sha256",
                     "last_verified_at_utc", "last_verify_result"])
    for row in rows:
        writer.writerow([
            row["evidence_id"], row.get("incident_id") or "", _ts(row["captured_at"]),
            row["kind"], row["user_id"], row.get("username_snapshot") or "",
            row.get("display_name_snapshot") or "", row.get("message_id") or "",
            "yes" if row.get("content_snapshot") else "no",
            row.get("content_omitted_reason") or "", row["sha256"],
            _ts(row.get("last_verified_at")) if row.get("last_verified_at") else "",
            row.get("last_verify_result") or "",
        ])
    return buffer.getvalue()
