# -*- coding: utf-8 -*-
"""group_security_intelligence/correlate.py — เอนจินรวมเหตุการณ์เป็น "incident"

pure logic: รับ list เหตุการณ์ความปลอดภัย (เรียงเวลา) แล้วจัดกลุ่มเหตุการณ์ที่เกิด
ใกล้กันในหน้าต่างเวลาเดียวกันเป็น incident พร้อมให้คะแนน/ระดับ/เหตุผลที่รวม

ระดับ incident: INFO / LOW / MEDIUM / HIGH / CRITICAL
ไม่ฟันธงว่าเป็น "การโจมตีที่ยืนยันแล้ว" — บอกเป็นความเป็นไปได้พร้อมเหตุผลเสมอ
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import store

SEVERITY_WEIGHT = {"INFO": 1, "LOW": 2, "MEDIUM": 5, "HIGH": 10, "CRITICAL": 20}
LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# รูปแบบเหตุการณ์ที่ "มาคู่กันแล้วน่าสงสัยเป็นการยึดกลุ่ม"
_TAKEOVER_KINDS = {
    "admin_promoted", "admin_perms_changed", "admin_demoted",
    "config_permissions_changed", "config_username_changed",
    "invite_created", "invite_revoked",
}


def _score_to_level(score: float) -> str:
    if score >= 40:
        return "CRITICAL"
    if score >= 22:
        return "HIGH"
    if score >= 11:
        return "MEDIUM"
    if score >= 4:
        return "LOW"
    return "INFO"


def correlate(events: List[Dict[str, Any]], window_sec: int = 900,
              min_events: int = 2, now=None) -> List[Dict[str, Any]]:
    """จัดกลุ่มเหตุการณ์เป็น incident

    events: [{ts(iso), kind, severity, detail, actor_id}] — ควรเรียงเวลาแล้ว
    คืน list incident:
      {events:[...], start_iso, end_iso, kinds:{...}, actors:[...],
       score, level, repeated, diverse, explanation}
    """
    evs = [e for e in events if store.parse_iso(e.get("ts"))]
    evs.sort(key=lambda e: store.parse_iso(e["ts"]))
    if len(evs) < min_events:
        return []

    clusters: List[List[Dict[str, Any]]] = []
    cur: List[Dict[str, Any]] = []
    cluster_start = None
    for e in evs:
        t = store.parse_iso(e["ts"])
        if not cur:
            cur = [e]
            cluster_start = t
            continue
        # อยู่ในหน้าต่างเดียวกันถ้าห่างจากเหตุการณ์แรกของกลุ่มไม่เกิน window
        if (t - cluster_start).total_seconds() <= window_sec:
            cur.append(e)
        else:
            clusters.append(cur)
            cur = [e]
            cluster_start = t
    if cur:
        clusters.append(cur)

    incidents = []
    for cl in clusters:
        if len(cl) < min_events:
            continue
        incidents.append(_build_incident(cl))
    return incidents


def _build_incident(cluster: List[Dict[str, Any]]) -> Dict[str, Any]:
    kinds: Dict[str, int] = {}
    actors = []
    base = 0
    for e in cluster:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
        base += SEVERITY_WEIGHT.get(e.get("severity", "LOW"), 2)
        a = e.get("actor_id")
        if a is not None and a not in actors:
            actors.append(a)

    diverse = len(kinds) >= 2
    repeated = any(c >= 3 for c in kinds.values())
    takeover_overlap = len(set(kinds) & _TAKEOVER_KINDS)

    score = float(base)
    if diverse:
        score += 4 * (len(kinds) - 1)       # หลายชนิด = น่าสงสัยกว่า
    if repeated:
        score += 6                          # ชนิดเดิมซ้ำ ๆ = brute/ย้ำ
    if takeover_overlap >= 2:
        score += 10                         # เข้ารูปแบบยึดกลุ่ม

    level = _score_to_level(score)
    return {
        "events": cluster,
        "start_iso": cluster[0]["ts"],
        "end_iso": cluster[-1]["ts"],
        "kinds": kinds,
        "actors": actors,
        "score": round(score, 1),
        "level": level,
        "repeated": repeated,
        "diverse": diverse,
        "takeover_overlap": takeover_overlap,
        "explanation": _explain(kinds, diverse, repeated, takeover_overlap, len(cluster)),
    }


def _explain(kinds, diverse, repeated, takeover_overlap, n) -> str:
    parts = [f"รวม {n} เหตุการณ์ในช่วงเวลาใกล้กัน"]
    if takeover_overlap >= 2:
        parts.append(f"พบรูปแบบที่สอดคล้องกับการพยายามยึดกลุ่ม "
                     f"(เหตุการณ์อ่อนไหว {takeover_overlap} ชนิดเกิดต่อเนื่อง)")
    if diverse:
        parts.append(f"ครอบคลุม {len(kinds)} ประเภท: " + ", ".join(kinds.keys()))
    if repeated:
        hot = [k for k, c in kinds.items() if c >= 3]
        parts.append("มีเหตุการณ์ชนิดเดิมเกิดซ้ำ: " + ", ".join(hot))
    parts.append("ยังไม่ใช่ข้อสรุปว่าเป็นการโจมตี — เป็นสัญญาณที่ควรให้แอดมินตรวจสอบ")
    return " • ".join(parts)
