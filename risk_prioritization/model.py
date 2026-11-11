# -*- coding: utf-8 -*-
"""risk_prioritization/model.py — โมเดลให้คะแนนความเสี่ยงหลายปัจจัย (pure, โปร่งใส)

แยกคอนเซ็ปต์ตามสเปค: technical severity ≠ overall risk · penalize ความไม่แน่นอน แต่
"ไม่ลดเกรด finding ร้ายแรงเพียงเพราะหลักฐานไม่ครบ" (ใช้ NEEDS_VERIFICATION แทนการ
ปัดตก) · อธิบายได้ทุกคะแนน · น้ำหนักปรับได้ · บันทึกเวอร์ชันโมเดล · คงค่า severity เดิมของ scanner

สูตร (documented):
  base = 100 * ( w_sev*sev + w_expl*expl + w_asset*asset + w_evid*evid )
  โดย sev/expl/asset/evid ∈ [0,1], น้ำหนักรวม = 1
  ปรับ: floor สำหรับของร้ายแรงที่ยืนยันแล้ว, penalize ความไม่แน่นอนผ่านปัจจัย evid/expl
  priority: จาก base + กฎ NEEDS_VERIFICATION (observation ที่ยังไม่ยืนยัน + หลักฐานต่ำ)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

MODEL_VERSION = 2

# น้ำหนักเริ่มต้น (ปรับได้ผ่าน policy) — รวม = 1.0
DEFAULT_WEIGHTS = {
    "severity": 0.40,
    "exploitability": 0.25,
    "asset_criticality": 0.20,
    "evidence_confidence": 0.15,
}

_SEV_SCORE = {"INFORMATIONAL": 0.10, "LOW": 0.30, "MEDIUM": 0.55, "HIGH": 0.80,
              "CRITICAL": 1.0}
_SEV_RANK = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# verification -> exploitability base + ว่าเป็น "ยืนยันแล้ว" ไหม
_VERIF = {
    "reproduced": (0.95, True), "verified": (0.90, True), "confirmed": (0.90, True),
    "potential": (0.55, False), "suspected": (0.50, False),
    "observed": (0.30, False), "informational": (0.20, False),
    "not_reproducible": (0.10, False), "inconclusive": (0.25, False),
}

_EXPOSURE_SCORE = {"internet_facing": 1.0, "external": 1.0, "internal": 0.4,
                   "unknown": 0.6}


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def severity_factor(severity: str, cvss: Optional[float]) -> float:
    """technical severity -> [0,1]; ถ้ามี CVSS ใช้ผสม (เฉลี่ยกับ mapping ของ severity)"""
    base = _SEV_SCORE.get((severity or "INFORMATIONAL").upper(), 0.10)
    if cvss is not None:
        try:
            c = _clamp(float(cvss) / 10.0)
            return round((base + c) / 2.0, 3)
        except (TypeError, ValueError):
            pass
    return base


def exploitability_factor(verification: str, *, accessible: Optional[bool],
                          auth_required: Optional[bool],
                          reproducible: Optional[bool],
                          theoretical: bool = False) -> float:
    """exploitability จากสถานะยืนยัน + การเข้าถึง + auth — penalize ของทฤษฎีล้วน"""
    base, _ = _VERIF.get((verification or "observed").lower(), (0.30, False))
    f = base
    if accessible is True:
        f += 0.10
    elif accessible is False:
        f -= 0.15
    if auth_required is True:
        f -= 0.10          # ต้อง auth = ใช้ประโยชน์ยากขึ้น
    if reproducible is True:
        f += 0.10
    elif reproducible is False:
        f -= 0.10
    if theoretical:
        f -= 0.20          # observation เชิงทฤษฎีล้วน
    return round(_clamp(f), 3)


def asset_criticality_factor(*, exposure: str, importance: Optional[str],
                             related_assets: int, related_findings: int,
                             is_api_sensitive: bool = False) -> float:
    """asset context: exposure + ความสำคัญ + จำนวน asset/finding ที่เกี่ยวข้อง"""
    f = _EXPOSURE_SCORE.get((exposure or "unknown").lower(), 0.6) * 0.6
    imp = {"CRITICAL": 0.4, "HIGH": 0.3, "MEDIUM": 0.2, "LOW": 0.1}.get(
        (importance or "MEDIUM").upper(), 0.2)
    f += imp
    # asset ที่สัมพันธ์กันมาก / finding หลายตัวบน asset = พื้นที่โจมตีสำคัญกว่า
    f += _clamp(related_assets / 20.0, 0, 0.15)
    f += _clamp(related_findings / 10.0, 0, 0.15)
    if is_api_sensitive:
        f += 0.05
    return round(_clamp(f), 3)


def evidence_confidence_factor(*, base_confidence: float,
                               supporting_count: int, integrity_ok: bool,
                               verified: bool, contradictory: bool,
                               source_reliability: float = 0.7) -> float:
    """evidence confidence: จำนวนหลักฐานอิสระ + integrity + ความขัดแย้ง + ความน่าเชื่อของแหล่ง"""
    f = _clamp(float(base_confidence or 0.0)) * 0.5
    f += _clamp(supporting_count / 5.0, 0, 0.25)   # หลายหลักฐานอิสระ = มั่นใจกว่า
    f += 0.15 if integrity_ok else 0.0
    f += 0.10 if verified else 0.0
    f += _clamp(source_reliability - 0.5, -0.1, 0.1)
    if contradictory:
        f -= 0.25                                   # มีหลักฐานขัดแย้ง = ลดความมั่นใจ
    return round(_clamp(f), 3)


def score_finding(factors: Dict[str, float], *, severity: str, verification: str,
                  weights: Optional[Dict[str, float]] = None,
                  confidence_threshold: float = 0.70) -> Dict[str, Any]:
    """รวมปัจจัยเป็นคะแนน + priority + คำอธิบาย (ไม่แก้ค่า severity เดิม)

    factors: {severity, exploitability, asset_criticality, evidence_confidence} ∈ [0,1]
    """
    w = dict(DEFAULT_WEIGHTS)
    if weights:
        w.update({k: v for k, v in weights.items() if k in DEFAULT_WEIGHTS})
    total_w = sum(w.values()) or 1.0

    contrib = {k: factors.get(k, 0.0) * w[k] for k in w}
    base = 100.0 * sum(contrib.values()) / total_w
    explanation: List[str] = [
        f"{k}={factors.get(k,0):.2f}×w{w[k]:.2f} -> {100*contrib[k]/total_w:.1f}" for k in w]

    sev_rank = _SEV_RANK.get((severity or "INFORMATIONAL").upper(), 0)
    verif = (verification or "observed").lower()
    _, is_verified = _VERIF.get(verif, (0.30, False))
    evid = factors.get("evidence_confidence", 0.0)

    # ไม่ลดเกรดของร้ายแรงที่ยืนยันแล้ว: floor คะแนน
    if sev_rank >= 3 and is_verified:
        if base < 75:
            explanation.append(f"floor: severity {severity}+verified -> score ≥ 75")
        base = max(base, 75.0)

    score = int(round(_clamp(base, 0, 100)))

    # priority bucket จากคะแนน
    if score >= 85:
        priority = "CRITICAL"
    elif score >= 70:
        priority = "HIGH"
    elif score >= 45:
        priority = "MEDIUM"
    elif score >= 20:
        priority = "LOW"
    else:
        priority = "INFORMATIONAL"

    # NEEDS_VERIFICATION: ของที่มีนัย (>=MEDIUM) แต่ยังไม่ยืนยัน + หลักฐานต่ำ -> ต้องทดสอบเพิ่ม
    # (ไม่ปัดตกเป็น LOW เงียบ ๆ — คงคะแนนไว้ให้เห็นความเสี่ยงแฝง)
    needs_verification = (sev_rank >= 2 and not is_verified and evid < confidence_threshold)
    if needs_verification:
        explanation.append(
            f"NEEDS_VERIFICATION: severity {severity} แต่ยังไม่ยืนยัน (verification={verif}) "
            f"และ evidence_confidence {evid:.2f} < {confidence_threshold}")
        priority = "NEEDS_VERIFICATION"

    return {
        "risk_score": score,
        "risk_priority": priority,
        "model_version": MODEL_VERSION,
        "weights": w,
        "factors": factors,
        "score_explanation": explanation,
        "needs_verification": needs_verification,
    }
