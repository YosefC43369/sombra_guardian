"""
cve_tracker.intelligence.exposure — describe how exposed a vulnerability is.

Reads the CVSS metrics already decoded on the record to characterise the attack
surface in plain terms (remotely reachable? needs credentials? needs a user to
click?). This feeds both the priority score's exposure component and the Thai
alert's '🌐 ช่องทางการโจมตี' lines. It asserts nothing the CVSS vector doesn't
say — no guessing about a specific deployment's exposure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from ..enrichment.cvss import pick_primary
from ..models import CVERecord, CVSSScore


@dataclass
class ExposureProfile:
    network_reachable: Optional[bool] = None
    requires_privileges: Optional[bool] = None
    requires_user_interaction: Optional[bool] = None
    attack_vector: str = ""
    attack_complexity: str = ""
    summary_th: str = ""

    @property
    def is_wormable_shape(self) -> bool:
        """Network + no privileges + no user interaction — the shape of the
        vulnerabilities that spread fastest. NOT a claim that an exploit exists."""
        return (self.network_reachable is True
                and self.requires_privileges is False
                and self.requires_user_interaction is False)


def assess(record: CVERecord) -> ExposureProfile:
    primary: Optional[CVSSScore] = pick_primary(record.cvss_scores)
    prof = ExposureProfile()
    if primary is None:
        prof.summary_th = "ไม่พบข้อมูล CVSS สำหรับประเมินช่องทางการโจมตี"
        return prof

    prof.attack_vector = primary.attack_vector
    prof.attack_complexity = primary.attack_complexity
    if primary.attack_vector:
        prof.network_reachable = primary.attack_vector == "Network"
    if primary.privileges_required:
        prof.requires_privileges = primary.privileges_required != "None"
    if primary.user_interaction:
        prof.requires_user_interaction = primary.user_interaction != "None"

    prof.summary_th = _summarize_th(prof)
    return prof


def _summarize_th(prof: ExposureProfile) -> str:
    bits: List[str] = []
    if prof.network_reachable is True:
        bits.append("โจมตีจากระยะไกลผ่านเครือข่ายได้")
    elif prof.network_reachable is False:
        bits.append(f"ต้องเข้าถึงในระดับ {prof.attack_vector or 'local'}")
    if prof.requires_privileges is False:
        bits.append("ไม่ต้องมีสิทธิ์ล่วงหน้า")
    elif prof.requires_privileges is True:
        bits.append("ต้องมีสิทธิ์บางระดับ")
    if prof.requires_user_interaction is False:
        bits.append("ไม่ต้องอาศัยการกระทำของผู้ใช้")
    elif prof.requires_user_interaction is True:
        bits.append("ต้องอาศัยการกระทำของผู้ใช้")
    if prof.is_wormable_shape:
        bits.append("(รูปแบบที่แพร่กระจายได้เร็ว)")
    return " ".join(bits) if bits else "ไม่ระบุ"
