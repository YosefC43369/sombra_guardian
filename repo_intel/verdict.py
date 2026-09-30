# -*- coding: utf-8 -*-
"""
repo_intel.verdict — เครื่องตัดสิน "ปัจจุบัน repo นี้ยังใช้งานได้ไหม" จากหลักฐานล้วน

นี่คือหัวใจของกฎเหล็กที่ dj กำหนด:
  - ``tested`` เป็น True ก็ต่อเมื่อมีการ "รันโค้ดของ repo จริง" (test/smoke/build)
    อย่างน้อยหนึ่งครั้งที่ ran=True — ติดตั้ง dependency อย่างเดียวไม่นับว่า "เทสแล้ว"
  - สถานะ USABLE ให้ได้ก็ต่อเมื่อ "เทสจริงแล้วผ่าน" เท่านั้น
  - เทสจริงแล้ว error/ตกเวลา → NOT_USABLE (พร้อมเหตุผลจากหลักฐาน) ห้ามบอกว่าผ่าน
  - ไม่มี runner / ปิดสวิตช์ / รันไม่ได้ → UNTESTED ห้ามบอกว่าเทสแล้ว

เป็นฟังก์ชันบริสุทธิ์ (pure) รับ list[Evidence] คืน Verdict — เทสต์ได้โดยไม่ต่อเน็ต
ไม่มีการเรียก AI ที่นี่ (AI แค่ "เรียบเรียง" ผลนี้ ห้ามเปลี่ยนคำตัดสิน)
"""

from typing import List

from .model import Evidence, ProbeKind, Verdict, VerdictStatus


# kinds ที่ถือว่าเป็น "การรันโค้ดของ repo จริง" (ติดตั้ง dependency ไม่เข้าข่าย)
_RUN_KINDS = {ProbeKind.TEST.value, ProbeKind.SMOKE.value, ProbeKind.BUILD.value}


def decide(evidence: List[Evidence]) -> Verdict:
    ran = [e for e in evidence if e.ran]
    run_ev = [e for e in ran if e.kind in _RUN_KINDS]
    tested = len(run_ev) > 0

    test_ev = [e for e in ran if e.kind == ProbeKind.TEST.value]
    smoke_ev = [e for e in ran if e.kind == ProbeKind.SMOKE.value]
    build_ev = [e for e in ran if e.kind == ProbeKind.BUILD.value]
    install_ev = [e for e in evidence if e.kind == ProbeKind.INSTALL.value]
    install_ok = any(e.ran and e.passed for e in install_ev)
    install_failed = any(e.ran and e.passed is False for e in install_ev)

    reasons: List[str] = []

    # ---- ไม่ได้รันโค้ด repo เลย → UNTESTED ----
    if not tested:
        if not evidence:
            reasons.append("ยังไม่ได้ probe อะไรเลย")
        else:
            for e in evidence:
                if not e.ran and e.skipped_reason:
                    reasons.append(f"{e.kind}: ไม่ได้รัน ({e.skipped_reason})")
        if not reasons:
            reasons.append("ไม่มีชุดเทส/entrypoint ที่รันได้ในสภาพแวดล้อมนี้")
        return Verdict(status=VerdictStatus.UNTESTED.value, tested=False,
                       reasons=reasons, confidence="high")

    # ---- มีการรันเทสจริง → ตัดสินจาก returncode จริง ----
    if test_ev:
        passed_any = any(e.passed for e in test_ev)
        failed_any = any(e.passed is False or e.timed_out for e in test_ev)
        if passed_any and not failed_any:
            reasons.append("ชุดเทสของ repo รันแล้วผ่านทั้งหมด (returncode 0)")
            if smoke_ev and all(e.passed for e in smoke_ev):
                reasons.append("entrypoint สตาร์ตได้")
            return Verdict(status=VerdictStatus.USABLE.value, tested=True,
                           reasons=reasons, confidence="high")
        if passed_any and failed_any:
            reasons.append("ชุดเทสผ่านบางส่วน ล้มเหลวบางส่วน")
            return Verdict(status=VerdictStatus.PARTIALLY_USABLE.value, tested=True,
                           reasons=reasons, confidence="medium")
        # ทุกเทสล้ม
        for e in test_ev:
            if e.timed_out:
                reasons.append("ชุดเทสรันไม่จบในเวลาที่กำหนด (timeout)")
            elif e.passed is False:
                reasons.append(f"ชุดเทสล้มเหลว (returncode {e.returncode})")
        if install_failed:
            reasons.append("หมายเหตุ: ติดตั้ง dependency ไม่สำเร็จ — ความล้มเหลวอาจมาจาก"
                           "สภาพแวดล้อมบางส่วน แต่ในสภาพปัจจุบันยังรันไม่ผ่าน")
        return Verdict(status=VerdictStatus.NOT_USABLE.value, tested=True,
                       reasons=reasons, confidence="high" if install_ok else "medium")

    # ---- ไม่มีเทส แต่ smoke/build รันจริง ----
    if smoke_ev or build_ev:
        good = [e for e in (smoke_ev + build_ev) if e.passed]
        bad = [e for e in (smoke_ev + build_ev) if e.passed is False or e.timed_out]
        if good and not bad:
            reasons.append("entrypoint/บิลด์รันได้ แต่ repo ไม่มีชุดเทสให้ยืนยันพฤติกรรม")
            return Verdict(status=VerdictStatus.PARTIALLY_USABLE.value, tested=True,
                           reasons=reasons, confidence="medium")
        if bad and not good:
            reasons.append("entrypoint/บิลด์รันไม่ผ่าน (มี error จริง)")
            return Verdict(status=VerdictStatus.NOT_USABLE.value, tested=True,
                           reasons=reasons, confidence="medium")
        reasons.append("entrypoint/บิลด์รันได้บางส่วน")
        return Verdict(status=VerdictStatus.PARTIALLY_USABLE.value, tested=True,
                       reasons=reasons, confidence="low")

    return Verdict(status=VerdictStatus.UNKNOWN.value, tested=tested,
                   reasons=["สรุปสถานะไม่ได้จากหลักฐานที่มี"], confidence="low")


def verdict_banner(status: str) -> str:
    """อีโมจิ+ข้อความสั้นสำหรับหัวรายงาน (ธีมแฮกเกอร์เรียบง่าย)"""
    return {
        VerdictStatus.USABLE.value: "🟢 ใช้งานได้ (เทสจริงแล้วผ่าน)",
        VerdictStatus.PARTIALLY_USABLE.value: "🟡 ใช้งานได้บางส่วน (รันได้ แต่ไม่ครบ)",
        VerdictStatus.NOT_USABLE.value: "🔴 ใช้งานไม่ได้ (เทสจริงแล้วพัง)",
        VerdictStatus.UNTESTED.value: "⚪ ยังไม่ได้เทส (ไม่มี runner/รันไม่ได้ในสภาพแวดล้อมนี้)",
        VerdictStatus.UNKNOWN.value: "❔ สรุปไม่ได้",
    }.get(status, "❔ สรุปไม่ได้")
