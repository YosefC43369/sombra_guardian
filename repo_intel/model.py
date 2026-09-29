# -*- coding: utf-8 -*-
"""
repo_intel.model — ชนิดข้อมูลกลางของโมดูลวิเคราะห์ repository

ทุก dataclass ที่นี่เป็น "ข้อเท็จจริงที่จับต้องได้" (serializable) — ตัวเลข exit code,
เอาต์พุตจริง, ธง ran/tested — เพื่อให้ชั้นสรุป (verdict/summarize/report) สร้างคำตอบ
จาก "หลักฐาน" เท่านั้น ไม่ใช่จากการเดา นี่คือกระดูกสันหลังของกฎเหล็ก:
"ถ้าไม่ได้เทส ห้ามบอกว่าเทสแล้ว / ถ้าเทสแล้ว error ห้ามบอกว่าผ่าน"

ไม่พึ่ง scope_policy.py และไม่ import ข้ามไปหามันเด็ดขาด (ข้อกำหนดของโมดูลนี้)
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class ProbeKind(str, Enum):
    INSTALL = "install"        # ติดตั้ง dependency (pip/npm) ในแซนด์บ็อกซ์
    TEST = "test"              # รันชุดเทสของ repo จริง
    SMOKE = "smoke"            # เรียก entrypoint --help/--version เพื่อดูว่าสตาร์ตติดไหม
    BUILD = "build"            # compile/build step (go build ฯลฯ)


@dataclass
class Evidence:
    """หลักฐานการรันหนึ่งครั้งในแซนด์บ็อกซ์ — ``ran`` คือหัวใจ: True ก็ต่อเมื่อ
    subprocess ถูกเรียกจริงและได้ผลกลับมา ค่าอื่น ๆ ทั้งหมดต้องมาจากการรันนั้น"""
    kind: str
    ran: bool
    command: List[str] = field(default_factory=list)
    returncode: Optional[int] = None
    passed: Optional[bool] = None          # returncode == 0 (เฉพาะเมื่อ ran)
    timed_out: bool = False
    output_excerpt: str = ""
    duration_seconds: Optional[float] = None
    skipped_reason: Optional[str] = None   # ตั้งเมื่อ ran=False (ปิดสวิตช์/ไม่มี runner/ฯลฯ)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """ข้อค้นพบเชิงสถิต (จาก capability analyzer) — อ้างอิงตำแหน่งจริงในไฟล์เสมอ"""
    capability: str
    severity: str                          # info | low | medium | high | critical
    title: str
    detail: str = ""
    location: str = ""                     # path:line
    confidence: str = "medium"             # low | medium | high

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CapabilityStatus(str, Enum):
    OK = "ok"                    # รันได้และมีผล
    CLEAN = "clean"              # รันได้ ไม่พบอะไร
    UNAVAILABLE = "unavailable"  # ต้องใช้เครื่องมือ/ข้อมูลที่ไม่มีในเครื่องนี้
    NOT_IMPLEMENTED = "not_implemented"  # เป็น roadmap ยังไม่ลงมือ (บอกตรง ๆ)
    ERROR = "error"


@dataclass
class CapabilityResult:
    name: str
    status: str
    summary: str = ""
    findings: List[Finding] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


class VerdictStatus(str, Enum):
    USABLE = "usable"                    # เทสจริงแล้วผ่าน
    PARTIALLY_USABLE = "partially_usable"  # รันได้บางส่วน/เทสบางส่วนผ่าน
    NOT_USABLE = "not_usable"            # เทสจริงแล้วพัง (มีหลักฐาน error)
    UNTESTED = "untested"                # ยังไม่ได้รันเทส (ไม่มี runner/ปิดสวิตช์) — ห้ามบอกว่าเทสแล้ว
    UNKNOWN = "unknown"


@dataclass
class Verdict:
    status: str
    tested: bool                         # True ก็ต่อเมื่อมี Evidence.ran จริงอย่างน้อยหนึ่ง
    reasons: List[str] = field(default_factory=list)
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Fingerprint:
    languages: Dict[str, int] = field(default_factory=dict)   # ext -> count
    primary_language: Optional[str] = None
    package_managers: List[str] = field(default_factory=list)
    manifests: List[str] = field(default_factory=list)
    entrypoints: List[str] = field(default_factory=list)
    run_hints: List[str] = field(default_factory=list)        # คำสั่งรันที่พบใน README/manifest
    has_tests: bool = False
    test_runner: Optional[str] = None
    total_files: int = 0
    total_size_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RepoIntelReport:
    repository_id: Any
    repo: str
    created_at: str
    fingerprint: Fingerprint
    evidence: List[Evidence] = field(default_factory=list)
    capabilities: List[CapabilityResult] = field(default_factory=list)
    verdict: Optional[Verdict] = None
    ai_summary: str = ""
    ai_provider: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repository_id": self.repository_id,
            "repo": self.repo,
            "created_at": self.created_at,
            "fingerprint": self.fingerprint.to_dict(),
            "evidence": [e.to_dict() for e in self.evidence],
            "capabilities": [c.to_dict() for c in self.capabilities],
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "ai_summary": self.ai_summary,
            "ai_provider": self.ai_provider,
            "notes": self.notes,
        }

    def facts_bundle(self) -> Dict[str, Any]:
        """ชุด "ข้อเท็จจริงล้วน" ที่ป้อนให้ AI สรุป — ตัดเอาต์พุตยาว ๆ ให้พอดี
        ห้ามมีอะไรที่ AI ต้องเดา ทุกฟิลด์คือสิ่งที่วัด/รันมาได้จริง"""
        return {
            "repo": self.repo,
            "fingerprint": self.fingerprint.to_dict(),
            "execution_evidence": [e.to_dict() for e in self.evidence],
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "capabilities": [
                {"name": c.name, "status": c.status, "summary": c.summary,
                 "findings": [f.to_dict() for f in c.findings[:15]]}
                for c in self.capabilities
            ],
        }
