# -*- coding: utf-8 -*-
"""
repo_intel.capabilities.vuln_scan — #1 Automated Vulnerability Identification + PoC scaffold

สแกนเชิงสถิต (ไม่รันโค้ด) หาแพตเทิร์นที่มักเป็นช่องโหว่/พฤติกรรมอันตรายในตัว repo เอง
เช่น การรันคำสั่งจากอินพุต, deserialize ที่ไม่ปลอดภัย, ความลับฝังในโค้ด แล้วสร้าง
"โครงร่างชุดทดสอบ (PoC scaffold)" เป็นข้อความ unittest ที่ชี้ไปยังตำแหน่งที่พบ —
เป็นโครงให้ผู้ทดสอบเติม ไม่ใช่ exploit สำเร็จรูป และตัว scaffold เป็น "ข้อมูล" ไม่ถูกรัน

ทุกข้อค้นพบอ้างอิง path:line จริง — เป็นหลักฐาน ไม่ใช่การเดา
"""

import re
from typing import List

from ..model import CapabilityResult, CapabilityStatus, Finding
from ._common import iter_files, read_text, line_of

# (regex, severity, title) — แพตเทิร์นเชิงสถิตแบบอนุรักษ์ (เน้น false-positive ต่ำ)
_PATTERNS = [
    (re.compile(r"\bos\.system\s*\("), "high", "เรียก os.system() (อาจ command injection)"),
    (re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"), "high",
     "subprocess ที่ shell=True (เสี่ยง command injection)"),
    (re.compile(r"\beval\s*\("), "high", "ใช้ eval() กับข้อมูลที่อาจมาจากภายนอก"),
    (re.compile(r"\bexec\s*\("), "high", "ใช้ exec()"),
    (re.compile(r"pickle\.loads?\s*\("), "high", "pickle deserialize (RCE ถ้าข้อมูลไม่น่าเชื่อถือ)"),
    (re.compile(r"yaml\.load\s*\((?![^)]*Loader)"), "medium",
     "yaml.load() ไม่ระบุ SafeLoader"),
    (re.compile(r"marshal\.loads?\s*\("), "medium", "marshal deserialize"),
    (re.compile(r"hashlib\.md5\s*\(|hashlib\.sha1\s*\("), "low",
     "ใช้ hash ที่อ่อน (MD5/SHA1)"),
    (re.compile(r"verify\s*=\s*False"), "medium", "ปิดการตรวจใบรับรอง TLS (verify=False)"),
    (re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
     "high", "อาจมีความลับ (API key/secret/token) ฝังในโค้ด"),
    (re.compile(r"\brequest\.args\.get\([^)]*\).*(?:execute|system|eval)", re.I), "high",
     "อินพุตผู้ใช้ไหลเข้าฟังก์ชันอันตรายโดยตรง"),
    (re.compile(r"tempfile\.mktemp\s*\("), "low", "tempfile.mktemp() (race condition)"),
]

_SOURCE_EXTS = (".py", ".js", ".ts", ".rb", ".php", ".go", ".java", ".sh")


def run(ctx) -> CapabilityResult:
    findings: List[Finding] = []
    for full, rel in iter_files(ctx.workspace_path, _SOURCE_EXTS):
        text = read_text(full)
        if not text:
            continue
        for rx, severity, title in _PATTERNS:
            for m in rx.finditer(text):
                findings.append(Finding(
                    capability="vuln_scan", severity=severity, title=title,
                    detail=text[m.start():m.start() + 120].splitlines()[0].strip(),
                    location=f"{rel}:{line_of(text, m.start())}",
                    confidence="medium"))
                if len(findings) >= 200:
                    break
    # จัดเรียงตามความรุนแรง
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f.severity, 5))

    scaffold = _poc_scaffold(findings)
    status = CapabilityStatus.OK.value if findings else CapabilityStatus.CLEAN.value
    high = sum(1 for f in findings if f.severity in ("high", "critical"))
    summary = (f"พบจุดน่าสงสัย {len(findings)} จุด (รุนแรง/สูง {high})"
               if findings else "ไม่พบแพตเทิร์นอันตรายที่รู้จักในการสแกนเชิงสถิต")
    return CapabilityResult(
        name="Vulnerability ID + PoC scaffold", status=status, summary=summary,
        findings=findings[:60],
        data={"total": len(findings), "high": high, "poc_scaffold": scaffold})


def _poc_scaffold(findings: List[Finding]) -> str:
    """สร้างโครง unittest ชี้ไปยังจุดที่พบ (ข้อความล้วน ไม่ถูกรัน) — เป็นโครงให้เติม
    ห้ามใส่ payload โจมตีสำเร็จรูป: หน้าที่มันคือ 'พิสูจน์ว่าจุดนี้มีจริง/รับอินพุตยังไง'"""
    if not findings:
        return ""
    top = findings[:5]
    lines = [
        '"""PoC scaffold — เติม assertion เพื่อยืนยันจุดที่สแกนเจอ (สร้างอัตโนมัติ)"""',
        "import unittest", "",
        "class ProofOfConcept(unittest.TestCase):",
    ]
    for i, f in enumerate(top, 1):
        loc = f.location.replace("'", "")
        lines += [
            f"    def test_finding_{i}(self):",
            f"        # {f.title}",
            f"        # ตำแหน่ง: {loc}",
            "        # TODO: เรียกฟังก์ชัน/route ที่จุดนี้ด้วยอินพุตควบคุม แล้ว assert พฤติกรรม",
            "        self.skipTest('เติมขั้นตอนพิสูจน์ที่นี่')",
            "",
        ]
    lines += ['if __name__ == "__main__":', "    unittest.main()"]
    return "\n".join(lines)
