# -*- coding: utf-8 -*-
"""
repo_intel.capabilities.supply_chain — #9 Supply Chain & Dependency Poisoning Analyzer

ตรวจไฟล์ประกาศ dependency (requirements.txt / package.json / setup.py) หา:
  - เวอร์ชันที่ไม่ pin (เสี่ยงดึงของใหม่ที่ถูกวางยา)
  - ชื่อแพ็กเกจที่คล้ายของยอดนิยมจนน่าสงสัย (typosquat/confusable)
  - install hook อันตราย (npm preinstall/postinstall, setup.py ที่มีการต่อเน็ต/exec)
อ่านล้วน ไม่ติดตั้ง/ไม่รันอะไร (การติดตั้งจริงอยู่ที่ probe.py แยกกัน)
"""

import os
import re
import json
from typing import List

from ..model import CapabilityResult, CapabilityStatus, Finding
from ._common import read_text

# แพ็กเกจยอดนิยม (ไว้เทียบ typosquat ด้วยระยะแก้ไข 1)
_POPULAR = {
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "pytest",
    "setuptools", "cryptography", "boto3", "pillow", "scipy", "click",
    "express", "react", "lodash", "axios", "chalk", "commander", "debug",
    "colorama", "pyyaml", "beautifulsoup4", "selenium", "tensorflow",
}
_DANGEROUS_HOOKS = ("preinstall", "postinstall", "install", "prepare")
_NETWORK_IN_SETUP = re.compile(r"(urllib|requests\.|socket\.|urlopen|subprocess|os\.system|exec\()")


def _levenshtein1(a: str, b: str) -> bool:
    """คืน True ถ้าระยะแก้ไข <= 1 (พอสำหรับจับ typosquat แบบเบา)"""
    if a == b:
        return False  # เหมือนกันเป๊ะ ไม่ใช่ typosquat
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        return sum(1 for x, y in zip(a, b) if x != y) == 1
    # ต่างกัน 1 ตัว: ตรวจ insertion/deletion เดียว
    short, long = (a, b) if la < lb else (b, a)
    i = j = 0
    edits = 0
    while i < len(short) and j < len(long):
        if short[i] == long[j]:
            i += 1
            j += 1
        else:
            edits += 1
            j += 1
            if edits > 1:
                return False
    return True


def _check_typosquat(name: str) -> bool:
    low = name.lower()
    return any(_levenshtein1(low, p) for p in _POPULAR)


def _scan_requirements(text: str, rel: str, findings: List[Finding]) -> int:
    n = 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        n += 1
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(.*)$", line)
        if not m:
            continue
        name, spec = m.group(1), m.group(2)
        if not spec or ("==" not in spec and "@" not in spec):
            findings.append(Finding("supply_chain", "medium",
                                    f"dependency ไม่ pin เวอร์ชัน: {name}",
                                    detail=line, location=f"{rel}:{i}", confidence="high"))
        if _check_typosquat(name):
            findings.append(Finding("supply_chain", "high",
                                    f"ชื่อแพ็กเกจคล้ายของยอดนิยม (อาจ typosquat): {name}",
                                    detail=line, location=f"{rel}:{i}", confidence="medium"))
    return n


def _scan_package_json(text: str, rel: str, findings: List[Finding]) -> int:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return 0
    if not isinstance(data, dict):
        return 0
    count = 0
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section)
        if isinstance(deps, dict):
            for name, ver in deps.items():
                count += 1
                if isinstance(ver, str) and (ver.startswith("^") or ver.startswith("~")
                                             or ver in ("*", "latest")):
                    findings.append(Finding("supply_chain", "medium",
                                            f"dependency ช่วงกว้าง/ไม่ pin: {name}@{ver}",
                                            location=rel, confidence="high"))
                if _check_typosquat(str(name)):
                    findings.append(Finding("supply_chain", "high",
                                            f"npm package คล้ายของยอดนิยม (typosquat?): {name}",
                                            location=rel, confidence="medium"))
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for hook in _DANGEROUS_HOOKS:
            if hook in scripts:
                findings.append(Finding("supply_chain", "high",
                                        f"มี install hook '{hook}' รันตอนติดตั้ง",
                                        detail=str(scripts[hook])[:160],
                                        location=rel, confidence="high"))
    return count


def run(ctx) -> CapabilityResult:
    ws = ctx.workspace_path
    findings: List[Finding] = []
    total_deps = 0

    req = os.path.join(ws, "requirements.txt")
    if os.path.isfile(req):
        total_deps += _scan_requirements(read_text(req) or "", "requirements.txt", findings)

    pkg = os.path.join(ws, "package.json")
    if os.path.isfile(pkg):
        total_deps += _scan_package_json(read_text(pkg) or "", "package.json", findings)

    setup = os.path.join(ws, "setup.py")
    if os.path.isfile(setup):
        stext = read_text(setup) or ""
        if _NETWORK_IN_SETUP.search(stext):
            findings.append(Finding("supply_chain", "high",
                                    "setup.py มีการต่อเน็ต/รันคำสั่ง (เสี่ยงรันตอน pip install)",
                                    location="setup.py", confidence="medium"))

    if total_deps == 0 and not findings:
        return CapabilityResult("Supply Chain Analyzer",
                                CapabilityStatus.CLEAN.value,
                                "ไม่พบไฟล์ประกาศ dependency ที่อ่านได้")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: order.get(f.severity, 4))
    status = CapabilityStatus.OK.value if findings else CapabilityStatus.CLEAN.value
    return CapabilityResult(
        "Supply Chain Analyzer", status,
        f"ตรวจ dependency ~{total_deps} รายการ พบประเด็น {len(findings)} จุด",
        findings=findings[:40], data={"dependencies": total_deps})
