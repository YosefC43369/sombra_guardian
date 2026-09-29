# -*- coding: utf-8 -*-
"""
repo_intel.capabilities.disasm — #14 Headless disassembly / binary analysis

ถ้า repo แถมไฟล์ที่คอมไพล์แล้ว (EXE/DLL/SO/ELF) และเครื่องนี้มีเครื่องมือวิเคราะห์
ไร้หน้าจอ (objdump / nm / rabin2) ให้ดึงข้อมูลหัวไฟล์ + สัญลักษณ์ออกมาเป็นหลักฐาน
ถ้าไม่มีเครื่องมือ → คืน UNAVAILABLE พร้อมบอกว่าต้องติดตั้งอะไร (ไม่ปั้นผล)
"""

import os
import shutil
import subprocess
from typing import List, Optional

from ..model import CapabilityResult, CapabilityStatus

_BINARY_EXTS = (".exe", ".dll", ".so", ".dylib", ".elf", ".o")
_TOOLS = ("rabin2", "objdump", "nm", "file")


def _find_binary(ws: str) -> Optional[str]:
    for root, dirs, files in os.walk(ws, followlinks=False):
        if ".git" in dirs:
            dirs.remove(".git")
        for f in files:
            if os.path.splitext(f)[1].lower() in _BINARY_EXTS:
                return os.path.join(root, f)
    return None


def _run_tool(cmd: List[str]) -> Optional[str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return (p.stdout or p.stderr)[:4000]
    except (OSError, subprocess.SubprocessError):
        return None


def run(ctx) -> CapabilityResult:
    ws = ctx.workspace_path
    binpath = _find_binary(ws)
    available = [t for t in _TOOLS if shutil.which(t)]

    if binpath is None:
        return CapabilityResult("Headless Disassembly", CapabilityStatus.CLEAN.value,
                                "repo ไม่มีไฟล์ไบนารีที่คอมไพล์แล้วให้วิเคราะห์")
    if not available:
        return CapabilityResult(
            "Headless Disassembly", CapabilityStatus.UNAVAILABLE.value,
            "พบไบนารีแต่เครื่องนี้ไม่มีเครื่องมือวิเคราะห์",
            data={"binary": os.path.relpath(binpath, ws),
                  "requires": "ติดตั้ง radare2 (rabin2) หรือ binutils (objdump/nm)"})

    rel = os.path.relpath(binpath, ws)
    out = {}
    if "file" in available:
        r = _run_tool(["file", binpath])
        if r:
            out["file"] = r.strip()
    if "rabin2" in available:
        r = _run_tool(["rabin2", "-I", binpath])
        if r:
            out["rabin2_info"] = r
    elif "objdump" in available:
        r = _run_tool(["objdump", "-f", binpath])
        if r:
            out["objdump_header"] = r
    if "nm" in available:
        r = _run_tool(["nm", "-D", "--defined-only", binpath])
        if r:
            out["exported_symbols"] = "\n".join(r.splitlines()[:40])

    return CapabilityResult(
        "Headless Disassembly", CapabilityStatus.OK.value,
        f"วิเคราะห์ไบนารี {rel} ด้วย {', '.join(available)}",
        data={"binary": rel, "analysis": out})
