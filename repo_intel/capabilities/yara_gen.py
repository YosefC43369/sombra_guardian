# -*- coding: utf-8 -*-
"""
repo_intel.capabilities.yara_gen — #5 YARA rule generator (ส่วน generator)

สร้างกฎ YARA เบื้องต้นจาก "สายอักขระเด่น" ในอาร์ติแฟกต์ของ repo (ไบนารีถ้ามี ไม่งั้น
สคริปต์ฝั่ง entrypoint) เพื่อใช้เป็นจุดตั้งต้นในการวิเคราะห์ว่าเครื่องมือนี้ถูกตรวจจับ
อย่างไร กฎที่ได้เป็น "ข้อมูล/ข้อความ" ไม่ถูกรัน

หมายเหตุความซื่อสัตย์: ส่วน "generator" ทำได้จริงและอยู่ในนี้ ส่วน "วนปรับโค้ดใน
sandbox จนหลบกฎได้" (evasion loop) ยังไม่ได้ลงมือ — ประกาศไว้ใน roadmap.py ตรง ๆ
"""

import os
import re
import string
from collections import Counter
from typing import List, Optional

from ..model import CapabilityResult, CapabilityStatus
from ._common import read_text

_BINARY_EXTS = (".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".elf")
_PRINTABLE = set(bytes(string.printable, "ascii")) - set(b"\t\n\r\x0b\x0c")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_./\\:-]{6,40}")
_COMMON = {"function", "return", "import", "require", "module", "exports",
           "console", "python", "string", "object", "length", "prototype"}


def _ascii_strings(data: bytes, min_len: int = 6) -> List[str]:
    out, cur = [], bytearray()
    for b in data:
        if b in _PRINTABLE:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", "ignore"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", "ignore"))
    return out


def _pick_binary(ws: str) -> Optional[str]:
    for root, dirs, files in os.walk(ws, followlinks=False):
        if ".git" in dirs:
            dirs.remove(".git")
        for f in files:
            if os.path.splitext(f)[1].lower() in _BINARY_EXTS:
                full = os.path.join(root, f)
                try:
                    if os.path.getsize(full) <= 20 * 1024 * 1024:
                        return full
                except OSError:
                    continue
    return None


def _rule_from_strings(name: str, strings: List[str]) -> str:
    # เลือก token ที่ไม่ธรรมดาและไม่ซ้ำมาก 8 ตัว
    counter = Counter()
    for s in strings:
        for tok in _TOKEN_RE.findall(s):
            low = tok.lower()
            if low in _COMMON or tok.isdigit():
                continue
            counter[tok] += 1
    picked = [tok for tok, _ in counter.most_common(40)]
    picked = sorted(set(picked), key=len, reverse=True)[:8]
    if not picked:
        return ""
    ruleid = re.sub(r"[^A-Za-z0-9_]", "_", name)[:40] or "repo_artifact"
    lines = [f"rule sg_{ruleid}", "{", "    strings:"]
    for i, tok in enumerate(picked):
        esc = tok.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'        $s{i} = "{esc}" ascii')
    lines += ["    condition:", "        3 of them", "}"]
    return "\n".join(lines)


def run(ctx) -> CapabilityResult:
    ws = ctx.workspace_path
    binpath = _pick_binary(ws)
    if binpath:
        try:
            with open(binpath, "rb") as f:
                data = f.read(4 * 1024 * 1024)
        except OSError:
            data = b""
        strings = _ascii_strings(data)
        source = os.path.relpath(binpath, ws)
    else:
        # ไม่มีไบนารี → ใช้สคริปต์ entrypoint เป็นแหล่งสตริง
        strings = []
        for rel in ctx.fingerprint.entrypoints[:2]:
            t = read_text(os.path.join(ws, rel))
            if t:
                strings.extend(t.splitlines())
        source = ", ".join(ctx.fingerprint.entrypoints[:2]) or "(ไม่มี entrypoint)"

    rule = _rule_from_strings(ctx.fingerprint.primary_language or "repo", strings)
    if not rule:
        return CapabilityResult("YARA Rule Generator", CapabilityStatus.CLEAN.value,
                                "ไม่มีสตริงเด่นพอจะสร้างกฎ")
    return CapabilityResult(
        "YARA Rule Generator", CapabilityStatus.OK.value,
        f"สร้างกฎ YARA ตั้งต้นจาก {source} (evasion-loop ยังไม่ลงมือ — ดู roadmap)",
        data={"source": source, "yara_rule": rule})
