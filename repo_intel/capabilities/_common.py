# -*- coding: utf-8 -*-
"""repo_intel.capabilities._common — เครื่องมือช่วยที่ capability ใช้ร่วมกัน (อ่านล้วน)"""

import os
from typing import Iterator, List, Optional, Tuple

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
              "build", ".tox", ".mypy_cache", ".pytest_cache", "vendor"}
_MAX_FILES = 4000
_MAX_BYTES = 400_000


def read_text(path: str, limit: int = _MAX_BYTES) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            return f.read(limit).decode("utf-8", "ignore")
    except OSError:
        return None


def iter_files(workspace_path: str, exts: Optional[Tuple[str, ...]] = None
               ) -> Iterator[Tuple[str, str]]:
    """คืน (abs_path, rel_posix) ของไฟล์ในเวิร์กสเปซ ข้ามโฟลเดอร์ที่ไม่เกี่ยว
    exts=None = ทุกไฟล์; ระบุ tuple นามสกุล (รวมจุด) เพื่อกรอง"""
    scanned = 0
    for root, dirs, files in os.walk(workspace_path, followlinks=False):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            scanned += 1
            if scanned > _MAX_FILES:
                return
            if exts is not None and os.path.splitext(fname)[1].lower() not in exts:
                continue
            full = os.path.join(root, fname)
            if os.path.islink(full):
                continue
            yield full, os.path.relpath(full, workspace_path).replace(os.sep, "/")


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1
