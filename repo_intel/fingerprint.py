# -*- coding: utf-8 -*-
"""
repo_intel.fingerprint — ระบุว่า repo นี้เป็นโปรเจกต์แบบไหน รันยังไง (อ่านอย่างเดียว)

เดินไฟล์ในเวิร์กสเปซ (ข้าม .git) เพื่อสรุป: ภาษาเด่น, package manager, ไฟล์ manifest,
entrypoint ที่น่าจะรันได้, คำสั่งรันที่พบใน README/manifest, และมีชุดเทสไหม
ทั้งหมดเป็นการ "อ่าน" ล้วน ไม่รันอะไร (การรันจริงอยู่ใน probe.py)
"""

import os
import re
import json
import logging
from typing import List, Optional

from .model import Fingerprint

logger = logging.getLogger("modbot.repo_intel.fingerprint")

_MAX_WALK = 6000
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
              "build", ".tox", ".mypy_cache", ".pytest_cache", "vendor"}

# นามสกุล -> ชื่อภาษา (นับความถี่เพื่อหา primary language)
_EXT_LANG = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".jsx": "JavaScript",
    ".tsx": "TypeScript", ".go": "Go", ".rs": "Rust", ".java": "Java",
    ".rb": "Ruby", ".php": "PHP", ".c": "C", ".h": "C", ".cpp": "C++",
    ".cc": "C++", ".cs": "C#", ".sh": "Shell", ".ps1": "PowerShell",
    ".pl": "Perl", ".lua": "Lua", ".kt": "Kotlin", ".swift": "Swift",
}

# manifest -> package manager
_MANIFEST_PM = {
    "requirements.txt": "pip", "pyproject.toml": "pip", "setup.py": "pip",
    "setup.cfg": "pip", "Pipfile": "pipenv",
    "package.json": "npm", "yarn.lock": "yarn", "pnpm-lock.yaml": "pnpm",
    "go.mod": "go", "Cargo.toml": "cargo", "pom.xml": "maven",
    "build.gradle": "gradle", "Gemfile": "bundler", "composer.json": "composer",
    "Makefile": "make", "Dockerfile": "docker", "CMakeLists.txt": "cmake",
}

_ENTRYPOINT_NAMES = ("main.py", "app.py", "__main__.py", "cli.py", "run.py",
                     "manage.py", "index.js", "server.js", "main.go",
                     "main.rs", "main.c")

_RUN_HINT_RE = re.compile(
    r"(?m)^\s*\$?\s*((?:python[3]?|node|npm|yarn|go|cargo|docker|make|"
    r"\./[\w./-]+|bash|sh)\s+[^\n`]{1,120})")


def _read(path: str, limit: int = 200_000) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            return f.read(limit).decode("utf-8", "ignore")
    except OSError:
        return None


def _has_main_guard(path: str) -> bool:
    text = _read(path, 65536) or ""
    return 'if __name__' in text and '__main__' in text


def build(workspace_path: str, *, test_runner: Optional[str] = None,
          has_tests: bool = False) -> Fingerprint:
    fp = Fingerprint(test_runner=test_runner, has_tests=has_tests)
    manifests_seen = set()
    entrypoints: List[str] = []
    readmes: List[str] = []
    scanned = 0

    for root, dirs, files in os.walk(workspace_path, followlinks=False):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            scanned += 1
            if scanned > _MAX_WALK:
                break
            fpath = os.path.join(root, fname)
            if os.path.islink(fpath):
                continue
            rel = os.path.relpath(fpath, workspace_path).replace(os.sep, "/")
            try:
                fp.total_size_bytes += os.path.getsize(fpath)
            except OSError:
                pass
            fp.total_files += 1

            ext = os.path.splitext(fname)[1].lower()
            lang = _EXT_LANG.get(ext)
            if lang:
                fp.languages[lang] = fp.languages.get(lang, 0) + 1

            if fname in _MANIFEST_PM and rel.count("/") <= 2:
                manifests_seen.add(fname)
                if rel not in fp.manifests:
                    fp.manifests.append(rel)

            if fname in _ENTRYPOINT_NAMES and rel.count("/") <= 3:
                entrypoints.append(rel)
            elif ext == ".py" and rel.count("/") == 0 and _has_main_guard(fpath):
                entrypoints.append(rel)

            if fname.lower().startswith("readme"):
                readmes.append(fpath)

    # package managers จาก manifest ที่พบ
    for m in sorted(manifests_seen):
        pm = _MANIFEST_PM.get(m)
        if pm and pm not in fp.package_managers:
            fp.package_managers.append(pm)

    # primary language = ภาษาที่ไฟล์เยอะสุด
    if fp.languages:
        fp.primary_language = max(fp.languages.items(), key=lambda kv: kv[1])[0]

    # entrypoint จาก package.json (main/bin) เพิ่มเติม
    for rel in list(fp.manifests):
        if rel.endswith("package.json"):
            data = _read(os.path.join(workspace_path, rel))
            try:
                pkg = json.loads(data) if data else {}
            except (json.JSONDecodeError, ValueError):
                pkg = {}
            if isinstance(pkg, dict):
                if isinstance(pkg.get("main"), str):
                    entrypoints.append(pkg["main"])
                binv = pkg.get("bin")
                if isinstance(binv, str):
                    entrypoints.append(binv)
                elif isinstance(binv, dict):
                    entrypoints.extend(v for v in binv.values() if isinstance(v, str))

    # ดึงคำสั่งรันจาก README (สูงสุด 12 บรรทัด)
    hints: List[str] = []
    for rp in readmes[:2]:
        text = _read(rp) or ""
        for m in _RUN_HINT_RE.findall(text):
            cmd = m.strip()
            if cmd and cmd not in hints:
                hints.append(cmd)
            if len(hints) >= 12:
                break
    fp.run_hints = hints

    # dedupe entrypoints คงลำดับ
    seen = set()
    fp.entrypoints = [e for e in entrypoints if not (e in seen or seen.add(e))][:10]
    return fp
