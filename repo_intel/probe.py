# -*- coding: utf-8 -*-
"""
repo_intel.probe — รัน repo จริงในแซนด์บ็อกซ์ แล้วเก็บเป็น Evidence (หลักฐานล้วน)

ใช้เครื่องยนต์เดิมของ repository_sandbox.py ซ้ำ (ตัวรัน subprocess ที่คุมความเสี่ยงแล้ว:
arg-list ไม่ใช่ shell string, env ขั้นต่ำไม่มี secret, timeout, kill ทั้ง process group,
จำกัดเอาต์พุต) — ไม่สร้างตัวรันใหม่ให้ปลอดภัยน้อยกว่าเดิม

หลักการความซื่อสัตย์ (บังคับ):
- คำสั่งทุกตัวเป็น "เวกเตอร์อาร์กิวเมนต์ที่ allow-list ไว้" เท่านั้น ไม่เคยเอาสตริงจาก
  repo มารันเป็น shell (เช่นไม่แตะ scripts.test ที่เป็นข้อความ, ไม่ eval Makefile)
- Evidence.ran = True เฉพาะเมื่อ subprocess ถูกเรียกจริงและได้ผลกลับ
- ถ้าปิดสวิตช์/ไม่มี runner/ไฟล์ไม่อยู่ → ran=False + skipped_reason (ห้ามปั้นผล)

ไม่ import scope_policy และไม่อ้างอิงถึงมัน
"""

import os
import sys
import shutil
import logging
from typing import List, Optional

from .model import Evidence, ProbeKind

from envutil import env_int, env_bool
import repository_sandbox as rs
from github_repo import get_workspace_path

logger = logging.getLogger("modbot.repo_intel.probe")

# สวิตช์/งบเวลา — override ด้วย env ได้ ทุกตัวเคารพ TEST_EXECUTION_ENABLED เป็นสวิตช์ใหญ่
INSTALL_ENABLED = env_bool("REPO_ANALYZE_INSTALL", "true")
INSTALL_TIMEOUT = env_int("REPO_ANALYZE_INSTALL_TIMEOUT", 180)
SMOKE_ENABLED = env_bool("REPO_ANALYZE_SMOKE", "true")
SMOKE_TIMEOUT = env_int("REPO_ANALYZE_SMOKE_TIMEOUT", 30)
BUILD_TIMEOUT = env_int("REPO_ANALYZE_BUILD_TIMEOUT", 150)
_MAX_EXCERPT = 6000

# แฟล็ก smoke ที่ปลอดภัย (แค่ให้โปรแกรมพิมพ์ help/version แล้วออก — ไม่ทำงานจริง)
_SMOKE_FLAGS = ("--help", "-h", "--version", "-V")


def _excerpt(text: str) -> str:
    text = text or ""
    if len(text) <= _MAX_EXCERPT:
        return text
    head = text[: _MAX_EXCERPT - 400]
    tail = text[-400:]
    return head + "\n…[ตัดเอาต์พุตกลางออก]…\n" + tail


def _tmp_home():
    import tempfile
    return tempfile.mkdtemp(prefix="repo_intel_home_")


def _run(cmd: List[str], workspace_path: str, kind: str, timeout: int) -> Evidence:
    """เรียก _run_capped ของ repository_sandbox (มี sandbox env + timeout + output cap)"""
    tmp = _tmp_home()
    try:
        env = rs._sandbox_env(workspace_path, tmp)
        outcome = rs._run_capped(cmd, cwd=workspace_path, env=env,
                                 timeout_seconds=timeout,
                                 max_output_bytes=rs.MAX_TEST_OUTPUT_BYTES)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if outcome.get("exec_error"):
        return Evidence(kind=kind, ran=False, command=cmd,
                        skipped_reason=f"exec_error: {outcome.get('output','')[:200]}")
    rc = outcome.get("returncode")
    return Evidence(
        kind=kind, ran=True, command=cmd, returncode=rc,
        passed=(rc == 0) if rc is not None else None,
        timed_out=bool(outcome.get("timed_out")),
        output_excerpt=_excerpt(outcome.get("output", "")),
        duration_seconds=outcome.get("duration_seconds"),
    )


def _install_commands(workspace_path: str, fingerprint) -> List[List[str]]:
    """เลือกคำสั่งติดตั้ง dependency แบบ allow-list ตาม manifest ที่พบ"""
    cmds: List[List[str]] = []
    join = lambda n: os.path.join(workspace_path, n)
    if os.path.isfile(join("requirements.txt")):
        cmds.append([sys.executable, "-m", "pip", "install", "--no-input",
                     "--disable-pip-version-check", "-r", "requirements.txt"])
    elif any(os.path.isfile(join(n)) for n in ("pyproject.toml", "setup.py", "setup.cfg")):
        cmds.append([sys.executable, "-m", "pip", "install", "--no-input",
                     "--disable-pip-version-check", "."])
    if os.path.isfile(join("package.json")) and shutil.which("npm"):
        if os.path.isfile(join("package-lock.json")):
            cmds.append(["npm", "ci", "--no-audit", "--no-fund"])
        else:
            cmds.append(["npm", "install", "--no-audit", "--no-fund"])
    return cmds


def probe_install(repository_id, fingerprint) -> List[Evidence]:
    workspace_path = get_workspace_path(repository_id)
    if workspace_path is None:
        return [Evidence(kind=ProbeKind.INSTALL.value, ran=False,
                         skipped_reason="REPOSITORY_NOT_AVAILABLE")]
    if not rs.TEST_EXECUTION_ENABLED:
        return [Evidence(kind=ProbeKind.INSTALL.value, ran=False,
                         skipped_reason="TEST_EXECUTION_DISABLED")]
    if not INSTALL_ENABLED:
        return [Evidence(kind=ProbeKind.INSTALL.value, ran=False,
                         skipped_reason="REPO_ANALYZE_INSTALL=off")]
    cmds = _install_commands(workspace_path, fingerprint)
    if not cmds:
        return [Evidence(kind=ProbeKind.INSTALL.value, ran=False,
                         skipped_reason="ไม่พบ manifest ที่ติดตั้งได้ (requirements/package.json)")]
    return [_run(cmd, workspace_path, ProbeKind.INSTALL.value, INSTALL_TIMEOUT)
            for cmd in cmds]


def probe_test(repository_id, actor_user_id=None) -> Evidence:
    """ใช้ repository_sandbox.run_repository_tests เดิม (เส้นทางที่ audit แล้ว)
    แล้วแปลง TestRunResult -> Evidence"""
    result = rs.run_repository_tests(repository_id, actor_user_id)
    if not result.ok:
        # ok=False = การรันไม่เกิด/ถูกปฏิเสธ/timeout/เกินเอาต์พุต
        if result.timed_out:
            return Evidence(kind=ProbeKind.TEST.value, ran=True,
                            command=result.command, returncode=None, passed=False,
                            timed_out=True, output_excerpt=_excerpt(result.output),
                            duration_seconds=result.duration_seconds)
        return Evidence(kind=ProbeKind.TEST.value, ran=False,
                        command=result.command or [],
                        skipped_reason=result.reason or "รันเทสไม่ได้",
                        output_excerpt=_excerpt(result.output))
    return Evidence(
        kind=ProbeKind.TEST.value, ran=True, command=result.command,
        returncode=result.returncode, passed=bool(result.passed),
        output_excerpt=_excerpt(result.output),
        duration_seconds=result.duration_seconds)


def _valid_entry(workspace_path: str, rel: str) -> Optional[str]:
    """ยืนยันว่า entrypoint อยู่ในเวิร์กสเปซจริง ไม่ traversal ออกนอก"""
    if not rel:
        return None
    full = os.path.realpath(os.path.join(workspace_path, rel))
    root = os.path.realpath(workspace_path)
    if not (full == root or full.startswith(root + os.sep)):
        return None
    return full if os.path.isfile(full) else None


def probe_smoke(repository_id, fingerprint) -> List[Evidence]:
    """เรียก entrypoint ด้วยแฟล็ก --help/--version เพื่อดูว่า 'สตาร์ตติด' ไหม
    ทำเฉพาะเมื่อ repo ไม่มีชุดเทส (ถ้ามีเทส เราเชื่อผลเทสมากกว่า) หรือเพื่อยืนยันเสริม"""
    workspace_path = get_workspace_path(repository_id)
    if workspace_path is None:
        return [Evidence(kind=ProbeKind.SMOKE.value, ran=False,
                         skipped_reason="REPOSITORY_NOT_AVAILABLE")]
    if not (rs.TEST_EXECUTION_ENABLED and SMOKE_ENABLED):
        return [Evidence(kind=ProbeKind.SMOKE.value, ran=False,
                         skipped_reason="smoke ปิดอยู่")]

    out: List[Evidence] = []
    for rel in fingerprint.entrypoints[:2]:
        full = _valid_entry(workspace_path, rel)
        if full is None:
            continue
        if rel.endswith(".py"):
            base = [sys.executable, rel]
        elif rel.endswith(".js"):
            if not shutil.which("node"):
                continue
            base = ["node", rel]
        else:
            continue
        # ลอง --help ก่อน ถ้า returncode != 0 ค่อยลอง --version (บางตัว help ออก code 0/2 ต่างกัน)
        ev = _run(base + ["--help"], workspace_path, ProbeKind.SMOKE.value, SMOKE_TIMEOUT)
        if ev.ran and ev.passed is False:
            ev2 = _run(base + ["--version"], workspace_path, ProbeKind.SMOKE.value, SMOKE_TIMEOUT)
            # เก็บอันที่ผ่าน ถ้ามี ไม่งั้นเก็บอันแรก (help) เป็นหลักฐาน error จริง
            ev = ev2 if (ev2.ran and ev2.passed) else ev
        out.append(ev)
    if not out:
        return [Evidence(kind=ProbeKind.SMOKE.value, ran=False,
                         skipped_reason="ไม่พบ entrypoint ที่รันได้")]
    return out


def probe_build(repository_id, fingerprint) -> List[Evidence]:
    """บิลด์สำหรับภาษาที่ต้อง compile (Go/Rust) — allow-list, ทำเฉพาะเมื่อมี toolchain"""
    workspace_path = get_workspace_path(repository_id)
    if workspace_path is None or not rs.TEST_EXECUTION_ENABLED:
        return []
    join = lambda n: os.path.join(workspace_path, n)
    out: List[Evidence] = []
    if os.path.isfile(join("go.mod")) and shutil.which("go"):
        out.append(_run(["go", "build", "./..."], workspace_path,
                        ProbeKind.BUILD.value, BUILD_TIMEOUT))
    if os.path.isfile(join("Cargo.toml")) and shutil.which("cargo"):
        out.append(_run(["cargo", "build", "--quiet"], workspace_path,
                        ProbeKind.BUILD.value, BUILD_TIMEOUT))
    return out


def probe_all(repository_id, fingerprint, actor_user_id=None) -> List[Evidence]:
    """ลำดับ probe เต็ม: install → test → (ถ้าไม่มีเทส) smoke → build
    คืน list[Evidence] ทั้งหมดตามจริง"""
    evidence: List[Evidence] = []
    evidence.extend(probe_install(repository_id, fingerprint))

    test_ev = probe_test(repository_id, actor_user_id)
    evidence.append(test_ev)

    # ถ้าไม่มีชุดเทสที่รันได้ ลอง smoke entrypoint เพื่อยังพอมีหลักฐาน "สตาร์ตติดไหม"
    if not (test_ev.ran):
        evidence.extend(probe_smoke(repository_id, fingerprint))

    evidence.extend(probe_build(repository_id, fingerprint))
    return evidence
