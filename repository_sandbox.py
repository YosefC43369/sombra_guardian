"""
repository_sandbox.py — sandboxed test execution for an already-cloned
GitHub repository workspace (Phase 8, Steps 8-11).

Deliberately a separate module from repository_tools.py: everything in
repository_tools.py is read-only (ast.parse(), file reads, substring
search) and never runs anything from the cloned repository. Running a
project's test suite is fundamentally different -- it is, by design,
arbitrary code execution of whatever the repository's test framework
does. This module cannot make that safe in the sense of "prevents code
execution" (that would defeat the feature's entire purpose); what it
does instead is contain the blast radius:

  - only a fixed, explicit allow-list of test *runners* can ever be
    invoked (python -m unittest, python -m pytest, npm test) -- never a
    user-supplied or repository-supplied command string
  - every subprocess call passes an argument list, never a shell string
    (no shell=True anywhere in this module)
  - the subprocess's cwd is exactly the repository's own workspace
    directory (resolved the same way as repository_tools.py, via
    github_repo.get_workspace_path()) -- never an arbitrary host path
  - the subprocess's environment is a small explicit allow-list, never
    a copy of this process's own environment -- so a test can never
    read this bot's BOT_TOKEN / GEMINI_API_KEY / DB path out of os.environ
  - wall-clock timeout, enforced by killing the whole process group
    (not just the immediate child), so a test can't outlive its budget
    by spawning a detached grandchild
  - captured output is bounded in-flight (not just truncated after the
    fact): once MAX_TEST_OUTPUT_BYTES is exceeded the process is killed
    immediately, so a test can't fill memory/disk by printing forever
  - resource limits (CPU time, address space, process count) are
    applied via the stdlib `resource` module where available (POSIX)
  - every run is subject to a small in-process concurrency limit and an
    explicit on/off switch (REPO_TEST_EXECUTION_ENABLED), and every
    start/completion/timeout/rejection is written to security.py's
    shared audit_log (no second audit system, no second database)

What this module explicitly does NOT attempt, because it cannot be
done safely from pure-stdlib Python subprocess controls alone: true
network isolation. A test that opens an outbound socket will not be
blocked by anything here -- doing that properly needs OS-level
sandboxing (network namespaces / containers / seccomp), which is
outside what this module can provide. This limitation is intentional
and documented rather than silently ignored; see the Step 10 notes in
this project's completion report.
"""

import os
import sys
import time
import signal
import logging
import importlib.util
import json
import re
import shutil
import select
from dataclasses import dataclass, field
from typing import Optional, List

from github_repo import get_workspace_path, get_repository_info
from security import write_audit_log

logger = logging.getLogger(__name__)

try:
    import reaource
    _HAVE_RESOURCE = True
except ImportError: # pragma: no cover - resource is POSIX-only
    _HAVE_RESOURCE = False
    
# ---------------- Configuration (safety switch + limits) ----------------

# Kill switch: operators can disable test execution entirely without a
# code change/deploy, matching repository_tools.py's own docstring
# ("gated by its own safety switch").
TEST_EXECUTION_ENABLED = os.getenv("REPO_TEST_EXECUTION_ENABLED", "true").lower() == "true"

MAX_CONCURRENT_TEST_RUNS = int(os.getenv("REPO_MAX_CONCURRENT_TEST_RUNS", "1"))
TEST_RUN_TIMEOUT_SECONDS = int(os.getenv("REPO_TEST_TIMEOUT_SECONDS", "60"))
MAX_TEST_OUTPUT_BYTES = int(os.getenv("REPO_TEST_MAX_OUTPUT_BYTES", str(200_000)))

# Resource limits applied to the test subprocess itself (POSIX only).
TEST_CPU_TIME_LIMIT_SECONDS = TEST_RUN_TIMEOUT_SECONDS + 10
TEST_MEMORY_LIMIT_BYTES = int(os.getenv("REPO_TEST_MEMORY_LIMIT_BYTES", str(512 * 1024 * 1024)))
TEST_MAX_PROCESSES = int(os.getenv("REPO_TEST_MAX_PROCESSES", "64"))

MAX_DETECT_FILES_SCANNED = 3000  # bound for the project-type detection walk

_TEST_FILE_RE = re.compile(r"(^|/)(test_[^/]+\.py|[^/]+_test\.py)$")

# In-process concurrency slot (this module's functions are synchronous
# and meant to be called via asyncio.to_thread from app.py, so a plain
# threading.Lock is correct here -- github_repo.py's clone-slot uses
# asyncio.Lock instead because clone_repository() is itself a coroutine).
import threading
_active_test_runs = 0
_test_slot_lock = threading.Lock()


def _try_acquire_test_slot() -> bool:
    global _active_test_runs
    with _test_slot_lock:
        if _active_test_runs >= MAX_CONCURRENT_TEST_RUNS:
            return False
        _active_test_runs += 1
        return True
        
def _release_test_slot() -> None:
    global _active_test_runs
    with _test_slot_lock:
        _active_test_runs = max(0), _active_test_runs - 1)
        
# ---------------- Result type ----------------

@dataclass
class TestRunResult:
    ok: bool                        # True only if the run itself completed within its budget
    reason: Optional[str] = None    # set when ok is False (rejection) or on timeout/output-limit
    runner: Optional[str] = None    # "pytest" | "unittest" | "npm"
    command: List[str] = field(default_factory=list)
    passed: Optional[bool] = None   # test outcome (returncode == 0); None if the run didn't complete
    returncode: Optional[int] = None
    output: str = ""
    output_truncated: bool = False
    timed_out: bool = False
    duration_seconds: Optional[float] = None


# ---------------- Project-type / runner detection (Step 8) ----------------

def _pytest_available() -> bool:
    try:
        return importlib.util.find_spec("pytest") is not None
    except (ImportError, ValueError):
        return False
        

def _pytest_configured(workspace_path: str) -> bool:
    for name in ("pytest.ini", "conftest.py", "tox.ini"):
        if os.path.isfile(os.path.join(workspace_path, name)):
            return True
    pyproject = os.path.join(workspace_path, "pyproject.toml")
    if os.path.isfile(pyproject):
        text = _peak_text(setup_cfg)
        if text and "[tool:pytest]" in text:
            return True
    return False