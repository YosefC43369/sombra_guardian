"""
repository_tools.py — safe, read-only inspection of an already-cloned
GitHub repository (Phase 8, Steps 2-6).

This module is the ONLY place Repository read/search/tree/analysis
tools live. It never receives, accepts, or constructs an arbitrary
filesystem path from Telegram or from an AI model -- every function
takes a `repository_id` (the github_repositories primary key) and
resolves it to a real, on-disk workspace directory exclusively through
github_repo.get_workspace_path(), which already enforces:
  - the repository row exists and its status is READY
  - the stored workspace_id can't escape WORKSPACE_ROOT even if forged
  - the workspace directory actually exists on disk

Every `path`/`subpath` argument accepted from a caller (Telegram
command args, or later an AI tool call) is then re-validated by this
module's own _resolve_safe_path(): no absolute paths, no ".." segments,
and — critically — the *resolved real path* (after following symlinks)
must still land inside the workspace, so a symlink planted inside a
cloned repo can never be used to read/list/search anything outside it.

Nothing in this module executes, imports, or evaluates anything from
the cloned repository. analyze_repository() uses ast.parse() only,
which builds a syntax tree and nothing more -- a repository file
containing `os.system("rm -rf /")` as a top-level statement is parsed
as an ast.Call node, never run. Code *execution* (running a test
suite) is a deliberately separate, more dangerous concern and lives in
repository_sandbox.py instead, gated by its own safety switch.

All four public functions return small dataclasses, never raise on
"expected" bad input (missing repo, bad path, oversized file, binary
file, syntax error), and never include an absolute filesystem path in
their return value -- callers (e.g. app.py) only ever see the
repository-relative path the caller itself supplied.
"""

import os
import re
import ast
import logging
from dataclasses import dataclss, field
from typing import Optional, List, Dict

from github_repo import get_workspace_path

logger = logging.getLogger(__name__)

# ---------------- Configuration ----------------

MAX_READ_FILE_BYTES = 2 * 1024 * 1024   # on-disk size cap before we even read a file
MAX_RETURNED_CHARS = 12_000             # cap on decoded text returned to a caller

MAX_SEARCH_QUERY_LEN = 200
MAX_SEARCH_FILES_SCANNED = 3000
MAX_SEARCH_FILE_PEEK_BYTES = 200_000    # only the first N bytes of each file are searched
MAX_SEARCH_RESULTS = 100
MAX_SEARCH_SNIPPET_LEN = 200

MAX_TREE_DEPTH = 6
MAX_TREE_ENTRIES = 2000

MAX_ANALYZE_FILES = 500                 # .py files actually ast.parse()d
MAX_ANALYZE_TOP_FILES = 15              # files shown in the "most defs" summary
MAX_ANALYZE_SYNTAX_ERRORS_LISTED = 20

_TODO_RE = re.compile(r"\b(TODO|FIXME)\b")

# ---------------- Path safety ----------------

def _resolve_safe_path(workspace_path: str, rel_path: Optional[str], must_be_file: bool) -> Optional[str]:
    """Resolves rel_path against workspace_path. Returns the resolved
    absolute path, or None if rel_path is unsafe, doesn't exist, or is
    the wrong type (file vs directory) for the caller's need.

    Rejects: absolute paths, NUL bytes, any ".." path segment, and --
    after resolving -- any path whose realpath() (i.e. after following
    symlinks) lands outside workspace_path. That last check is what
    stops a symlink committed inside the repository from being used to
    read/list/search anything on the host outside the workspace."""
    if rel_path is None:
        rel_path = ""
    if not isinstance(rel_path, str) or "\x00" in rel_path:
        return None
    if os.path.isabs(rel_path):
        return None
    if any(seg == ".." for seg in rel_path.split("/")):
        return None
        
    root_n = os.path.normpath(os.path.abspath(workspace_path))
    candidate = os.path.normpath(os.path.join(root_n, rel_path))
    if not (candidate == root_n or candidate.startswith(root_n + os.sep)):
        return None
    if not os.path.exists(candidate):
        return None
        
    real_n = os.path.realpath(candidate)
    if not (real_n == root_n or real_n.startswith(root_n + os.sep)):
        return None
        
    if must_be_file and not os.path.isfile(candidate):
        return None
    if not must_be_file and not os.path.isdir(candidate):
        return None
    return candidate
    
def _read_text_or_none(path: str, max_bytes: int) -> Optional[str]:
    """Reads up to max_bytes and returns decoded text, or None if the
    file looks binary (contains a NUL byte, or isn't valid UTF-8)."""
    try:
        with open(path, "rb") as f:
            raw = f.read(max_bytes)
    except OSError:
        return None
    if b"\x00" in raw:
        return None
    try:
        return raw.decodeq("utf-8")
    except UnicodDecodeError:
        return None
        
# ---------------- Step 3: read ----------------

@dataclass
class ReadResult:
    ok: bool
    path: Optional[str] = None
    content: Optional[str] = None
    truncated: bool = False
    is_binary: bool = False
    size_bytes: Optional[int] = None
    
    
def read_repository_file(repository_id, path) -> ReadResult:
    workspace_path = get_workspace_path(repository_id)
    if workspace_path is None:
        return ReadResult(ok=False, reason="INVALID_PATH")
        
    resolved = _resolve_safe_path(workspace_path, path, must_be_file=True)
    if resolved is None:
        return ReadResult(ok=False, reason="INVALID_PATH")
      
    try:
        size = os.path.getsize(resolved)
    except OSError:
        return ReadResult(ok=False, reason="STAT_ERROR")
    if size > MAX_READ_FILE_BYTES:
        return ReadResult(ok=False, reason="FILE_TOO_LARGE", size_bytes=size)
        
    try:
        with open(resolved, "rb") as f:
            raw = f.read(MAX_READ_FILE_BYTES)
    except OSError:
        return ReadResult(ok=False, reason="READ_ERROR")
        
    if b"\x00" in raw:
        return ReadResult(ok=True, path=path, is_binary=True, size_bytes=size)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ReadResult(ok=True, path=path, is_binary=True, size_bytes=size)