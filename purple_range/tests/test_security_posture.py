"""
Security-posture guard: the module must never contain execution or bypass primitives.

This is an enforced invariant, not a style check — it fails the build if anyone ever adds
real command execution or a scope/RoE-bypass flag to purple_range.
"""

from __future__ import annotations

import os
import re

import purple_range

_PKG_DIR = os.path.dirname(os.path.abspath(purple_range.__file__))

# patterns that must NEVER appear in module source (tests excluded)
_FORBIDDEN = [
    r"\bsubprocess\b",
    r"\bos\.system\b",
    r"\bos\.popen\b",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bpty\b",
    r"bypass_roe",
    r"ignore_scope",
    r"admin_override",
    r"\bforce\s*=\s*True",
]


def _source_files():
    for root, _dirs, files in os.walk(_PKG_DIR):
        if os.path.basename(root) == "tests":
            continue
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(root, f)


def test_no_execution_or_bypass_primitives():
    violations = []
    for path in _source_files():
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        for pat in _FORBIDDEN:
            if re.search(pat, text):
                violations.append(f"{os.path.relpath(path, _PKG_DIR)}: /{pat}/")
    assert not violations, "forbidden primitives found:\n" + "\n".join(violations)


def test_does_not_import_scope_policy():
    # purple_range respects scope via purpleteam; it must not import scope_policy directly
    for path in _source_files():
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        assert "import scope_policy" not in text, path
        assert "from scope_policy" not in text, path


def test_no_shell_style_commands_in_dispatcher():
    from purple_range.commands.range import _HELP
    lowered = _HELP.lower()
    for bad in ("/shell", "/exec", "/cmd", "shellaccess", "arbitrary command"):
        assert bad not in lowered
