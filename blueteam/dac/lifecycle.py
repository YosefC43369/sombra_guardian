"""
blueteam/dac/lifecycle.py — rule lifecycle state machine + tamper-evident version
hashing (pure; stdlib only).

States: ``disabled -> shadow -> canary -> enabled`` (and any state may return to
``disabled``; ``enabled``/``canary`` may step back to ``shadow``). A **rollback**
restores a previous version's body and bumps to a new version that records the
rollback in its notes.

Version history is a **hash chain**: each version's ``sha256`` covers the canonical
rule body plus the previous version's hash, so the sequence is tamper-evident on
its own. The service additionally seals each change to the app's Merkle integrity
ledger through an injected sealer port — but the chain here stands without it.
"""

from __future__ import annotations

import hashlib
import json
from typing import Dict, Optional, Tuple

DISABLED, SHADOW, CANARY, ENABLED = "disabled", "shadow", "canary", "enabled"
_STATES = (DISABLED, SHADOW, CANARY, ENABLED)

# allowed transitions (promotion is gradual; demotion/disable always allowed)
_ALLOWED: Dict[str, set] = {
    DISABLED: {SHADOW, ENABLED, DISABLED},        # ENABLED direct allowed for imports/admin
    SHADOW: {CANARY, ENABLED, DISABLED, SHADOW},
    CANARY: {ENABLED, SHADOW, DISABLED, CANARY},
    ENABLED: {SHADOW, CANARY, DISABLED, ENABLED},
}


class LifecycleError(ValueError):
    pass


def can_transition(old: str, new: str) -> bool:
    return new in _ALLOWED.get(old, set())


def validate_transition(old: str, new: str) -> None:
    if new not in _STATES:
        raise LifecycleError(f"unknown state: {new}")
    if not can_transition(old, new):
        raise LifecycleError(f"illegal transition {old} -> {new}")


def canonical_body(body: dict) -> str:
    """Deterministic JSON for hashing (sorted keys, no whitespace drift)."""
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def version_hash(body: dict, prev_hash: str = "") -> str:
    """sha256(prev_hash || canonical(body)) — the tamper-evident chain link."""
    h = hashlib.sha256()
    h.update((prev_hash or "").encode("utf-8"))
    h.update(canonical_body(body).encode("utf-8"))
    return h.hexdigest()


def bump_version(prev_version: str) -> str:
    """Semver-ish patch bump. '1.2.3' -> '1.2.4'; non-semver -> append '.1'."""
    parts = (prev_version or "1.0.0").split(".")
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return f"{prev_version}.1"
    while len(nums) < 3:
        nums.append(0)
    nums[-1] += 1
    return ".".join(str(n) for n in nums)


def verify_chain(versions: list) -> Tuple[bool, Optional[str]]:
    """Given [{'body': dict|str, 'sha256': str, 'version': str}, ...] in creation
    order, recompute each link and return (ok, first_bad_version)."""
    prev = ""
    for v in versions:
        body = v["body"]
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except ValueError:
                return False, v.get("version")
        expected = version_hash(body, prev)
        if expected != v.get("sha256"):
            return False, v.get("version")
        prev = expected
    return True, None


__all__ = ["can_transition", "validate_transition", "canonical_body", "version_hash",
           "bump_version", "verify_chain", "LifecycleError",
           "DISABLED", "SHADOW", "CANARY", "ENABLED"]
