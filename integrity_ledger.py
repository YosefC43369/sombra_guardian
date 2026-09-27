"""
integrity_ledger.py — Tamper-Evident Merkle Audit Ledger (data layer)

WHAT THIS IS. A private, single-writer, append-only *transparency log* for
Sombra Guardian, built entirely on the Python standard library. Every
security-relevant event (evidence captured, incident opened/closed, an admin
action, or a manual note) can be appended as an immutable, hash-linked entry.
The log can then prove three things cryptographically:

  1. INTEGRITY   — no past entry was edited, reordered, or deleted
                   (a broken hash-chain is detected and localized).
  2. INCLUSION   — a specific entry really is committed under a published
                   checkpoint (a Merkle audit path, O(log n) in size).
  3. APPEND-ONLY — an older checkpoint is a genuine prefix of a newer one,
                   i.e. history was only added to, never rewritten
                   (a Merkle consistency proof, RFC 6962 style).

WHY IT REPLACES THE OLD "blockchain/" CRATE. The previous design shelled out
to a Rust binary (`sombra-chain`) over subprocess to keep an append-only
ledger. That put a Rust toolchain in the deploy path, needed a background
anchor loop, and could only prove "entry N links to N-1". This module keeps
the good idea (a verifiable ledger of security events) and drops the
liabilities:

  * No external binary, no subprocess, no second process to supervise. Every
    operation is a handful of local SQLite statements — the same execution
    profile as security.py / member_incident.py.
  * Merkle trees (not just a linear prev-hash chain) give O(log n) inclusion
    AND consistency proofs. That is a strictly stronger integrity guarantee,
    and it is the exact mechanism behind Certificate Transparency (RFC 6962)
    — which makes this module a compact, self-contained teaching artifact.
  * Checkpoints are signed in-process with HMAC-SHA256, so a checkpoint
    someone forged by editing bot.db directly is rejected at verify time.

WHAT IT IS NOT. Not a cryptocurrency, not a payment rail, not a distributed
/ consensus blockchain. There is exactly one writer (this bot's host) and no
peers, no mining, no networking. It stores hashes of events, never money.

Design constraints (matches security.py / member_incident.py / findings.py):
- Standard library only (hashlib, hmac, json, os, secrets, sqlite3, time,
  logging, dataclasses, enum, typing), plus `from security import DB_PATH`
  — exactly what every other data-layer module here does, so this file loads
  and tests in complete isolation and never hard-codes a second "bot.db".
- No network/API calls, no LLM calls, no background threads or processes.
- CREATE TABLE IF NOT EXISTS only; reuses security.py's DB_PATH and its
  audit_log via write_audit_log — never a second database file.
- Ledgers are scoped per chat_id, exactly like every other feature in this
  bot (security_events, findings, incidents, ...). One group's admin can
  never read or anchor another group's log even by guessing an id.
- Every mutating call opens one connection, runs BEGIN IMMEDIATE (takes
  SQLite's write lock up front), and commits or rolls back as a unit — the
  same concurrency discipline the wallet ledger used, so two racing
  record_event() calls can never produce two entries at the same seq or a
  broken prev_hash link.
- `idempotency_key` (optional, usually Telegram's own update_id) lets a
  duplicate-delivered callback replay safely: the second call finds the
  already-recorded entry and returns it instead of appending a second one.

MERKLE HASHING (RFC 6962 §2.1). Leaves and internal nodes are domain-
separated to prevent second-preimage attacks that swap a leaf for an
internal node:

    leaf_hash(d)        = SHA-256(0x00 || d)
    node_hash(l, r)     = SHA-256(0x01 || l || r)
    root([])            = SHA-256("")            # empty tree
    root([d0])          = leaf_hash(d0)
    root(D[0:n]), n>1   = node_hash(root(D[0:k]), root(D[k:n]))
                          where k = largest power of two strictly < n

The leaf input `d` for entry i is the raw 32 bytes of that entry's
`entry_hash` (the hash-chain record hash), so the Merkle tree commits to the
whole chain, not just the payloads.
"""

import os
import json
import time
import hmac
import secrets
import hashlib
import logging
import sqlite3
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from security import DB_PATH, write_audit_log

logger = logging.getLogger("modbot.integrity")

# 64 hex zeros — the "genesis" prev_hash for the very first entry in a chat.
GENESIS_PREV_HASH = "0" * 64

MAX_PAYLOAD_BYTES = 64 * 1024        # a single event payload cap (sanity)
MAX_NOTE_LEN = 4000                  # /integrity record <text> cap
DEFAULT_PAGE_SIZE = 10
CONN_TIMEOUT_SECONDS = 30            # let racing writers wait out BEGIN IMMEDIATE
_SECRET_META_KEY = "integrity_hmac_secret"
_SIG_DOMAIN = "integrity-checkpoint-v1"


class EventType(str, Enum):
    """Canonical event kinds. `record_event` accepts any non-empty string so
    plugins can add their own, but these cover the built-in anchors."""
    EVIDENCE_CREATED = "EVIDENCE_CREATED"
    INCIDENT_CREATED = "INCIDENT_CREATED"
    INCIDENT_UPDATED = "INCIDENT_UPDATED"
    ADMIN_ACTION = "ADMIN_ACTION"
    DETECTION = "DETECTION"
    MANUAL_NOTE = "MANUAL_NOTE"
    CHECKPOINT = "CHECKPOINT"


@dataclass
class OpResult:
    """Same shape every other data-layer module here returns (wallet/expense/
    findings): a boolean, a machine reason code, an optional human detail, and
    a data bag. Callers turn `reason` into a localized reply."""
    ok: bool
    reason: str = ""
    detail: str = ""
    data: dict = field(default_factory=dict)


# =====================================================================
# Merkle primitives — pure functions, no DB, no I/O. Kept deliberately
# small and self-contained so they can be read top-to-bottom as a
# reference implementation of RFC 6962 tree hashing and its two proofs.
# =====================================================================

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(leaf_input: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA-256(0x00 || d)."""
    return _sha256(_LEAF_PREFIX + leaf_input)


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash: SHA-256(0x01 || left || right)."""
    return _sha256(_NODE_PREFIX + left + right)


def _largest_power_of_two_below(n: int) -> int:
    """Largest k = 2^b with k < n, for n >= 2. (n=2 -> 1, n=5 -> 4, n=8 -> 4)."""
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def merkle_root(leaf_inputs: List[bytes]) -> bytes:
    """Merkle Tree Hash over a list of raw leaf inputs (RFC 6962 §2.1).

    Recursive by design for readability; O(n log n) which is irrelevant at
    audit-log scale. The empty tree hashes the empty string, matching the RFC
    so an empty ledger still has a well-defined (and signable) root.
    """
    n = len(leaf_inputs)
    if n == 0:
        return _sha256(b"")
    if n == 1:
        return leaf_hash(leaf_inputs[0])
    k = _largest_power_of_two_below(n)
    return node_hash(merkle_root(leaf_inputs[:k]), merkle_root(leaf_inputs[k:]))


def merkle_audit_path(index: int, leaf_inputs: List[bytes]) -> List[bytes]:
    """Inclusion (audit) path for `index` in a tree of len(leaf_inputs) leaves.

    Returns the sibling hashes bottom-to-top (RFC 6962 §2.1.1). Verifying the
    path with `verify_inclusion` reconstructs the root from just the target
    leaf and these O(log n) siblings — the whole point of a transparency log.
    """
    n = len(leaf_inputs)
    if not (0 <= index < n):
        raise IndexError(f"index {index} out of range for {n} leaves")
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if index < k:
        return merkle_audit_path(index, leaf_inputs[:k]) + [merkle_root(leaf_inputs[k:])]
    return merkle_audit_path(index - k, leaf_inputs[k:]) + [merkle_root(leaf_inputs[:k])]


def verify_inclusion(index: int, tree_size: int, target_leaf_hash: bytes,
                     audit_path: List[bytes], root: bytes) -> bool:
    """Recompute the root from a leaf hash + audit path and compare.

    Standard RFC 6962 verifier (the Trillian decomposition): the position of
    each sibling — left or right — is read straight from the bits of `index`,
    so no tree is needed, only the O(log n) proof. `target_leaf_hash` is
    `leaf_hash(leaf_input)` of the entry being proven.
    """
    if index < 0 or tree_size < 0 or index >= tree_size:
        return False
    inner = (index ^ (tree_size - 1)).bit_length()   # depth of the "inner" part
    border = bin(index >> inner).count("1")           # remaining right-edge nodes
    if len(audit_path) != inner + border:
        return False
    h = target_leaf_hash
    # Inner part: index bits decide sibling side (0 => sibling on the right).
    for i in range(inner):
        sibling = audit_path[i]
        if (index >> i) & 1 == 0:
            h = node_hash(h, sibling)
        else:
            h = node_hash(sibling, h)
    # Border part: always fold in from the left (right-edge spine).
    for sibling in audit_path[inner:]:
        h = node_hash(sibling, h)
    return hmac.compare_digest(h, root)


def merkle_consistency_proof(first: int, second: int,
                             leaf_inputs: List[bytes]) -> List[bytes]:
    """Consistency proof that the size-`first` tree is a prefix of the
    size-`second` tree (RFC 6962 §2.1.2). `leaf_inputs` must be the full
    size-`second` leaf list. Empty when first==0 or first==second."""
    if not (0 <= first <= second <= len(leaf_inputs)):
        raise ValueError("require 0 <= first <= second <= len(leaves)")
    if first == 0 or first == second:
        return []
    return _subproof(first, leaf_inputs[:second], True)


def _subproof(m: int, leaf_inputs: List[bytes], b: bool) -> List[bytes]:
    n = len(leaf_inputs)
    if m == n:
        # The prefix tree's own root is only needed when b is False (i.e. it
        # is a proper subtree the verifier cannot recompute on its own).
        return [] if b else [merkle_root(leaf_inputs)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return _subproof(m, leaf_inputs[:k], b) + [merkle_root(leaf_inputs[k:])]
    return _subproof(m - k, leaf_inputs[k:], False) + [merkle_root(leaf_inputs[:k])]


def verify_consistency(first: int, second: int, proof: List[bytes],
                       first_root: bytes, second_root: bytes) -> bool:
    """Verify a consistency proof between two published roots (Trillian
    algorithm). Proves the size-`first` tree was only appended to, never
    rewritten, to become the size-`second` tree."""
    if first < 0 or second < first:
        return False
    if first == second:
        return not proof and hmac.compare_digest(first_root, second_root)
    if first == 0:
        # Every tree is consistent with the empty tree; proof must be empty.
        return not proof
    # 0 < first < second
    inner = ((first - 1) ^ (second - 1)).bit_length()
    border = bin((first - 1) >> inner).count("1")
    shift = ((first & -first).bit_length() - 1)       # trailing zeros of `first`
    inner -= shift
    if first == (1 << shift):
        seed, start = first_root, 0
    else:
        if not proof:
            return False
        seed, start = proof[0], 1
    if len(proof) != start + inner + border:
        return False
    body = proof[start:]
    mask = (first - 1) >> shift
    # Reconstruct first_root: only fold in siblings on set index bits.
    h1 = seed
    for i in range(inner):
        if (mask >> i) & 1 == 1:
            h1 = node_hash(body[i], h1)
    for sibling in body[inner:]:
        h1 = node_hash(sibling, h1)
    if not hmac.compare_digest(h1, first_root):
        return False
    # Reconstruct second_root from the same seed + siblings.
    h2 = seed
    for i in range(inner):
        if (mask >> i) & 1 == 0:
            h2 = node_hash(h2, body[i])
        else:
            h2 = node_hash(body[i], h2)
    for sibling in body[inner:]:
        h2 = node_hash(sibling, h2)
    return hmac.compare_digest(h2, second_root)


# =====================================================================
# Canonical serialization + entry hashing
# =====================================================================

def canonical_json(payload) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace. Two
    equal payloads always serialize to the same bytes, so their hash is
    reproducible on any machine (the same property the old Rust crate relied
    on by keeping serde_json key-sorting on)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def compute_entry_hash(seq: int, chat_id: int, event_type: str,
                       payload_hash: str, prev_hash: str, created_at: int) -> str:
    """The hash-chain record hash. Binds this entry to its position (seq),
    its chat, its content (payload_hash), and the entry before it (prev_hash).
    Changing any field, or reordering entries, breaks the chain from here on."""
    material = "\n".join([
        str(seq), str(chat_id), event_type, payload_hash, prev_hash, str(created_at),
    ]).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


# =====================================================================
# Database
# =====================================================================

def _conn():
    conn = sqlite3.connect(DB_PATH, timeout=CONN_TIMEOUT_SECONDS)
    conn.row_factory = sqlite3.Row
    conn.isolation_level = None      # manual BEGIN IMMEDIATE control
    return conn


class _Tx:
    """One connection, BEGIN IMMEDIATE, commit on clean exit / rollback on any
    exception. Identical discipline to the wallet ledger's _Tx."""

    def __enter__(self):
        self.conn = _conn()
        self.conn.execute("BEGIN IMMEDIATE")
        return self.conn

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.conn.commit()
        else:
            try:
                self.conn.rollback()
            except sqlite3.Error:
                pass
        self.conn.close()
        return False


def _tx():
    return _Tx()


def integrity_db_init() -> None:
    """Create the ledger tables and ensure a signing secret exists. Idempotent
    and safe on every process start; never drops or resets data, never touches
    any other module's tables."""
    conn = _conn()
    conn.execute("BEGIN IMMEDIATE")
    conn.execute("""CREATE TABLE IF NOT EXISTS integrity_entries (
        chat_id INTEGER NOT NULL,
        seq INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL,
        actor TEXT,
        idempotency_key TEXT,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (chat_id, seq)
    )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_integrity_entries_hash "
        "ON integrity_entries (chat_id, entry_hash)"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_integrity_idempotency "
        "ON integrity_entries (chat_id, idempotency_key) "
        "WHERE idempotency_key IS NOT NULL"
    )
    conn.execute("""CREATE TABLE IF NOT EXISTS integrity_checkpoints (
        chat_id INTEGER NOT NULL,
        checkpoint_id INTEGER NOT NULL,
        tree_size INTEGER NOT NULL,
        merkle_root TEXT NOT NULL,
        signature TEXT NOT NULL,
        created_by INTEGER,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (chat_id, checkpoint_id)
    )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_integrity_ckpt_size "
        "ON integrity_checkpoints (chat_id, tree_size)"
    )
    conn.execute("""CREATE TABLE IF NOT EXISTS integrity_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()
    # Touch the secret once so a fresh DB gets a stable random one immediately.
    _ensure_secret()
    logger.info("INTEGRITY DATABASE: OK")


# ---------------- Signing secret ----------------

# Per-DB_PATH cache of the resolved fallback secret, so signing/verifying never
# opens a fresh connection on the hot path (and, crucially, never opens a nested
# connection while a create_checkpoint transaction already holds the write lock,
# which would self-deadlock). Keyed by DB_PATH so the per-test temp databases
# each keep their own secret.
_secret_cache: Dict[str, bytes] = {}


def _ensure_secret(conn=None) -> bytes:
    """The HMAC key that signs checkpoints. Resolution order:

      1. env INTEGRITY_SECRET  — the production path; keep it OUT of bot.db so
         an attacker who only has the database file cannot forge a checkpoint.
      2. a random 32-byte secret persisted in integrity_meta on first use —
         so the module works out of the box and signatures stay stable across
         restarts, while still detecting edits made by anyone without the key.

    (Storing the fallback secret beside the data it protects is a deliberate,
    documented trade-off: it defends against tampering *through the bot* and
    against accidental corruption, not against someone who already owns the
    whole file. Set INTEGRITY_SECRET for the stronger property.)

    If `conn` is supplied it is reused (so a caller already inside a
    BEGIN IMMEDIATE transaction never opens a second, deadlocking connection).
    Otherwise the fast path returns the cached secret with no DB access at all.
    """
    env = os.getenv("INTEGRITY_SECRET")
    if env and env.strip():
        return env.strip().encode("utf-8")
    if conn is None and DB_PATH in _secret_cache:
        return _secret_cache[DB_PATH]

    own = conn is None
    c = _conn() if own else conn   # _conn() is autocommit (isolation_level=None)
    try:
        row = c.execute(
            "SELECT value FROM integrity_meta WHERE key=?", (_SECRET_META_KEY,)
        ).fetchone()
        if row is None:
            new_secret = secrets.token_bytes(32)
            c.execute(
                "INSERT INTO integrity_meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO NOTHING",
                (_SECRET_META_KEY, new_secret.hex()),
            )
            # Re-read in case a racing writer inserted first (ON CONFLICT no-op).
            row = c.execute(
                "SELECT value FROM integrity_meta WHERE key=?", (_SECRET_META_KEY,)
            ).fetchone()
        secret = bytes.fromhex(row["value"])
    finally:
        if own:
            c.close()

    _secret_cache[DB_PATH] = secret
    return secret


def _sign(chat_id: int, tree_size: int, merkle_root_hex: str, conn=None) -> str:
    secret = _ensure_secret(conn=conn)
    material = f"{_SIG_DOMAIN}|{chat_id}|{tree_size}|{merkle_root_hex}".encode("utf-8")
    return hmac.new(secret, material, hashlib.sha256).hexdigest()


def verify_signature(chat_id: int, tree_size: int, merkle_root_hex: str,
                     signature: str) -> bool:
    expected = _sign(chat_id, tree_size, merkle_root_hex)
    return hmac.compare_digest(expected, signature or "")


# =====================================================================
# Append (record) an event
# =====================================================================

def record_event(chat_id: int, event_type, payload: Optional[dict] = None,
                 actor: Optional[str] = None,
                 idempotency_key: Optional[str] = None) -> OpResult:
    """Append one immutable entry to this chat's ledger, atomically.

    The new entry's prev_hash is the previous entry's entry_hash (or the
    genesis value for seq 0), and its entry_hash is computed over its whole
    record. Because the whole thing runs inside BEGIN IMMEDIATE, two racing
    appends can never grab the same seq or read a stale "last entry".

    Returns OpResult(ok=True, data={"entry": {...}}). On a duplicate
    idempotency_key, returns the already-stored entry with
    data["already_recorded"]=True instead of appending a second one.
    """
    etype = event_type.value if isinstance(event_type, EventType) else str(event_type)
    if not etype.strip():
        return OpResult(False, reason="INVALID_EVENT_TYPE")
    payload = payload if isinstance(payload, dict) else {}
    payload_str = canonical_json(payload)
    if len(payload_str.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        return OpResult(False, reason="PAYLOAD_TOO_LARGE")
    payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

    try:
        with _tx() as conn:
            if idempotency_key:
                existing = conn.execute(
                    "SELECT * FROM integrity_entries WHERE chat_id=? AND idempotency_key=?",
                    (chat_id, idempotency_key),
                ).fetchone()
                if existing:
                    return OpResult(True, data={"entry": dict(existing),
                                                "already_recorded": True})
            last = conn.execute(
                "SELECT seq, entry_hash FROM integrity_entries "
                "WHERE chat_id=? ORDER BY seq DESC LIMIT 1",
                (chat_id,),
            ).fetchone()
            seq = 0 if last is None else last["seq"] + 1
            prev_hash = GENESIS_PREV_HASH if last is None else last["entry_hash"]
            created_at = int(time.time())
            entry_hash = compute_entry_hash(seq, chat_id, etype, payload_hash,
                                            prev_hash, created_at)
            conn.execute(
                "INSERT INTO integrity_entries "
                "(chat_id, seq, event_type, payload, payload_hash, prev_hash, "
                " entry_hash, actor, idempotency_key, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (chat_id, seq, etype, payload_str, payload_hash, prev_hash,
                 entry_hash, actor, idempotency_key, created_at),
            )
            entry = {
                "chat_id": chat_id, "seq": seq, "event_type": etype,
                "payload": payload_str, "payload_hash": payload_hash,
                "prev_hash": prev_hash, "entry_hash": entry_hash,
                "actor": actor, "idempotency_key": idempotency_key,
                "created_at": created_at,
            }
    except sqlite3.Error:
        logger.exception("INTEGRITY DB ERROR on record_event")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, None, actor=(actor or "system"),
                    action="INTEGRITY_EVENT_RECORDED",
                    detail=f"seq={seq} type={etype} entry_hash={entry_hash[:16]}…")
    return OpResult(True, data={"entry": entry})


# =====================================================================
# Reads
# =====================================================================

def entry_count(chat_id: int) -> int:
    conn = _conn()
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM integrity_entries WHERE chat_id=?", (chat_id,)
    ).fetchone()
    conn.close()
    return row["c"]


def get_entry(chat_id: int, seq: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM integrity_entries WHERE chat_id=? AND seq=?", (chat_id, seq)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def list_entries(chat_id: int, page: int = 1,
                 page_size: int = DEFAULT_PAGE_SIZE) -> dict:
    """Newest-first, paginated view of a chat's ledger (for /integrity log)."""
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    conn = _conn()
    total = conn.execute(
        "SELECT COUNT(*) AS c FROM integrity_entries WHERE chat_id=?", (chat_id,)
    ).fetchone()["c"]
    rows = conn.execute(
        "SELECT * FROM integrity_entries WHERE chat_id=? "
        "ORDER BY seq DESC LIMIT ? OFFSET ?",
        (chat_id, page_size, (page - 1) * page_size),
    ).fetchall()
    conn.close()
    total_pages = max(1, (total + page_size - 1) // page_size)
    return {"items": [dict(r) for r in rows], "page": page, "page_size": page_size,
            "total_count": total, "total_pages": total_pages}


def _leaf_inputs(conn, chat_id: int, upto_size: Optional[int] = None) -> List[bytes]:
    """The Merkle leaf inputs (raw entry_hash bytes) for a chat, ordered by
    seq. `upto_size` limits to the first N leaves (a historical tree size)."""
    if upto_size is None:
        rows = conn.execute(
            "SELECT entry_hash FROM integrity_entries WHERE chat_id=? ORDER BY seq ASC",
            (chat_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT entry_hash FROM integrity_entries WHERE chat_id=? AND seq < ? "
            "ORDER BY seq ASC",
            (chat_id, upto_size),
        ).fetchall()
    return [bytes.fromhex(r["entry_hash"]) for r in rows]


def current_root(chat_id: int) -> str:
    """The Merkle root over *all* current entries in a chat (hex)."""
    conn = _conn()
    try:
        leaves = _leaf_inputs(conn, chat_id)
    finally:
        conn.close()
    return merkle_root(leaves).hex()


# =====================================================================
# Checkpoints (the "anchor" — replaces the old Rust anchor loop)
# =====================================================================

def create_checkpoint(chat_id: int, created_by: Optional[int] = None) -> OpResult:
    """Publish a signed checkpoint over the chat's current entries.

    A checkpoint is {tree_size, merkle_root, signature}. It is the commitment
    a later inclusion/consistency proof is checked against. Idempotent: if the
    tree has not grown since the last checkpoint, the existing one is returned
    rather than duplicated (an empty ledger can still be checkpointed once, so
    there is always a root to prove against)."""
    try:
        with _tx() as conn:
            leaves = _leaf_inputs(conn, chat_id)
            tree_size = len(leaves)
            last = conn.execute(
                "SELECT * FROM integrity_checkpoints WHERE chat_id=? "
                "ORDER BY checkpoint_id DESC LIMIT 1",
                (chat_id,),
            ).fetchone()
            if last is not None and last["tree_size"] == tree_size:
                return OpResult(True, data={"checkpoint": dict(last),
                                            "unchanged": True})
            root_hex = merkle_root(leaves).hex()
            signature = _sign(chat_id, tree_size, root_hex, conn=conn)
            checkpoint_id = 0 if last is None else last["checkpoint_id"] + 1
            created_at = int(time.time())
            conn.execute(
                "INSERT INTO integrity_checkpoints "
                "(chat_id, checkpoint_id, tree_size, merkle_root, signature, "
                " created_by, created_at) VALUES (?,?,?,?,?,?,?)",
                (chat_id, checkpoint_id, tree_size, root_hex, signature,
                 created_by, created_at),
            )
            checkpoint = {
                "chat_id": chat_id, "checkpoint_id": checkpoint_id,
                "tree_size": tree_size, "merkle_root": root_hex,
                "signature": signature, "created_by": created_by,
                "created_at": created_at,
            }
    except sqlite3.Error:
        logger.exception("INTEGRITY DB ERROR on create_checkpoint")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, None, actor=(str(created_by) if created_by else "system"),
                    action="INTEGRITY_CHECKPOINT_CREATED",
                    detail=f"checkpoint_id={checkpoint['checkpoint_id']} "
                           f"tree_size={tree_size} root={root_hex[:16]}…")
    return OpResult(True, data={"checkpoint": checkpoint})


def latest_checkpoint(chat_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM integrity_checkpoints WHERE chat_id=? "
        "ORDER BY checkpoint_id DESC LIMIT 1",
        (chat_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def list_checkpoints(chat_id: int, limit: int = 20) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM integrity_checkpoints WHERE chat_id=? "
        "ORDER BY checkpoint_id DESC LIMIT ?",
        (chat_id, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# =====================================================================
# Proofs (the API a /integrity proof command / external auditor uses)
# =====================================================================

def inclusion_proof(chat_id: int, seq: int,
                    tree_size: Optional[int] = None) -> OpResult:
    """Build an inclusion proof for entry `seq` against a tree size (defaults
    to the latest checkpoint's size, else the whole current ledger).

    Returns audit_path as hex strings plus the leaf/root context needed to
    verify it offline with verify_inclusion()."""
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT entry_hash FROM integrity_entries WHERE chat_id=? AND seq=?",
            (chat_id, seq),
        ).fetchone()
        if row is None:
            return OpResult(False, reason="ENTRY_NOT_FOUND")
        if tree_size is None:
            ckpt = conn.execute(
                "SELECT tree_size FROM integrity_checkpoints WHERE chat_id=? "
                "ORDER BY checkpoint_id DESC LIMIT 1",
                (chat_id,),
            ).fetchone()
            tree_size = ckpt["tree_size"] if ckpt else entry_count_in_conn(conn, chat_id)
        if seq >= tree_size:
            return OpResult(False, reason="ENTRY_AFTER_TREE_SIZE")
        leaves = _leaf_inputs(conn, chat_id, upto_size=tree_size)
    finally:
        conn.close()

    path = merkle_audit_path(seq, leaves)
    root = merkle_root(leaves)
    return OpResult(True, data={
        "leaf_index": seq,
        "tree_size": tree_size,
        "leaf_hash": leaf_hash(bytes.fromhex(row["entry_hash"])).hex(),
        "entry_hash": row["entry_hash"],
        "audit_path": [h.hex() for h in path],
        "root": root.hex(),
    })


def consistency_proof(chat_id: int, first_size: int,
                      second_size: Optional[int] = None) -> OpResult:
    """Build a consistency proof that the size-`first_size` tree is a prefix
    of the size-`second_size` tree (defaults to the current ledger size)."""
    conn = _conn()
    try:
        total = entry_count_in_conn(conn, chat_id)
        if second_size is None:
            second_size = total
        if not (0 <= first_size <= second_size <= total):
            return OpResult(False, reason="INVALID_SIZES")
        leaves = _leaf_inputs(conn, chat_id, upto_size=second_size)
    finally:
        conn.close()

    proof = merkle_consistency_proof(first_size, second_size, leaves)
    first_root = merkle_root(leaves[:first_size])
    second_root = merkle_root(leaves)
    return OpResult(True, data={
        "first_size": first_size,
        "second_size": second_size,
        "proof": [h.hex() for h in proof],
        "first_root": first_root.hex(),
        "second_root": second_root.hex(),
    })


def entry_count_in_conn(conn, chat_id: int) -> int:
    return conn.execute(
        "SELECT COUNT(*) AS c FROM integrity_entries WHERE chat_id=?", (chat_id,)
    ).fetchone()["c"]


# =====================================================================
# Full verification — the authoritative "is this ledger intact?" check
# =====================================================================

def verify_chain(chat_id: int) -> dict:
    """Recompute the whole ledger from scratch and report its integrity.

    Checks, in order:
      * hash-chain: every entry's entry_hash recomputes correctly and its
        prev_hash equals the previous entry_hash (detects edits / reordering /
        deletion, and localizes the FIRST broken seq).
      * checkpoints: each stored checkpoint's signature verifies (not forged)
        AND its merkle_root matches a freshly computed root at that tree_size
        (detects a checkpoint minted over tampered data).
      * append-only: each checkpoint is consistent with the next larger one
        (a self-check that history was only appended to).

    Returns a structured dict; `ok` is True only if nothing failed. This is
    the read side of the tamper-evidence guarantee — it never mutates.
    """
    result = {
        "ok": True,
        "chat_id": chat_id,
        "entry_count": 0,
        "checkpoint_count": 0,
        "chain_ok": True,
        "checkpoints_ok": True,
        "consistency_ok": True,
        "first_bad_seq": None,
        "problems": [],
        "current_root": None,
    }
    conn = _conn()
    try:
        entries = conn.execute(
            "SELECT * FROM integrity_entries WHERE chat_id=? ORDER BY seq ASC",
            (chat_id,),
        ).fetchall()
        checkpoints = conn.execute(
            "SELECT * FROM integrity_checkpoints WHERE chat_id=? "
            "ORDER BY checkpoint_id ASC",
            (chat_id,),
        ).fetchall()
    finally:
        conn.close()

    result["entry_count"] = len(entries)
    result["checkpoint_count"] = len(checkpoints)

    # 1) Hash chain.
    prev_hash = GENESIS_PREV_HASH
    leaf_inputs: List[bytes] = []
    for i, e in enumerate(entries):
        if e["seq"] != i:
            result["chain_ok"] = False
            result["first_bad_seq"] = i
            result["problems"].append(
                f"seq gap/reorder at position {i}: stored seq={e['seq']}")
            break
        recomputed_payload_hash = hashlib.sha256(
            e["payload"].encode("utf-8")).hexdigest()
        if recomputed_payload_hash != e["payload_hash"]:
            result["chain_ok"] = False
            result["first_bad_seq"] = e["seq"]
            result["problems"].append(f"payload edited at seq={e['seq']}")
            break
        if e["prev_hash"] != prev_hash:
            result["chain_ok"] = False
            result["first_bad_seq"] = e["seq"]
            result["problems"].append(f"prev_hash mismatch at seq={e['seq']}")
            break
        expected = compute_entry_hash(e["seq"], chat_id, e["event_type"],
                                      e["payload_hash"], e["prev_hash"],
                                      e["created_at"])
        if expected != e["entry_hash"]:
            result["chain_ok"] = False
            result["first_bad_seq"] = e["seq"]
            result["problems"].append(f"entry_hash mismatch at seq={e['seq']}")
            break
        prev_hash = e["entry_hash"]
        leaf_inputs.append(bytes.fromhex(e["entry_hash"]))

    result["current_root"] = merkle_root(leaf_inputs).hex()

    # 2) Checkpoints: signature + root over freshly computed leaves. Only
    #    meaningful when the chain up to that size is itself intact.
    for c in checkpoints:
        size = c["tree_size"]
        if not verify_signature(chat_id, size, c["merkle_root"], c["signature"]):
            result["checkpoints_ok"] = False
            result["problems"].append(
                f"checkpoint {c['checkpoint_id']} signature invalid (forged/edited)")
            continue
        if size <= len(leaf_inputs) and result["chain_ok"]:
            recomputed = merkle_root(leaf_inputs[:size]).hex()
            if recomputed != c["merkle_root"]:
                result["checkpoints_ok"] = False
                result["problems"].append(
                    f"checkpoint {c['checkpoint_id']} root != recomputed root "
                    f"(data changed under a signed checkpoint)")
        elif size > len(leaf_inputs):
            result["checkpoints_ok"] = False
            result["problems"].append(
                f"checkpoint {c['checkpoint_id']} claims {size} entries but only "
                f"{len(leaf_inputs)} exist (entries deleted after checkpoint)")

    # 3) Append-only consistency between consecutive checkpoints.
    if result["chain_ok"]:
        for a, b in zip(checkpoints, checkpoints[1:]):
            sa, sb = a["tree_size"], b["tree_size"]
            if sa > len(leaf_inputs) or sb > len(leaf_inputs) or sa > sb:
                continue
            proof = merkle_consistency_proof(sa, sb, leaf_inputs[:sb])
            ra = merkle_root(leaf_inputs[:sa])
            rb = merkle_root(leaf_inputs[:sb])
            if not verify_consistency(sa, sb, proof, ra, rb):
                result["consistency_ok"] = False
                result["problems"].append(
                    f"consistency broken between checkpoints "
                    f"{a['checkpoint_id']} and {b['checkpoint_id']}")

    result["ok"] = (result["chain_ok"] and result["checkpoints_ok"]
                    and result["consistency_ok"])
    return result
