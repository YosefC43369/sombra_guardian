"""
test_integrity_ledger.py — Test suite for integrity_ledger.py (Tamper-Evident
Merkle Audit Ledger).

Same isolation pattern as test_wallet.py / test_findings.py: every test gets a
fresh temp SQLite file, and every data-layer module's own already-bound
`DB_PATH` is redirected explicitly (each does `from security import DB_PATH`,
which copies the name at import time). Exercises the real public API plus the
pure Merkle primitives, and — most importantly — proves the tamper-evidence
claim by editing the database directly and confirming verify_chain() catches it.
"""

import os
import hashlib
import tempfile
import threading
import unittest

import security
import integrity_ledger as il
import integrity_report as ir


class MerkleMathTest(unittest.TestCase):
    """The pure functions need no DB. These lock down RFC 6962 behavior."""

    def _leaves(self, n):
        return [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(n)]

    def test_empty_and_single_leaf_vectors(self):
        # RFC 6962: empty tree hashes the empty string.
        self.assertEqual(il.merkle_root([]).hex(), hashlib.sha256(b"").hexdigest())
        # RFC 6962 published test vector for the hash of an empty leaf.
        self.assertEqual(
            il.merkle_root([b""]).hex(),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        )

    def test_inclusion_roundtrip_all_positions(self):
        for n in range(1, 33):
            leaves = self._leaves(n)
            root = il.merkle_root(leaves)
            for idx in range(n):
                path = il.merkle_audit_path(idx, leaves)
                lh = il.leaf_hash(leaves[idx])
                self.assertTrue(il.verify_inclusion(idx, n, lh, path, root),
                                f"n={n} idx={idx}")
                # A wrong root must be rejected.
                self.assertFalse(
                    il.verify_inclusion(idx, n, lh, path, hashlib.sha256(b"x").digest()))
                # A flipped sibling must be rejected.
                if path:
                    bad = list(path)
                    bad[0] = hashlib.sha256(b"flip").digest()
                    self.assertFalse(il.verify_inclusion(idx, n, lh, bad, root))

    def test_consistency_roundtrip(self):
        for n in range(1, 33):
            leaves = self._leaves(n)
            rn = il.merkle_root(leaves)
            for m in range(1, n + 1):          # m=0 is trivially consistent
                proof = il.merkle_consistency_proof(m, n, leaves)
                rm = il.merkle_root(leaves[:m])
                self.assertTrue(il.verify_consistency(m, n, proof, rm, rn),
                                f"m={m} n={n}")
                if m < n:
                    # A forged second root must be rejected.
                    self.assertFalse(il.verify_consistency(
                        m, n, proof, rm, hashlib.sha256(b"z").digest()))
                if 0 < m < n:
                    # A forged first root must be rejected.
                    self.assertFalse(il.verify_consistency(
                        m, n, proof, hashlib.sha256(b"q").digest(), rn))

    def test_canonical_json_is_key_order_independent(self):
        a = il.canonical_json({"b": 1, "a": 2, "c": [3, 2, 1]})
        b = il.canonical_json({"c": [3, 2, 1], "a": 2, "b": 1})
        self.assertEqual(a, b)


class IntegrityLedgerTest(unittest.TestCase):
    CHAT = 42

    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = path
        # No env secret -> the per-DB random secret path is exercised.
        os.environ.pop("INTEGRITY_SECRET", None)
        security.DB_PATH = path
        il.DB_PATH = path
        security.security_db_init()
        il.integrity_db_init()

    def tearDown(self):
        try:
            os.remove(self._db_path)
        except OSError:
            pass

    def _record(self, n, chat=None):
        chat = self.CHAT if chat is None else chat
        out = []
        for i in range(n):
            r = il.record_event(chat, il.EventType.MANUAL_NOTE, {"i": i, "text": f"e{i}"})
            self.assertTrue(r.ok, r.reason)
            out.append(r.data["entry"])
        return out

    # ---- append / chain ----

    def test_record_increments_seq_and_links_prev_hash(self):
        entries = self._record(4)
        self.assertEqual([e["seq"] for e in entries], [0, 1, 2, 3])
        self.assertEqual(entries[0]["prev_hash"], il.GENESIS_PREV_HASH)
        for a, b in zip(entries, entries[1:]):
            self.assertEqual(b["prev_hash"], a["entry_hash"])
        self.assertEqual(il.entry_count(self.CHAT), 4)

    def test_idempotency_key_replays(self):
        r1 = il.record_event(self.CHAT, il.EventType.ADMIN_ACTION, {"a": 1},
                             idempotency_key="k1")
        r2 = il.record_event(self.CHAT, il.EventType.ADMIN_ACTION, {"a": 1},
                             idempotency_key="k1")
        self.assertTrue(r1.ok and r2.ok)
        self.assertTrue(r2.data.get("already_recorded"))
        self.assertEqual(r1.data["entry"]["seq"], r2.data["entry"]["seq"])
        self.assertEqual(il.entry_count(self.CHAT), 1)

    def test_chats_are_isolated(self):
        self._record(3, chat=self.CHAT)
        self._record(2, chat=999)
        self.assertEqual(il.entry_count(self.CHAT), 3)
        self.assertEqual(il.entry_count(999), 2)
        # Independent genesis chains.
        self.assertEqual(il.get_entry(999, 0)["prev_hash"], il.GENESIS_PREV_HASH)

    def test_verify_clean_chain_ok(self):
        self._record(5)
        il.create_checkpoint(self.CHAT, created_by=1)
        res = il.verify_chain(self.CHAT)
        self.assertTrue(res["ok"], res["problems"])
        self.assertTrue(res["chain_ok"] and res["checkpoints_ok"]
                        and res["consistency_ok"])
        self.assertIsNone(res["first_bad_seq"])

    # ---- tamper detection (the whole point) ----

    def _raw_exec(self, sql, params=()):
        import sqlite3
        conn = sqlite3.connect(self._db_path)
        conn.execute(sql, params)
        conn.commit()
        conn.close()

    def test_detects_edited_payload(self):
        self._record(5)
        # Someone edits entry #2's payload directly in the DB.
        self._raw_exec(
            "UPDATE integrity_entries SET payload=? WHERE chat_id=? AND seq=?",
            ('{"i":2,"text":"HACKED"}', self.CHAT, 2))
        res = il.verify_chain(self.CHAT)
        self.assertFalse(res["ok"])
        self.assertFalse(res["chain_ok"])
        self.assertEqual(res["first_bad_seq"], 2)

    def test_detects_deleted_entry_after_checkpoint(self):
        self._record(5)
        il.create_checkpoint(self.CHAT, created_by=1)   # commits over 5 entries
        self._raw_exec("DELETE FROM integrity_entries WHERE chat_id=? AND seq=4",
                       (self.CHAT,))
        res = il.verify_chain(self.CHAT)
        self.assertFalse(res["ok"])
        # Checkpoint claims 5 entries, only 4 remain.
        self.assertFalse(res["checkpoints_ok"])

    def test_detects_reordered_seq(self):
        self._record(4)
        # Swap seq 1 and 2 (a reorder), which breaks the prev_hash linkage.
        self._raw_exec("UPDATE integrity_entries SET seq=99 WHERE chat_id=? AND seq=1",
                       (self.CHAT,))
        self._raw_exec("UPDATE integrity_entries SET seq=1 WHERE chat_id=? AND seq=2",
                       (self.CHAT,))
        self._raw_exec("UPDATE integrity_entries SET seq=2 WHERE chat_id=? AND seq=99",
                       (self.CHAT,))
        res = il.verify_chain(self.CHAT)
        self.assertFalse(res["ok"])
        self.assertFalse(res["chain_ok"])

    def test_detects_forged_checkpoint(self):
        self._record(3)
        il.create_checkpoint(self.CHAT, created_by=1)
        # Attacker rewrites the checkpoint's root but cannot re-sign it.
        fake_root = hashlib.sha256(b"fake").hexdigest()
        self._raw_exec(
            "UPDATE integrity_checkpoints SET merkle_root=? WHERE chat_id=?",
            (fake_root, self.CHAT))
        self.assertFalse(il.verify_signature(self.CHAT, 3, fake_root, "deadbeef"))
        res = il.verify_chain(self.CHAT)
        self.assertFalse(res["ok"])
        self.assertFalse(res["checkpoints_ok"])

    # ---- checkpoints ----

    def test_checkpoint_idempotent_when_unchanged(self):
        self._record(2)
        r1 = il.create_checkpoint(self.CHAT, created_by=1)
        r2 = il.create_checkpoint(self.CHAT, created_by=1)
        self.assertTrue(r1.ok and r2.ok)
        self.assertTrue(r2.data.get("unchanged"))
        self.assertEqual(len(il.list_checkpoints(self.CHAT)), 1)
        # After a new entry, a fresh checkpoint is minted.
        self._record(1)
        r3 = il.create_checkpoint(self.CHAT, created_by=1)
        self.assertFalse(r3.data.get("unchanged"))
        self.assertEqual(len(il.list_checkpoints(self.CHAT)), 2)

    def test_empty_ledger_can_be_checkpointed(self):
        r = il.create_checkpoint(self.CHAT, created_by=1)
        self.assertTrue(r.ok)
        self.assertEqual(r.data["checkpoint"]["tree_size"], 0)
        self.assertEqual(r.data["checkpoint"]["merkle_root"],
                         hashlib.sha256(b"").hexdigest())

    # ---- proofs against the live ledger ----

    def test_inclusion_proof_verifies(self):
        self._record(7)
        il.create_checkpoint(self.CHAT, created_by=1)
        for seq in range(7):
            r = il.inclusion_proof(self.CHAT, seq)
            self.assertTrue(r.ok, r.reason)
            d = r.data
            self.assertTrue(il.verify_inclusion(
                d["leaf_index"], d["tree_size"],
                bytes.fromhex(d["leaf_hash"]),
                [bytes.fromhex(h) for h in d["audit_path"]],
                bytes.fromhex(d["root"])))

    def test_inclusion_proof_rejects_entry_after_checkpoint(self):
        self._record(3)
        il.create_checkpoint(self.CHAT, created_by=1)  # tree_size = 3
        self._record(2)                                # seqs 3,4 not yet anchored
        r = il.inclusion_proof(self.CHAT, 4)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "ENTRY_AFTER_TREE_SIZE")

    def test_inclusion_proof_missing_entry(self):
        self._record(2)
        r = il.inclusion_proof(self.CHAT, 99)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "ENTRY_NOT_FOUND")

    def test_consistency_proof_between_checkpoints(self):
        self._record(3)
        il.create_checkpoint(self.CHAT, created_by=1)   # size 3
        self._record(4)
        il.create_checkpoint(self.CHAT, created_by=1)   # size 7
        r = il.consistency_proof(self.CHAT, 3, 7)
        self.assertTrue(r.ok, r.reason)
        d = r.data
        self.assertTrue(il.verify_consistency(
            d["first_size"], d["second_size"],
            [bytes.fromhex(h) for h in d["proof"]],
            bytes.fromhex(d["first_root"]),
            bytes.fromhex(d["second_root"])))

    def test_consistency_proof_rejects_bad_sizes(self):
        self._record(3)
        r = il.consistency_proof(self.CHAT, 5, 3)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "INVALID_SIZES")

    # ---- concurrency: no two entries share a seq ----

    def test_concurrent_appends_are_serialized(self):
        def worker(k):
            il.record_event(self.CHAT, il.EventType.DETECTION, {"k": k})
        threads = [threading.Thread(target=worker, args=(k,)) for k in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(il.entry_count(self.CHAT), 20)
        # verify_chain also proves every prev_hash links up, i.e. no seq clash.
        res = il.verify_chain(self.CHAT)
        self.assertTrue(res["ok"], res["problems"])
        seqs = sorted(il.get_entry(self.CHAT, s)["seq"] for s in range(20))
        self.assertEqual(seqs, list(range(20)))

    # ---- report layer smoke ----

    def test_report_layer_renders(self):
        self._record(2)
        ck = il.create_checkpoint(self.CHAT, created_by=1).data["checkpoint"]
        self.assertIn("Integrity", ir.format_status(2, ck, il.current_root(self.CHAT)))
        self.assertIn("✅", ir.format_verify(il.verify_chain(self.CHAT)))
        self.assertTrue(ir.deny_text("ENTRY_NOT_FOUND").startswith("❌"))


if __name__ == "__main__":
    unittest.main()
