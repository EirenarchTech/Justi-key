"""Anchoring: making tail truncation detectable.

The hash chain alone cannot detect deletion of its newest entries. These
tests exercise the attack it misses and confirm anchoring catches it.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import anchor, audit, config, db


class AnchorTestBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.dir, "justikey.db")
        db.init_db(self.db_path)
        self.conn = db.get_connection(self.db_path)
        self.store = anchor.AnchorStore(
            os.path.join(self.dir, "anchors.jsonl"), key=b"\x01" * 32
        )

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def append(self, n, actor="alice"):
        for i in range(n):
            audit.append_event(self.conn, "login_success", actor, {"i": i})


class TestTruncationDetection(AnchorTestBase):
    def test_chain_alone_cannot_detect_tail_truncation(self):
        """Establishes the gap that anchoring exists to close."""
        self.append(10)
        self.conn.execute("DELETE FROM audit_log WHERE seq > 6")
        ok, count, reason = audit.verify_chain(self.conn)
        self.assertTrue(ok, "a truncated chain is expected to still self-verify")
        self.assertEqual(count, 6)

    def test_anchors_prove_the_missing_tail(self):
        self.append(10)
        anchor.create_anchor(self.conn, self.store)
        self.conn.execute("DELETE FROM audit_log WHERE seq > 6")

        # The chain still says everything is fine...
        self.assertTrue(audit.verify_chain(self.conn)[0])
        # ...but the published checkpoint contradicts it.
        result = anchor.verify_anchors(self.conn, self.store)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "truncated")
        self.assertEqual(result["missing_entries"], 4)
        self.assertEqual(result["highest_anchored_seq"], 10)
        self.assertEqual(result["ledger_seq"], 6)

    def test_truncation_back_to_exactly_an_anchor_is_still_caught(self):
        self.append(5)
        anchor.create_anchor(self.conn, self.store)   # anchors seq=5
        self.append(5)
        anchor.create_anchor(self.conn, self.store)   # anchors seq=10
        self.conn.execute("DELETE FROM audit_log WHERE seq > 5")
        result = anchor.verify_anchors(self.conn, self.store)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "truncated")

    def test_intact_ledger_verifies(self):
        self.append(10)
        anchor.create_anchor(self.conn, self.store)
        self.append(3)  # growing past the anchor is normal, not a failure
        result = anchor.verify_anchors(self.conn, self.store)
        self.assertTrue(result["ok"], result["message"])
        self.assertEqual(result["status"], "ok")

    def test_rewritten_history_is_caught_even_at_the_right_length(self):
        """Re-chaining after an edit restores length but not the anchored hash."""
        self.append(10)
        anchor.create_anchor(self.conn, self.store)
        # Rebuild entry 3 and everything after it so the chain is internally
        # consistent again -- what a careful attacker would do.
        rows = self.conn.execute(
            "SELECT * FROM audit_log WHERE seq >= 3 ORDER BY seq").fetchall()
        prev = self.conn.execute("SELECT hash FROM audit_log WHERE seq=2").fetchone()["hash"]
        self.conn.execute("DELETE FROM audit_log WHERE seq >= 3")
        for row in rows:
            details = '{"i":999}' if row["seq"] == 3 else row["details"]
            new_hash = audit._entry_hash(row["seq"], row["timestamp"], row["event_type"],
                                         row["actor"], details, prev)
            self.conn.execute(
                "INSERT INTO audit_log (seq,timestamp,event_type,actor,details,prev_hash,hash) "
                "VALUES (?,?,?,?,?,?,?)",
                (row["seq"], row["timestamp"], row["event_type"], row["actor"],
                 details, prev, new_hash))
            prev = new_hash

        self.assertTrue(audit.verify_chain(self.conn)[0], "rewrite should re-chain cleanly")
        result = anchor.verify_anchors(self.conn, self.store)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "rewritten")


class TestAnchorLogIntegrity(AnchorTestBase):
    def test_forged_anchor_is_rejected(self):
        self.append(5)
        anchor.create_anchor(self.conn, self.store)
        records, _ = self.store.read_all()
        forged = dict(records[0], audit_seq=2)
        forged["hash"] = anchor.payload_hash(anchor.anchor_payload(forged))
        with open(self.store.path, "w") as fh:
            fh.write(json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n")
        result = anchor.verify_anchors(self.conn, self.store)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "forged")

    def test_anchor_signed_with_the_wrong_key_is_rejected(self):
        self.append(5)
        anchor.create_anchor(self.conn, self.store)
        other = anchor.AnchorStore(self.store.path, key=b"\x02" * 32)
        result = anchor.verify_anchors(self.conn, other)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "forged")

    def test_removing_an_anchor_from_the_middle_is_caught(self):
        for _ in range(3):
            self.append(4)
            anchor.create_anchor(self.conn, self.store)
        records, _ = self.store.read_all()
        self.assertEqual(len(records), 3)
        with open(self.store.path, "w") as fh:
            for rec in (records[0], records[2]):
                fh.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")
        result = anchor.verify_anchors(self.conn, self.store)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "broken_anchor_chain")

    def test_malformed_anchor_log_is_reported(self):
        self.append(5)
        anchor.create_anchor(self.conn, self.store)
        with open(self.store.path, "a") as fh:
            fh.write("{not json\n")
        result = anchor.verify_anchors(self.conn, self.store)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "malformed")

    def test_no_anchors_is_reported_but_not_an_integrity_failure(self):
        self.append(3)
        result = anchor.verify_anchors(self.conn, self.store)
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "no_anchors")


class TestAnchorCreation(AnchorTestBase):
    def test_anchors_link_into_their_own_chain(self):
        for _ in range(3):
            self.append(2)
            anchor.create_anchor(self.conn, self.store)
        records, _ = self.store.read_all()
        self.assertEqual([r["anchor_seq"] for r in records], [1, 2, 3])
        self.assertEqual(records[0]["prev_anchor_hash"], anchor.GENESIS_ANCHOR_HASH)
        self.assertEqual(records[1]["prev_anchor_hash"], records[0]["hash"])
        self.assertEqual(records[2]["prev_anchor_hash"], records[1]["hash"])

    def test_reanchoring_an_unchanged_head_is_a_no_op(self):
        self.append(4)
        self.assertIsNotNone(anchor.create_anchor(self.conn, self.store))
        self.assertIsNone(anchor.create_anchor(self.conn, self.store))
        self.assertEqual(len(self.store.read_all()[0]), 1)

    def test_empty_ledger_produces_no_anchor(self):
        self.assertIsNone(anchor.create_anchor(self.conn, self.store))

    def test_automatic_anchoring_fires_on_the_configured_interval(self):
        original = config.ANCHOR_INTERVAL_ENTRIES
        config.ANCHOR_INTERVAL_ENTRIES = 5
        try:
            # Uses the connection-derived store, exercising the real path
            # audit.append_event takes.
            self.append(12)
            store = anchor.AnchorStore.for_connection(self.conn)
            records, _ = store.read_all()
            self.assertGreaterEqual(len(records), 2)
            self.assertLessEqual(anchor.entries_since_last_anchor(self.conn, store), 5)
            self.assertTrue(anchor.verify_anchors(self.conn, store)["ok"])
        finally:
            config.ANCHOR_INTERVAL_ENTRIES = original

    def test_anchor_key_file_is_created_private(self):
        store = anchor.AnchorStore.for_connection(self.conn)
        self.assertIsNotNone(store)
        key_path = os.path.join(self.dir, "justikey.anchor-key")
        self.assertTrue(os.path.exists(key_path))
        self.assertEqual(os.stat(key_path).st_mode & 0o777, 0o600)

    def test_in_memory_database_has_no_anchor_store(self):
        mem = db.get_connection(":memory:")
        try:
            self.assertIsNone(anchor.AnchorStore.for_connection(mem))
        finally:
            mem.close()


if __name__ == "__main__":
    unittest.main()
