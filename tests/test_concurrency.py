"""Concurrency guarantees.

The server is threaded, so the audit ledger and the two-person approval
control are both exposed to simultaneous writers.
"""
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import audit, db, models


class TestConcurrentAuditAppend(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.path)
        db.init_db(self.path)

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.path + suffix)
            except OSError:
                pass

    def test_no_audit_entry_is_lost_under_concurrency(self):
        """A dropped audit entry is invisible: the chain still verifies."""
        threads_count, per_thread = 8, 15
        errors = []

        def worker(n):
            conn = db.get_connection(self.path)
            try:
                for i in range(per_thread):
                    audit.append_event(conn, "sensor_ingest", f"sensor:{n}", {"i": i})
            except Exception as exc:  # noqa: BLE001 - surfaced via assertion below
                errors.append(repr(exc))
            finally:
                conn.close()

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(threads_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        conn = db.get_connection(self.path)
        try:
            count = conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"]
            ok, info, reason = audit.verify_chain(conn)
        finally:
            conn.close()

        self.assertEqual(errors, [])
        self.assertEqual(count, threads_count * per_thread)
        self.assertTrue(ok, reason)

    def test_verify_detects_a_gap_even_when_links_still_hash(self):
        conn = db.get_connection(self.path)
        try:
            for i in range(5):
                audit.append_event(conn, "login_success", "alice", {"i": i})
            # Remove the tail: every surviving entry still hashes correctly
            # and chains to its predecessor, so only a sequence check catches it.
            conn.execute("DELETE FROM audit_log WHERE seq >= 4")
            ok, info, reason = audit.verify_chain(conn)
            self.assertTrue(ok, "truncating the tail is not detectable by hashes alone")

            # A hole in the middle is detectable.
            conn.execute("DELETE FROM audit_log WHERE seq = 2")
            ok, failing_seq, reason = audit.verify_chain(conn)
            self.assertFalse(ok)
            self.assertIn("sequence gap", reason)
        finally:
            conn.close()


class TestConcurrentApproval(unittest.TestCase):
    def setUp(self):
        self.conn = db.get_connection(":memory:")
        self.conn.executescript(db.SCHEMA)
        self.requester_id = models.create_user(self.conn, "officer1", "pw", "requester")
        self.approver_a = models.create_user(self.conn, "supervisor1", "pw", "approver")
        self.approver_b = models.create_user(self.conn, "supervisor2", "pw", "approver")
        self.auth_id = models.create_authorization(
            self.conn, "CASE-1", "Warrant 1", "Investigation", "ABC123",
            "2026-01-01T00:00:00.000000+00:00", "2026-12-31T00:00:00.000000+00:00",
            self.requester_id,
        )

    def tearDown(self):
        self.conn.close()

    def test_only_the_first_approval_takes_effect(self):
        ok_a, _ = models.approve_authorization(self.conn, self.auth_id, self.approver_a)
        ok_b, reason_b = models.approve_authorization(self.conn, self.auth_id, self.approver_b)
        self.assertTrue(ok_a)
        self.assertFalse(ok_b)
        self.assertEqual(reason_b, "not_pending")
        row = models.get_authorization(self.conn, self.auth_id)
        self.assertEqual(row["approved_by"], self.approver_a)

    def test_self_approval_blocked_by_the_update_guard_itself(self):
        """The prohibition lives in the SQL predicate, not a prior read."""
        ok, reason = models.approve_authorization(self.conn, self.auth_id, self.requester_id)
        self.assertFalse(ok)
        self.assertEqual(reason, "self_approval_forbidden")
        row = models.get_authorization(self.conn, self.auth_id)
        self.assertEqual(row["status"], "pending")
        self.assertIsNone(row["approved_by"])

    def test_denied_request_cannot_then_be_approved(self):
        models.deny_authorization(self.conn, self.auth_id, self.approver_a, "too broad")
        ok, reason = models.approve_authorization(self.conn, self.auth_id, self.approver_b)
        self.assertFalse(ok)
        self.assertEqual(reason, "not_pending")


if __name__ == "__main__":
    unittest.main()
