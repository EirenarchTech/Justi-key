import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import audit, db


class TestAuditChain(unittest.TestCase):
    def setUp(self):
        self.conn = db.get_connection(":memory:")
        self.conn.executescript(db.SCHEMA)

    def tearDown(self):
        self.conn.close()

    def test_chain_verifies_when_untouched(self):
        audit.append_event(self.conn, "login_success", "alice", {"role": "requester"})
        audit.append_event(self.conn, "authorization_requested", "alice", {"authorization_id": 1})
        audit.append_event(self.conn, "authorization_approved", "bob", {"authorization_id": 1})
        ok, count, reason = audit.verify_chain(self.conn)
        self.assertTrue(ok)
        self.assertEqual(count, 3)
        self.assertIsNone(reason)

    def test_tampered_details_breaks_chain(self):
        audit.append_event(self.conn, "login_success", "alice", {"role": "requester"})
        audit.append_event(self.conn, "disclosure", "alice", {"record_count": 1})
        self.conn.execute("UPDATE audit_log SET details=? WHERE seq=1", ('{"role":"approver"}',))
        self.conn.commit()
        ok, failing_seq, reason = audit.verify_chain(self.conn)
        self.assertFalse(ok)
        self.assertEqual(failing_seq, 1)

    def test_deleted_entry_breaks_chain(self):
        audit.append_event(self.conn, "login_success", "alice", {})
        audit.append_event(self.conn, "login_success", "bob", {})
        audit.append_event(self.conn, "login_success", "carol", {})
        self.conn.execute("DELETE FROM audit_log WHERE seq=2")
        self.conn.commit()
        ok, failing_seq, reason = audit.verify_chain(self.conn)
        self.assertFalse(ok)
        self.assertEqual(failing_seq, 3)


if __name__ == "__main__":
    unittest.main()
