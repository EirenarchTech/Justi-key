import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import db, models, policy


def iso(dt):
    return dt.isoformat()


class TestPolicyEngine(unittest.TestCase):
    def setUp(self):
        self.conn = db.get_connection(":memory:")
        self.conn.executescript(db.SCHEMA)
        self.requester_id = models.create_user(self.conn, "officer1", "pw", "requester")
        self.approver_id = models.create_user(self.conn, "supervisor1", "pw", "approver")
        self.other_requester_id = models.create_user(self.conn, "officer2", "pw", "requester")

        self.now = datetime.now(timezone.utc)
        models.insert_event(
            self.conn, "ABC123", iso(self.now - timedelta(hours=1)), "CAM-1", 0.95, "North Gate", "sim"
        )
        models.insert_event(
            self.conn, "ABC123", iso(self.now - timedelta(days=5)), "CAM-1", 0.95, "North Gate", "sim"
        )
        models.insert_event(
            self.conn, "ZZZ999", iso(self.now - timedelta(hours=1)), "CAM-2", 0.90, "South Lot", "sim"
        )

        self.auth_id = models.create_authorization(
            self.conn,
            case_number="CASE-1",
            legal_authority="Warrant 1",
            purpose="Investigation",
            target_plate="ABC123",
            window_start=iso(self.now - timedelta(hours=2)),
            window_end=iso(self.now + timedelta(hours=2)),
            requested_by=self.requester_id,
        )

    def tearDown(self):
        self.conn.close()

    def _requester(self):
        return models.get_user_by_id(self.conn, self.requester_id)

    def test_unapproved_request_denies_disclosure(self):
        allowed, reason, events = policy.evaluate_disclosure(self.conn, self.auth_id, "ABC123", self._requester())
        self.assertFalse(allowed)
        self.assertEqual(reason, "authorization_not_approved")
        self.assertEqual(events, [])

    def test_self_approval_is_rejected(self):
        ok, reason = models.approve_authorization(self.conn, self.auth_id, self.requester_id)
        self.assertFalse(ok)
        self.assertEqual(reason, "self_approval_forbidden")

    def test_independent_approval_allows_scoped_disclosure(self):
        ok, reason = models.approve_authorization(self.conn, self.auth_id, self.approver_id)
        self.assertTrue(ok)
        allowed, reason, events = policy.evaluate_disclosure(self.conn, self.auth_id, "ABC123", self._requester())
        self.assertTrue(allowed)
        self.assertEqual(len(events), 1)  # only the in-window observation
        self.assertEqual(events[0]["plate"], "ABC123")

    def test_wrong_plate_denied_even_after_approval(self):
        models.approve_authorization(self.conn, self.auth_id, self.approver_id)
        allowed, reason, events = policy.evaluate_disclosure(self.conn, self.auth_id, "ZZZ999", self._requester())
        self.assertFalse(allowed)
        self.assertEqual(reason, "plate_mismatch")

    def test_other_user_cannot_use_someone_elses_authorization(self):
        models.approve_authorization(self.conn, self.auth_id, self.approver_id)
        other = models.get_user_by_id(self.conn, self.other_requester_id)
        allowed, reason, events = policy.evaluate_disclosure(self.conn, self.auth_id, "ABC123", other)
        self.assertFalse(allowed)
        self.assertEqual(reason, "authorization_not_owned_by_requester")

    def test_expired_authorization_denies_disclosure(self):
        models.approve_authorization(self.conn, self.auth_id, self.approver_id)
        # Force expiry into the past.
        self.conn.execute(
            "UPDATE authorizations SET approval_expires_at=? WHERE id=?",
            (iso(self.now - timedelta(minutes=1)), self.auth_id),
        )
        self.conn.commit()
        allowed, reason, events = policy.evaluate_disclosure(self.conn, self.auth_id, "ABC123", self._requester())
        self.assertFalse(allowed)
        self.assertEqual(reason, "authorization_expired")


if __name__ == "__main__":
    unittest.main()
