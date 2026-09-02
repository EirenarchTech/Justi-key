"""Approver-signed authorizations.

The signature binds an approval to the exact scope approved. Editing what an
approved authorization covers should invalidate it, rather than silently
producing a different vehicle's history under a real approver's name.
"""
import os
import sys
import unittest
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import helpers  # noqa: E402
from justikey import approvals, config, db, models, policy, timeutil  # noqa: E402

SKIP = not approvals.SIGNING_AVAILABLE


@unittest.skipIf(SKIP, "signing requires the cryptography package")
class SignedApprovalTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.get_connection(":memory:")
        self.conn.executescript(db.SCHEMA)
        self.requester_id = models.create_user(self.conn, "officer1", "pw", "requester")
        self.approver_id = models.create_user(self.conn, "supervisor1", "pw", "approver")
        now = timeutil.now()
        models.insert_event(self.conn, "ABC123", timeutil.to_canonical(now - timedelta(hours=1)),
                            "CAM-1", 0.95, "Gate", "sim")
        models.insert_event(self.conn, "ZZZ999", timeutil.to_canonical(now - timedelta(hours=1)),
                            "CAM-2", 0.95, "Lot", "sim")
        self.auth_id = models.create_authorization(
            self.conn, "CASE-1", "Warrant 1", "Investigation", "ABC123",
            timeutil.to_canonical(now - timedelta(days=1)),
            timeutil.to_canonical(now + timedelta(days=1)), self.requester_id)

    def tearDown(self):
        self.conn.close()

    def requester(self):
        return models.get_user_by_id(self.conn, self.requester_id)

    def auth(self):
        return models.get_authorization(self.conn, self.auth_id)

    def disclose(self, plate="ABC123"):
        return policy.evaluate_disclosure(self.conn, self.auth_id, plate, self.requester())


class TestSigningKeyCustody(SignedApprovalTest):
    def test_the_private_key_is_not_stored_in_the_clear(self):
        public_hex, wrapped, salt = approvals.generate_signing_key("pw")
        self.assertNotIn(public_hex, wrapped)
        models.set_signing_key(self.conn, self.approver_id, public_hex, wrapped, salt)
        row = models.get_user_by_id(self.conn, self.approver_id)
        self.assertIsNotNone(row["signing_key_ct"])
        self.assertNotEqual(row["signing_key_ct"], row["signing_pub"])

    def test_the_key_unlocks_only_with_the_right_password(self):
        public_hex, wrapped, salt = approvals.generate_signing_key("pw")
        models.set_signing_key(self.conn, self.approver_id, public_hex, wrapped, salt)
        user = models.get_user_by_id(self.conn, self.approver_id)
        self.assertIsNotNone(approvals.unwrap_signing_key(user, "pw"))
        with self.assertRaises(approvals.ApprovalKeyError):
            approvals.unwrap_signing_key(user, "wrong-password")

    def test_an_approver_without_a_key_cannot_be_unwrapped(self):
        user = models.get_user_by_id(self.conn, self.approver_id)
        with self.assertRaises(approvals.ApprovalKeyError):
            approvals.unwrap_signing_key(user, "pw")

    def test_each_approver_gets_a_distinct_key(self):
        a, _, _ = approvals.generate_signing_key("pw")
        b, _, _ = approvals.generate_signing_key("pw")
        self.assertNotEqual(a, b)


class TestSignedApprovalEnablesDisclosure(SignedApprovalTest):
    def test_a_signed_approval_verifies_and_discloses(self):
        ok, reason = helpers.approve_signed(self.conn, self.auth_id, self.approver_id)
        self.assertTrue(ok, reason)
        verified, why = approvals.verify_authorization(self.conn, self.auth())
        self.assertTrue(verified, why)
        allowed, reason, events = self.disclose()
        self.assertTrue(allowed, reason)
        self.assertEqual(len(events), 1)

    def test_an_unsigned_approval_is_refused_by_default(self):
        models.approve_authorization(self.conn, self.auth_id, self.approver_id)
        allowed, reason, _ = self.disclose()
        self.assertFalse(allowed)
        self.assertEqual(reason, "approval_signature_invalid")

    def test_the_signature_is_stored_on_the_authorization(self):
        helpers.approve_signed(self.conn, self.auth_id, self.approver_id)
        self.assertTrue(self.auth()["approval_signature"])


class TestPostApprovalTampering(SignedApprovalTest):
    """The attack a status column cannot see: leave the approval, change what
    it authorizes."""

    def setUp(self):
        super().setUp()
        helpers.approve_signed(self.conn, self.auth_id, self.approver_id)

    def alter(self, **fields):
        for column, value in fields.items():
            self.conn.execute(f"UPDATE authorizations SET {column}=? WHERE id=?",
                              (value, self.auth_id))

    def test_swapping_the_target_plate_invalidates_the_approval(self):
        self.alter(target_plate="ZZZ999")
        allowed, reason, _ = self.disclose("ZZZ999")
        self.assertFalse(allowed)
        self.assertEqual(reason, "approval_signature_invalid")

    def test_widening_the_window_invalidates_the_approval(self):
        """Widened just enough to stay inside the breadth limit, so only the
        signature can catch it -- the case the other checks would miss."""
        self.alter(window_start=timeutil.to_canonical(timeutil.now() - timedelta(days=10)))
        allowed, reason, _ = self.disclose()
        self.assertFalse(allowed)
        self.assertEqual(reason, "approval_signature_invalid")

    def test_a_grossly_widened_window_is_caught_by_the_breadth_limit_first(self):
        self.alter(window_start=timeutil.parse("2000-01-01T00:00"))
        allowed, reason, _ = self.disclose()
        self.assertFalse(allowed)
        self.assertEqual(reason, "window_too_broad")

    def test_extending_the_expiry_invalidates_the_approval(self):
        self.alter(approval_expires_at=timeutil.to_canonical(
            timeutil.now() + timedelta(days=3650)))
        allowed, reason, _ = self.disclose()
        self.assertFalse(allowed)
        self.assertEqual(reason, "approval_signature_invalid")

    def test_rewriting_the_legal_authority_invalidates_the_approval(self):
        self.alter(legal_authority="Warrant 9999 (fabricated)")
        allowed, reason, _ = self.disclose()
        self.assertFalse(allowed)

    def test_reassigning_the_authorization_to_another_requester_fails(self):
        other = models.create_user(self.conn, "officer2", "pw", "requester")
        self.alter(requested_by=other)
        allowed, reason, _ = policy.evaluate_disclosure(
            self.conn, self.auth_id, "ABC123", models.get_user_by_id(self.conn, other))
        self.assertFalse(allowed)
        self.assertEqual(reason, "approval_signature_invalid")

    def test_crediting_the_approval_to_a_different_approver_fails(self):
        other = models.create_user(self.conn, "supervisor2", "pw", "approver")
        public_hex, wrapped, salt = approvals.generate_signing_key("pw")
        models.set_signing_key(self.conn, other, public_hex, wrapped, salt)
        self.alter(approved_by=other)
        allowed, reason, _ = self.disclose()
        self.assertFalse(allowed)
        self.assertEqual(reason, "approval_signature_invalid")

    def test_an_untouched_approval_still_works(self):
        allowed, reason, _ = self.disclose()
        self.assertTrue(allowed, reason)


class TestForgery(SignedApprovalTest):
    def test_a_signature_from_another_key_is_refused(self):
        helpers.approve_signed(self.conn, self.auth_id, self.approver_id)
        forged_pub, wrapped, salt = approvals.generate_signing_key("attacker")
        rogue = approvals.unwrap_signing_key(
            {"signing_key_ct": wrapped, "signing_key_salt": salt, "signing_pub": forged_pub},
            "attacker")
        approver = models.get_user_by_id(self.conn, self.approver_id)
        requester = models.get_user_by_id(self.conn, self.requester_id)
        statement = approvals.build_statement(
            self.auth(), requester["username"], approver["username"],
            self.auth()["approved_at"], self.auth()["approval_expires_at"])
        self.conn.execute("UPDATE authorizations SET approval_signature=? WHERE id=?",
                          (approvals.sign_statement(rogue, statement), self.auth_id))
        allowed, reason, _ = self.disclose()
        self.assertFalse(allowed)

    def test_a_garbage_signature_is_refused(self):
        helpers.approve_signed(self.conn, self.auth_id, self.approver_id)
        self.conn.execute("UPDATE authorizations SET approval_signature=? WHERE id=?",
                          ("00" * 64, self.auth_id))
        self.assertFalse(self.disclose()[0])

    def test_verification_fails_when_the_approver_has_no_public_key(self):
        helpers.approve_signed(self.conn, self.auth_id, self.approver_id)
        self.conn.execute("UPDATE users SET signing_pub=NULL WHERE id=?", (self.approver_id,))
        ok, reason = approvals.verify_authorization(self.conn, self.auth())
        self.assertFalse(ok)
        self.assertIn("no signing key", reason)


class TestApprovalReceipt(SignedApprovalTest):
    def test_a_receipt_verifies_independently_of_the_database(self):
        """An approval should be provable to an outside party."""
        helpers.approve_signed(self.conn, self.auth_id, self.approver_id)
        receipt = approvals.approval_receipt(self.conn, self.auth())
        self.assertTrue(approvals.verify_statement(
            receipt["approver_public_key"], receipt["statement"], receipt["signature"]))

    def test_a_receipt_with_an_edited_statement_does_not_verify(self):
        helpers.approve_signed(self.conn, self.auth_id, self.approver_id)
        receipt = approvals.approval_receipt(self.conn, self.auth())
        receipt["statement"]["target_plate"] = "ZZZ999"
        self.assertFalse(approvals.verify_statement(
            receipt["approver_public_key"], receipt["statement"], receipt["signature"]))


class TestMigrationEscapeHatch(SignedApprovalTest):
    def test_unsigned_approvals_can_be_tolerated_during_migration(self):
        models.approve_authorization(self.conn, self.auth_id, self.approver_id)
        original = config.REQUIRE_SIGNED_APPROVALS
        config.REQUIRE_SIGNED_APPROVALS = False
        try:
            allowed, reason, _ = self.disclose()
            self.assertTrue(allowed, reason)
        finally:
            config.REQUIRE_SIGNED_APPROVALS = original

    def test_a_wrong_signature_is_refused_even_during_migration(self):
        """Tolerating 'no signature' must not tolerate 'bad signature'."""
        helpers.approve_signed(self.conn, self.auth_id, self.approver_id)
        self.conn.execute("UPDATE authorizations SET target_plate='ZZZ999' WHERE id=?",
                          (self.auth_id,))
        original = config.REQUIRE_SIGNED_APPROVALS
        config.REQUIRE_SIGNED_APPROVALS = False
        try:
            allowed, reason, _ = self.disclose("ZZZ999")
            self.assertFalse(allowed)
            self.assertEqual(reason, "approval_signature_invalid")
        finally:
            config.REQUIRE_SIGNED_APPROVALS = original


if __name__ == "__main__":
    unittest.main()
