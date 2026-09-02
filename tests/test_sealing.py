"""Per-record sealing: the application writes what it cannot read.

Under v1 the application held one key that opened every observation, so the
policy engine was the only thing between a compromised process and the whole
archive. Here the write path holds a public key only, and opening goes
through the disclosure service, which requires an approver's signature.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import helpers  # noqa: E402
from justikey import (approvals, crypto_store, db, disclosure, models,  # noqa: E402
                      policy, sealing, timeutil)

SKIP = not sealing.SEALING_AVAILABLE


@unittest.skipIf(SKIP, "sealing requires the cryptography package")
class SealedDatabaseTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "justikey.db")
        db.init_db(self.path)
        self.conn = db.get_connection(self.path)
        self.source = models.create_source(self.conn, "cam", "Cam")
        self.requester_id = models.create_user(self.conn, "officer1", "pw", "requester")
        self.approver_id = models.create_user(self.conn, "supervisor1", "pw", "approver")
        self.now = timeutil.now()

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def add(self, plate="SECRET99", location="Elm Street Depot", offset_hours=1, camera="CAM-1"):
        return models.insert_event(
            self.conn, plate, timeutil.to_canonical(self.now - timedelta(hours=offset_hours)),
            camera, 0.95, location, "claimed", source_ref=self.source)

    def authorize(self, plate="SECRET99", days=1):
        auth_id = models.create_authorization(
            self.conn, "CASE-1", "Warrant 1", "Investigation", plate,
            timeutil.to_canonical(self.now - timedelta(days=days)),
            timeutil.to_canonical(self.now + timedelta(days=days)), self.requester_id)
        helpers.approve_signed(self.conn, auth_id, self.approver_id)
        return auth_id

    def requester(self):
        return models.get_user_by_id(self.conn, self.requester_id)


class TestTheApplicationCannotRead(SealedDatabaseTest):
    def test_new_databases_seal_records_by_default(self):
        self.assertEqual(crypto_store.encryption_mode(self.conn), crypto_store.MODE_V2)

    def test_plaintext_never_reaches_the_database_file(self):
        self.add()
        self.conn.close()
        with open(self.path, "rb") as fh:
            raw = fh.read()
        self.assertNotIn(b"SECRET99", raw)
        self.assertNotIn(b"Elm Street Depot", raw)
        self.conn = db.get_connection(self.path)

    def test_search_returns_records_still_sealed(self):
        """The query path has no way to reveal a plate."""
        self.add()
        rows = models.search_events(
            self.conn, "SECRET99",
            timeutil.to_canonical(self.now - timedelta(days=1)),
            timeutil.to_canonical(self.now + timedelta(days=1)))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["plate"], "")
        self.assertIsNone(rows[0]["location"])
        self.assertTrue(rows[0]["record_ct"])
        self.assertNotIn("SECRET99", json.dumps(rows[0], default=str))

    def test_the_field_cipher_cannot_open_a_sealed_record(self):
        """The key the application does hold is the wrong kind of key."""
        self.add()
        row = self.conn.execute("SELECT * FROM lpr_events").fetchone()
        cipher = models.cipher_for(self.conn)
        with self.assertRaises(crypto_store.WrongKeyError):
            cipher.decrypt(row["record_ct"],
                           crypto_store.record_aad(row["captured_at"], row["camera_id"]))

    def test_the_sealer_holds_no_private_key(self):
        sealer = models.sealer_for(self.conn)
        self.assertIsNotNone(sealer)
        self.assertFalse(hasattr(sealer, "open"))


class TestDisclosureThroughTheService(SealedDatabaseTest):
    def test_an_approved_request_discloses_in_scope_records(self):
        self.add()
        auth_id = self.authorize()
        allowed, reason, events = policy.evaluate_disclosure(
            self.conn, auth_id, "SECRET99", self.requester())
        self.assertTrue(allowed, reason)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["plate"], "SECRET99")
        self.assertEqual(events[0]["location"], "Elm Street Depot")

    def test_records_outside_the_window_are_never_opened(self):
        self.add(offset_hours=1)
        self.add(offset_hours=24 * 30)      # far outside the authorized window
        auth_id = self.authorize(days=1)
        allowed, reason, events = policy.evaluate_disclosure(
            self.conn, auth_id, "SECRET99", self.requester())
        self.assertTrue(allowed, reason)
        self.assertEqual(len(events), 1)

    def test_another_vehicle_is_never_opened(self):
        self.add(plate="SECRET99")
        self.add(plate="OTHER11")
        auth_id = self.authorize("SECRET99")
        allowed, _, events = policy.evaluate_disclosure(
            self.conn, auth_id, "SECRET99", self.requester())
        self.assertTrue(allowed)
        self.assertEqual([e["plate"] for e in events], ["SECRET99"])

    def test_null_location_survives_sealing(self):
        self.add(location=None)
        auth_id = self.authorize()
        _, _, events = policy.evaluate_disclosure(
            self.conn, auth_id, "SECRET99", self.requester())
        self.assertIsNone(events[0]["location"])


class TestTheServiceDoesNotTrustItsCaller(SealedDatabaseTest):
    """The caller has already run the policy engine; a compromised caller is
    exactly the one whose filtering cannot be believed."""

    def setUp(self):
        super().setUp()
        self.add(plate="SECRET99")
        self.add(plate="OTHER11")
        self.auth_id = self.authorize("SECRET99")
        self.service = disclosure.service_for(self.conn, self.path)
        auth = models.get_authorization(self.conn, self.auth_id)
        approver = models.get_user_by_id(self.conn, self.approver_id)
        self.statement = approvals.build_statement(
            auth, "officer1", "supervisor1", auth["approved_at"],
            auth["approval_expires_at"])
        self.signature = auth["approval_signature"]
        self.approver_pub = approver["signing_pub"]
        self.all_rows = [dict(r) for r in
                         self.conn.execute("SELECT * FROM lpr_events").fetchall()]

    _KEEP = object()

    def disclose(self, rows=_KEEP, statement=_KEEP, signature=_KEEP, requester="officer1"):
        return self.service.disclose(
            self.all_rows if rows is self._KEEP else rows,
            self.statement if statement is self._KEEP else statement,
            self.signature if signature is self._KEEP else signature,
            self.approver_pub, requester)

    def test_handing_it_every_row_still_opens_only_the_authorized_one(self):
        revealed = self.disclose()
        self.assertEqual([e["plate"] for e in revealed], ["SECRET99"])

    def test_an_unsigned_request_is_refused(self):
        for missing in (None, "", "00" * 64):
            with self.assertRaises(disclosure.DisclosureError):
                self.disclose(signature=missing)

    def test_a_request_without_an_approver_key_is_refused(self):
        with self.assertRaises(disclosure.DisclosureError):
            self.service.disclose(self.all_rows, self.statement, self.signature,
                                  None, "officer1")

    def test_a_statement_widened_after_signing_is_refused(self):
        widened = dict(self.statement, target_plate="OTHER11")
        with self.assertRaises(disclosure.DisclosureError):
            self.disclose(statement=widened)

    def test_a_window_widened_after_signing_is_refused(self):
        widened = dict(self.statement, window_start=timeutil.parse("2000-01-01T00:00"))
        with self.assertRaises(disclosure.DisclosureError):
            self.disclose(statement=widened)

    def test_another_requester_cannot_use_the_approval(self):
        with self.assertRaises(disclosure.DisclosureError):
            self.disclose(requester="officer2")

    def test_an_expired_approval_is_refused(self):
        auth = models.get_authorization(self.conn, self.auth_id)
        expired = timeutil.to_canonical(self.now - timedelta(minutes=1))
        statement = approvals.build_statement(
            auth, "officer1", "supervisor1", auth["approved_at"], expired)
        key = approvals.unwrap_signing_key(
            models.get_user_by_id(self.conn, self.approver_id), "pw")
        with self.assertRaises(disclosure.DisclosureError):
            self.disclose(statement=statement,
                          signature=approvals.sign_statement(key, statement))

    def test_a_self_approved_statement_is_refused(self):
        statement = dict(self.statement, approver="officer1", requester="officer1")
        key = approvals.unwrap_signing_key(
            models.get_user_by_id(self.conn, self.approver_id), "pw")
        with self.assertRaises(disclosure.DisclosureError):
            self.disclose(statement=statement,
                          signature=approvals.sign_statement(key, statement))


class TestSealTampering(SealedDatabaseTest):
    def test_a_wrapped_key_moved_to_another_sighting_cannot_be_used(self):
        self.add(plate="SECRET99", camera="CAM-1", offset_hours=1)
        self.add(plate="DECOY11", camera="CAM-9", offset_hours=2)
        rows = self.conn.execute("SELECT * FROM lpr_events ORDER BY id").fetchall()
        self.conn.execute(
            "UPDATE lpr_events SET record_ct=?, wrapped_key=?, ephemeral_pub=?, plate_index=? "
            "WHERE id=?",
            (rows[0]["record_ct"], rows[0]["wrapped_key"], rows[0]["ephemeral_pub"],
             rows[0]["plate_index"], rows[1]["id"]))
        auth_id = self.authorize("SECRET99", days=1)
        allowed, reason, _ = policy.evaluate_disclosure(
            self.conn, auth_id, "SECRET99", self.requester())
        self.assertFalse(allowed)
        self.assertEqual(reason, "disclosure_refused")

    def test_a_corrupted_seal_is_refused_not_guessed(self):
        self.add()
        row = self.conn.execute("SELECT id, record_ct FROM lpr_events").fetchone()
        flipped = ("A" if row["record_ct"][0] != "A" else "B") + row["record_ct"][1:]
        self.conn.execute("UPDATE lpr_events SET record_ct=? WHERE id=?", (flipped, row["id"]))
        auth_id = self.authorize()
        allowed, reason, _ = policy.evaluate_disclosure(
            self.conn, auth_id, "SECRET99", self.requester())
        self.assertFalse(allowed)


@unittest.skipIf(SKIP, "sealing requires the cryptography package")
class TestSealingPrimitives(unittest.TestCase):
    def test_seal_and_open_round_trip(self):
        private_hex, public_hex = sealing.generate_keypair()
        sealer = sealing.RecordSealer(public_hex)
        opener = sealing.RecordOpener(private_hex)
        sealed, wrapped, ephemeral = sealer.seal({"plate": "ABC123"}, "aad")
        self.assertEqual(opener.open(sealed, wrapped, ephemeral, "aad"), {"plate": "ABC123"})

    def test_a_different_private_key_cannot_open(self):
        _, public_hex = sealing.generate_keypair()
        other_private, _ = sealing.generate_keypair()
        sealed, wrapped, ephemeral = sealing.RecordSealer(public_hex).seal({"p": 1}, "aad")
        with self.assertRaises(sealing.SealingError):
            sealing.RecordOpener(other_private).open(sealed, wrapped, ephemeral, "aad")

    def test_the_aad_must_match(self):
        private_hex, public_hex = sealing.generate_keypair()
        sealed, wrapped, ephemeral = sealing.RecordSealer(public_hex).seal({"p": 1}, "aad")
        with self.assertRaises(sealing.SealingError):
            sealing.RecordOpener(private_hex).open(sealed, wrapped, ephemeral, "different-aad")

    def test_each_seal_uses_a_fresh_record_key(self):
        _, public_hex = sealing.generate_keypair()
        sealer = sealing.RecordSealer(public_hex)
        a = sealer.seal({"plate": "SAME"}, "aad")
        b = sealer.seal({"plate": "SAME"}, "aad")
        self.assertNotEqual(a[0], b[0], "identical plaintext must not seal identically")
        self.assertNotEqual(a[1], b[1])

    def test_public_key_derivation_is_consistent(self):
        private_hex, public_hex = sealing.generate_keypair()
        self.assertEqual(sealing.public_from_private(private_hex), public_hex)
        self.assertEqual(sealing.RecordOpener(private_hex).public_hex, public_hex)

    def test_malformed_keys_are_rejected(self):
        with self.assertRaises(sealing.SealingError):
            sealing.RecordSealer("not-a-key")
        with self.assertRaises(sealing.SealingError):
            sealing.RecordOpener("not-a-key")


if __name__ == "__main__":
    unittest.main()


class TestDisclosureServiceUnavailable(SealedDatabaseTest):
    """The key holder being unreachable is an operating state, not a crash.

    Availability of the disclosure service becomes a safety property: lawful
    access stops, which is correct, but it must stop legibly.
    """

    def test_records_stay_sealed_and_the_denial_is_clean(self):
        self.add()
        auth_id = self.authorize()
        os.rename(disclosure.key_file_for(self.path), os.path.join(self.dir, "moved.key"))
        try:
            allowed, reason, events = policy.evaluate_disclosure(
                self.conn, auth_id, "SECRET99", self.requester())
        finally:
            os.rename(os.path.join(self.dir, "moved.key"), disclosure.key_file_for(self.path))
        self.assertFalse(allowed)
        self.assertEqual(reason, "disclosure_unavailable")
        self.assertEqual(events, [])
        self.assertIn(reason, policy.DENIAL_MESSAGES)

    def test_access_resumes_once_the_service_returns(self):
        self.add()
        auth_id = self.authorize()
        allowed, reason, events = policy.evaluate_disclosure(
            self.conn, auth_id, "SECRET99", self.requester())
        self.assertTrue(allowed, reason)
        self.assertEqual(len(events), 1)
