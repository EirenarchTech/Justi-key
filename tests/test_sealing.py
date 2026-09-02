"""Per-record sealing and the disclosure boundary (stages 2-3).

The write path holds a public key only. Opening goes through the disclosure
service, which verifies the approver's signature against its own registry of
enrolled keys and re-derives scope for itself.
"""
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


class TestTheApplicationCannotDecrypt(SealedDatabaseTest):
    def test_new_databases_seal_records(self):
        self.assertEqual(crypto_store.encryption_mode(self.conn), crypto_store.MODE_V3)

    def test_plaintext_never_reaches_the_database_file(self):
        self.add()
        self.conn.close()
        with open(self.path, "rb") as fh:
            raw = fh.read()
        self.assertNotIn(b"SECRET99", raw)
        self.assertNotIn(b"Elm Street Depot", raw)
        self.conn = db.get_connection(self.path)

    def test_search_returns_records_still_sealed(self):
        self.add()
        rows = models.search_events(
            self.conn, "SECRET99",
            timeutil.to_canonical(self.now - timedelta(days=1)),
            timeutil.to_canonical(self.now + timedelta(days=1)))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["plate"], "")
        self.assertIsNone(rows[0]["location"])
        self.assertTrue(rows[0]["record_ct"])

    def test_the_envelope_records_its_version_and_recipient(self):
        self.add()
        row = self.conn.execute("SELECT * FROM lpr_events").fetchone()
        self.assertEqual(row["seal_version"], sealing.FORMAT_VERSION)
        self.assertTrue(row["recipient_key_id"])
        self.assertTrue(row["record_uid"])


class TestEnvelopeBinding(SealedDatabaseTest):
    """Everything identifying a record is authenticated with its ciphertext."""

    def setUp(self):
        super().setUp()
        self.add(plate="SECRET99", camera="CAM-1", offset_hours=1)
        self.add(plate="DECOY11", camera="CAM-9", offset_hours=2)
        self.rows = self.conn.execute("SELECT * FROM lpr_events ORDER BY id").fetchall()
        self.opener = sealing.RecordOpener(disclosure.load_private_key(self.path))

    def open_row(self, row, **overrides):
        envelope = dict(row)
        envelope.update(overrides)
        return self.opener.open(envelope, envelope["captured_at"],
                                envelope["camera_id"], envelope["plate_index"])

    def test_an_untouched_record_opens(self):
        self.assertEqual(self.open_row(self.rows[0])["plate"], "SECRET99")

    def test_transplanting_the_ciphertext_fails(self):
        with self.assertRaises(sealing.SealingError):
            self.open_row(self.rows[1], record_ct=self.rows[0]["record_ct"])

    def test_transplanting_the_wrapped_key_fails(self):
        with self.assertRaises(sealing.SealingError):
            self.open_row(self.rows[1], wrapped_key=self.rows[0]["wrapped_key"])

    def test_altering_the_record_uid_fails(self):
        with self.assertRaises(sealing.SealingError):
            self.open_row(self.rows[0], record_uid="0" * 32)

    def test_altering_the_timestamp_fails(self):
        row = dict(self.rows[0])
        row["captured_at"] = timeutil.to_canonical(self.now - timedelta(days=5))
        with self.assertRaises(sealing.SealingError):
            self.open_row(row)

    def test_altering_the_camera_fails(self):
        row = dict(self.rows[0])
        row["camera_id"] = "CAM-ELSEWHERE"
        with self.assertRaises(sealing.SealingError):
            self.open_row(row)

    def test_altering_the_blind_index_fails(self):
        row = dict(self.rows[0])
        row["plate_index"] = "f" * 64
        with self.assertRaises(sealing.SealingError):
            self.open_row(row)

    def test_a_record_sealed_to_another_key_is_refused_by_key_id(self):
        other_private, _ = sealing.generate_keypair()
        with self.assertRaises(sealing.SealingError) as ctx:
            sealing.RecordOpener(other_private).open(
                dict(self.rows[0]), self.rows[0]["captured_at"],
                self.rows[0]["camera_id"], self.rows[0]["plate_index"])
        self.assertIn("sealed to key", str(ctx.exception))

    def test_an_unknown_seal_version_is_refused(self):
        with self.assertRaises(sealing.SealingError):
            self.open_row(self.rows[0], seal_version="jk-seal-v99")


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
        self.add(offset_hours=24 * 30)
        auth_id = self.authorize(days=1)
        _, _, events = policy.evaluate_disclosure(
            self.conn, auth_id, "SECRET99", self.requester())
        self.assertEqual(len(events), 1)

    def test_another_vehicle_is_never_opened(self):
        self.add(plate="SECRET99")
        self.add(plate="OTHER11")
        auth_id = self.authorize("SECRET99")
        _, _, events = policy.evaluate_disclosure(
            self.conn, auth_id, "SECRET99", self.requester())
        self.assertEqual([e["plate"] for e in events], ["SECRET99"])

    def test_a_revoked_approver_key_stops_disclosure(self):
        self.add()
        auth_id = self.authorize()
        models.revoke_signing_key(self.conn, self.approver_id)
        allowed, reason, _ = policy.evaluate_disclosure(
            self.conn, auth_id, "SECRET99", self.requester())
        self.assertFalse(allowed)


class TestTheServiceDoesNotTrustItsCaller(SealedDatabaseTest):
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
            auth["approval_expires_at"], approver_key_id=sealing.key_id(approver["signing_pub"]))
        self.signature = auth["approval_signature"]
        self.all_rows = [dict(r) for r in
                         self.conn.execute("SELECT * FROM lpr_events").fetchall()]

    _KEEP = object()

    def disclose(self, rows=_KEEP, statement=_KEEP, signature=_KEEP, requester="officer1"):
        return self.service.disclose(
            self.all_rows if rows is self._KEEP else rows,
            self.statement if statement is self._KEEP else statement,
            self.signature if signature is self._KEEP else signature,
            requester)

    def resign(self, statement):
        key = approvals.unwrap_signing_key(
            models.get_user_by_id(self.conn, self.approver_id), "pw")
        return approvals.sign_statement(key, statement)

    def test_handing_it_every_row_still_opens_only_the_authorized_one(self):
        self.assertEqual([e["plate"] for e in self.disclose()], ["SECRET99"])

    def test_an_unsigned_request_is_refused(self):
        for missing in (None, "", "00" * 64):
            with self.assertRaises(disclosure.DisclosureError):
                self.disclose(signature=missing)

    def test_a_statement_widened_after_signing_is_refused(self):
        with self.assertRaises(disclosure.DisclosureError):
            self.disclose(statement=dict(self.statement, target_plate="OTHER11"))

    def test_a_window_widened_after_signing_is_refused(self):
        with self.assertRaises(disclosure.DisclosureError):
            self.disclose(statement=dict(self.statement,
                                         window_start=timeutil.parse("2000-01-01T00:00")))

    def test_another_requester_cannot_use_the_approval(self):
        with self.assertRaises(disclosure.DisclosureError):
            self.disclose(requester="officer2")

    def test_an_expired_approval_is_refused(self):
        expired = dict(self.statement,
                       approval_expires_at=timeutil.to_canonical(self.now - timedelta(minutes=1)))
        with self.assertRaises(disclosure.DisclosureError):
            self.disclose(statement=expired, signature=self.resign(expired))

    def test_a_self_approved_statement_is_refused(self):
        same = dict(self.statement, approver="officer1", requester="officer1")
        with self.assertRaises(disclosure.DisclosureError):
            self.disclose(statement=same, signature=self.resign(same))

    def test_an_unenrolled_approver_is_refused(self):
        """The service holds its own key registry; the caller cannot add to it."""
        rogue = dict(self.statement, approver="not-enrolled")
        with self.assertRaises(disclosure.DisclosureError) as ctx:
            self.disclose(statement=rogue, signature=self.resign(rogue))
        self.assertIn("not enrolled", str(ctx.exception))

    def test_a_caller_supplied_key_cannot_be_substituted(self):
        """A compromised application presenting its own approver key.

        The service looks the key up by username in its own registry, so the
        forged approval is checked against the real approver's key and fails.
        """
        forged_pub, wrapped, salt = approvals.generate_signing_key("attacker")
        rogue_key = approvals.unwrap_signing_key(
            {"signing_key_ct": wrapped, "signing_key_salt": salt,
             "signing_pub": forged_pub}, "attacker")
        statement = dict(self.statement, target_plate="OTHER11",
                         approver_key_id=sealing.key_id(forged_pub))
        signature = approvals.sign_statement(rogue_key, statement)
        with self.assertRaises(disclosure.DisclosureError):
            self.disclose(statement=statement, signature=signature)

    def test_a_statement_of_an_unknown_schema_is_refused(self):
        old = dict(self.statement, v=1)
        with self.assertRaises(disclosure.DisclosureError):
            self.disclose(statement=old, signature=self.resign(old))

    def test_a_statement_missing_required_fields_is_refused(self):
        for field in ("nonce", "approver_key_id", "window_end"):
            broken = dict(self.statement)
            broken[field] = None
            with self.assertRaises(disclosure.DisclosureError):
                self.disclose(statement=broken, signature=self.resign(broken))

    def test_a_revoked_approver_is_refused_by_the_service(self):
        models.revoke_signing_key(self.conn, self.approver_id)
        service = disclosure.service_for(self.conn, self.path)
        with self.assertRaises(disclosure.DisclosureError) as ctx:
            service.disclose(self.all_rows, self.statement, self.signature, "officer1")
        self.assertIn("revoked", str(ctx.exception))


class TestDisclosureServiceUnavailable(SealedDatabaseTest):
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

    def test_access_resumes_once_the_service_returns(self):
        self.add()
        auth_id = self.authorize()
        allowed, reason, events = policy.evaluate_disclosure(
            self.conn, auth_id, "SECRET99", self.requester())
        self.assertTrue(allowed, reason)
        self.assertEqual(len(events), 1)


@unittest.skipIf(SKIP, "sealing requires the cryptography package")
class TestSealingPrimitives(unittest.TestCase):
    ARGS = ("2026-08-31T12:00:00.000000+00:00", "CAM-1", "a" * 64)

    def seal(self, public_hex, fields=None):
        return sealing.RecordSealer(public_hex).seal(fields or {"plate": "ABC123"}, *self.ARGS)

    def test_seal_and_open_round_trip(self):
        private_hex, public_hex = sealing.generate_keypair()
        envelope = self.seal(public_hex)
        opened = sealing.RecordOpener(private_hex).open(envelope, *self.ARGS)
        self.assertEqual(opened, {"plate": "ABC123"})

    def test_a_different_private_key_cannot_open(self):
        _, public_hex = sealing.generate_keypair()
        other_private, _ = sealing.generate_keypair()
        with self.assertRaises(sealing.SealingError):
            sealing.RecordOpener(other_private).open(self.seal(public_hex), *self.ARGS)

    def test_each_seal_uses_a_fresh_record_key(self):
        _, public_hex = sealing.generate_keypair()
        a, b = self.seal(public_hex), self.seal(public_hex)
        self.assertNotEqual(a["record_ct"], b["record_ct"],
                            "identical plaintext must not seal identically")
        self.assertNotEqual(a["wrapped_key"], b["wrapped_key"])
        self.assertNotEqual(a["record_uid"], b["record_uid"])

    def test_the_key_id_is_stable_and_derived_from_the_public_key(self):
        private_hex, public_hex = sealing.generate_keypair()
        self.assertEqual(sealing.key_id(public_hex), sealing.key_id(public_hex))
        self.assertEqual(sealing.RecordOpener(private_hex).key_id, sealing.key_id(public_hex))

    def test_public_key_derivation_is_consistent(self):
        private_hex, public_hex = sealing.generate_keypair()
        self.assertEqual(sealing.public_from_private(private_hex), public_hex)

    def test_malformed_keys_are_rejected(self):
        with self.assertRaises(sealing.SealingError):
            sealing.RecordSealer("not-a-key")
        with self.assertRaises(sealing.SealingError):
            sealing.RecordOpener("not-a-key")


if __name__ == "__main__":
    unittest.main()


@unittest.skipIf(SKIP, "sealing requires the cryptography package")
class TestRemoteModeWithholdsTheIndexKey(unittest.TestCase):
    """The top finding in docs/threat-model.md.

    Plates are low-entropy, so an application holding the index key can
    enumerate them offline against the stored indexes and recover identities
    without decrypting anything. Removing the usage is not enough: the key
    must not be derivable from anything the application holds.
    """

    def setUp(self):
        from justikey import config
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "justikey.db")
        db.init_db(self.path)
        self._url = config.DISCLOSURE_URL
        config.DISCLOSURE_URL = "http://127.0.0.1:1"   # never contacted
        self.addCleanup(self._restore)

    def _restore(self):
        from justikey import config
        config.DISCLOSURE_URL = self._url
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_the_index_key_cannot_be_derived_in_remote_mode(self):
        with self.assertRaises(crypto_store.EncryptionError) as ctx:
            crypto_store.resolve_index_key(self.path)
        self.assertIn("disclosure service", str(ctx.exception))

    def test_a_local_deployment_still_derives_it(self):
        from justikey import config
        config.DISCLOSURE_URL = None
        self.assertEqual(len(crypto_store.resolve_index_key(self.path)),
                         crypto_store.KEY_BYTES)

    def test_remote_mode_requires_a_client_secret(self):
        from justikey import config
        original = config.DISCLOSURE_CLIENT_SECRET
        config.DISCLOSURE_CLIENT_SECRET = None
        try:
            conn = db.get_connection(self.path)
            with self.assertRaises(disclosure.DisclosureError):
                disclosure.service_for(conn, self.path)
            conn.close()
        finally:
            config.DISCLOSURE_CLIENT_SECRET = original


@unittest.skipIf(SKIP, "sealing requires the cryptography package")
class TestDisclosureLedgerUnderConcurrency(unittest.TestCase):
    """A ledger that forks under concurrent disclosures would undo the
    evidentiary property the service exists to provide."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "disclosure-audit.db")
        conn = db.get_connection(self.path)
        conn.executescript(
            "CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "seq INTEGER UNIQUE NOT NULL, timestamp TEXT NOT NULL, event_type TEXT NOT NULL,"
            "actor TEXT NOT NULL, details TEXT NOT NULL, prev_hash TEXT NOT NULL,"
            "hash TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
        conn.close()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_concurrent_disclosure_records_do_not_fork_the_chain(self):
        import threading
        from justikey import audit
        errors = []

        def worker(n):
            conn = db.get_connection(self.path)
            try:
                for i in range(5):
                    audit.append_event(conn, "disclosure_granted", f"requester:r{n}", {"i": i})
            except Exception as exc:  # noqa: BLE001
                errors.append(repr(exc))
            finally:
                conn.close()

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        conn = db.get_connection(self.path)
        try:
            count = conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"]
            ok, info, why = audit.verify_chain(conn)
        finally:
            conn.close()
        self.assertEqual(errors, [])
        self.assertEqual(count, 50)
        self.assertTrue(ok, why)
