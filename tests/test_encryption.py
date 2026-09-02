"""v1 encryption at rest: one symmetric key, held by the application.

Superseded as the default by per-record sealing (see test_sealing.py), but
still the mode an un-migrated database runs in, so it keeps its coverage.
These tests pin the mode explicitly rather than relying on the default.
"""
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from justikey import config, crypto_store, db, models  # noqa: E402


class V1ModeMixin:
    """Force legacy single-key encryption for this test's database."""

    def pin_v1(self):
        self._sealing_default = config.SEAL_RECORDS
        config.SEAL_RECORDS = False
        self.addCleanup(self._restore_sealing)

    def _restore_sealing(self):
        config.SEAL_RECORDS = self._sealing_default

SKIP = not crypto_store.CRYPTOGRAPHY_AVAILABLE
WINDOW = ("2026-01-01T00:00:00.000000+00:00", "2026-12-31T00:00:00.000000+00:00")


@unittest.skipIf(SKIP, "cryptography is not installed")
class EncryptedDatabaseTest(V1ModeMixin, unittest.TestCase):
    def setUp(self):
        self.pin_v1()
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "justikey.db")
        db.init_db(self.path)
        self.conn = db.get_connection(self.path)
        self.source = models.create_source(self.conn, "cam", "Cam")

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def add(self, plate="SECRET99", location="Elm Street Depot",
            captured="2026-08-31T12:00:00Z", camera="CAM-1"):
        return models.insert_event(self.conn, plate, captured, camera, 0.95, location,
                                   "claimed", source_ref=self.source)


class TestPlaintextIsAbsentFromDisk(EncryptedDatabaseTest):
    def test_a_v1_database_uses_single_key_encryption(self):
        self.assertEqual(crypto_store.encryption_mode(self.conn), crypto_store.MODE_V1)

    def test_plate_and_location_never_appear_in_the_file(self):
        """A stolen database or backup must not yield location history."""
        self.add()
        self.conn.close()
        with open(self.path, "rb") as fh:
            raw = fh.read()
        self.assertNotIn(b"SECRET99", raw)
        self.assertNotIn(b"Elm Street Depot", raw)
        self.conn = db.get_connection(self.path)

    def test_totp_secrets_are_not_stored_in_the_clear(self):
        models.create_user(self.conn, "officer1", "pw", "requester",
                           totp_secret="JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
        self.conn.close()
        with open(self.path, "rb") as fh:
            raw = fh.read()
        self.assertNotIn(b"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", raw)
        self.conn = db.get_connection(self.path)

    def test_totp_secret_round_trips_for_authentication(self):
        secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
        uid = models.create_user(self.conn, "officer1", "pw", "requester", totp_secret=secret)
        user = models.get_user_by_id(self.conn, uid)
        self.assertEqual(models.totp_secret_for(self.conn, user), secret)


class TestAuthorizedSearchStillWorks(EncryptedDatabaseTest):
    def test_exact_plate_lookup_returns_decrypted_values(self):
        self.add()
        found = models.search_events(self.conn, "SECRET99", *WINDOW)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["plate"], "SECRET99")
        self.assertEqual(found[0]["location"], "Elm Street Depot")

    def test_a_different_plate_matches_nothing(self):
        self.add()
        self.assertEqual(models.search_events(self.conn, "OTHER11", *WINDOW), [])

    def test_lookup_is_case_and_whitespace_insensitive(self):
        self.add(plate="ABC123")
        self.assertEqual(len(models.search_events(self.conn, "  abc123 ", *WINDOW)), 1)

    def test_time_window_still_bounds_results(self):
        self.add(captured="2026-08-31T12:00:00Z")
        self.add(captured="2027-06-01T12:00:00Z")
        self.assertEqual(len(models.search_events(self.conn, "SECRET99", *WINDOW)), 1)

    def test_null_location_survives_the_round_trip(self):
        self.add(location=None)
        self.assertIsNone(models.search_events(self.conn, "SECRET99", *WINDOW)[0]["location"])


class TestTamperResistance(EncryptedDatabaseTest):
    def test_ciphertext_cannot_be_moved_to_fabricate_a_sighting(self):
        """AAD binds a plate to its capture time and camera."""
        self.add(plate="SECRET99", captured="2026-08-31T12:00:00Z", camera="CAM-1")
        self.add(plate="DECOY11", captured="2026-08-31T20:00:00Z", camera="CAM-9")
        rows = self.conn.execute(
            "SELECT id, plate_ct, plate_index FROM lpr_events ORDER BY id").fetchall()
        self.conn.execute(
            "UPDATE lpr_events SET plate_ct=?, plate_index=? WHERE id=?",
            (rows[0]["plate_ct"], rows[0]["plate_index"], rows[1]["id"]))
        with self.assertRaises(crypto_store.WrongKeyError):
            models.search_events(self.conn, "SECRET99", *WINDOW)

    def test_altered_ciphertext_is_refused_not_guessed(self):
        self.add()
        row = self.conn.execute("SELECT id, plate_ct FROM lpr_events").fetchone()
        corrupted = ("A" if row["plate_ct"][0] != "A" else "B") + row["plate_ct"][1:]
        self.conn.execute("UPDATE lpr_events SET plate_ct=? WHERE id=?", (corrupted, row["id"]))
        with self.assertRaises(crypto_store.WrongKeyError):
            models.search_events(self.conn, "SECRET99", *WINDOW)


@unittest.skipIf(SKIP, "cryptography is not installed")
class TestKeyHandling(V1ModeMixin, unittest.TestCase):
    def setUp(self):
        self.pin_v1()
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "justikey.db")
        db.init_db(self.path)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_wrong_key_is_rejected_rather_than_returning_garbage(self):
        conn = db.get_connection(self.path)
        try:
            wrong = crypto_store.FieldCipher(b"\x09" * 32)
            with self.assertRaises(crypto_store.WrongKeyError):
                wrong.verify_canary(crypto_store.get_meta(conn, "key_check"))
        finally:
            conn.close()

    def test_subkeys_are_independent(self):
        """The index key must not be usable to decrypt, or vice versa."""
        root = b"\x05" * 32
        enc = crypto_store._hkdf(root, crypto_store._ENC_LABEL)
        idx = crypto_store._hkdf(root, crypto_store._IDX_LABEL)
        self.assertNotEqual(enc, idx)
        self.assertEqual(len(enc), 32)

    def test_key_file_is_created_private(self):
        key_path = crypto_store.key_file_for(self.path)
        self.assertTrue(os.path.exists(key_path))
        self.assertEqual(os.stat(key_path).st_mode & 0o777, 0o600)

    def test_env_supplied_key_takes_precedence_over_the_file(self):
        supplied = "ab" * 32
        self.assertEqual(crypto_store.load_root_key(None, key_hex=supplied),
                         bytes.fromhex(supplied))

    def test_malformed_env_key_is_rejected(self):
        for bad in ("not-hex", "ab" * 8):
            with self.assertRaises(crypto_store.EncryptionError):
                crypto_store.load_root_key(None, key_hex=bad)

    def test_blind_index_is_deterministic_but_key_dependent(self):
        a = crypto_store.FieldCipher(b"\x01" * 32)
        b = crypto_store.FieldCipher(b"\x02" * 32)
        self.assertEqual(a.blind_index("ABC123"), a.blind_index("ABC123"))
        self.assertNotEqual(a.blind_index("ABC123"), b.blind_index("ABC123"))
        self.assertNotEqual(a.blind_index("ABC123"), a.blind_index("ABC124"))


@unittest.skipIf(SKIP, "cryptography is not installed")
class TestPlaintextMigration(V1ModeMixin, unittest.TestCase):
    """A pre-encryption database must migrate deliberately, never silently."""

    def setUp(self):
        self.pin_v1()
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "legacy.db")
        os.environ["JUSTIKEY_ENCRYPT_AT_REST"] = "0"
        import importlib
        from justikey import config
        importlib.reload(config)
        db.init_db(self.path)
        conn = db.get_connection(self.path)
        src = models.create_source(conn, "cam", "Cam")
        models.insert_event(conn, "LEGACY01", "2026-08-31T12:00:00Z", "CAM-1", 0.9,
                            "Old Yard", "x", source_ref=src)
        conn.close()
        os.environ["JUSTIKEY_ENCRYPT_AT_REST"] = "1"
        importlib.reload(config)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_existing_plaintext_is_not_silently_switched_over(self):
        db.init_db(self.path)
        conn = db.get_connection(self.path)
        try:
            self.assertEqual(crypto_store.encryption_mode(conn), crypto_store.MODE_NONE,
                             "a half-encrypted store is worse than either state")
        finally:
            conn.close()

    def test_migration_script_encrypts_and_keeps_search_working(self):
        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", "encrypt_store.py"),
             "--db", self.path, "--apply"],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

        with open(self.path, "rb") as fh:
            raw = fh.read()
        self.assertNotIn(b"LEGACY01", raw)
        conn = db.get_connection(self.path)
        try:
            self.assertEqual(crypto_store.encryption_mode(conn), crypto_store.MODE_V1)
            found = models.search_events(conn, "LEGACY01", *WINDOW)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["location"], "Old Yard")
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
