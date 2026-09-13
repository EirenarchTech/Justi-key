"""v3 -> v4 reseal: re-wrapping an existing archive under a new suite.

Unlike the v1 -> v3 migration this destroys nothing. The old disclosure key
stays valid for anything not yet resealed, so the store is openable at every
point during the run and an interruption costs a retry rather than an
archive. That is why there is no destruction step and no confirmation phrase.

Rehearsed before these tests were written, against a 5,013-record store built
by the pre-v4 code at e975ddd: three live case files returned 3, 3 and 4
records before the reseal and the same 3, 3 and 4 afterwards; TOTP and sensor
secrets were untouched; new ingest sealed as v4; the old X25519 key opened
nothing. Two bugs surfaced doing it, both fixed and both covered below.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import helpers  # noqa: E402
from justikey import (approvals, config, crypto_store, db, disclosure, kem,  # noqa: E402
                      models, policy, sealing, timeutil)

SKIP = not sealing.SEALING_AVAILABLE
SCRIPT = os.path.join(ROOT, "scripts", "seal_store.py")


def seal_as_v3(public_hex, fields, captured_at, camera_id, blind_index):
    """A genuine jk-seal-v3 envelope, as the pre-v4 code wrote them.

    Written out rather than kept as a fixture file so the legacy format stays
    readable next to the code that has to keep opening it.
    """
    import json
    import os as _os
    import secrets

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    record_uid = secrets.token_hex(16)
    key_id = sealing.legacy_key_id(public_hex)
    aad = sealing.record_aad(key_id, record_uid, captured_at, camera_id, blind_index,
                             version=sealing.LEGACY_VERSION)

    record_key = AESGCM.generate_key(bit_length=256)
    nonce = _os.urandom(sealing.NONCE_BYTES)
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sealed = nonce + AESGCM(record_key).encrypt(nonce, payload, aad)

    suite = kem.suite(kem.X25519_ECDH)
    ephemeral_private, ephemeral_public = suite.generate()
    shared = suite.agree(ephemeral_private, bytes.fromhex(public_hex))
    wrap_key = sealing._wrap_key_from(shared)
    wrap_nonce = _os.urandom(sealing.NONCE_BYTES)
    wrapped = wrap_nonce + AESGCM(wrap_key).encrypt(wrap_nonce, record_key, aad)

    return {"record_uid": record_uid, "seal_version": sealing.LEGACY_VERSION,
            "seal_kem": None, "recipient_key_id": key_id,
            "record_ct": sealing._b64(sealed), "wrapped_key": sealing._b64(wrapped),
            "ephemeral_pub": sealing._b64(ephemeral_public)}


@unittest.skipIf(SKIP, "sealing requires the cryptography package")
class ResealTest(unittest.TestCase):
    """A v3 store with real case files, and a P-256 target key."""

    RECORDS = 40

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "justikey.db")

        self.old_kem = kem.X25519_ECDH
        self.old_private, self.old_public = sealing.generate_keypair(self.old_kem)
        with open(os.path.join(self.dir, "justikey.disclosure-key"), "w") as handle:
            handle.write(f"{self.old_kem}:{self.old_private}")
        self.target_private, self.target_public = sealing.generate_keypair(kem.P256_ECDH)

        self._saved = (config.DISCLOSURE_PRIVATE_KEY, config.DISCLOSURE_KEM,
                       config.DISCLOSURE_PUBLIC_KEY)
        self.addCleanup(self._restore)
        config.DISCLOSURE_PRIVATE_KEY = None
        config.DISCLOSURE_PUBLIC_KEY = None
        config.DISCLOSURE_KEM = None

        self._build_v3_store()

    def _restore(self):
        (config.DISCLOSURE_PRIVATE_KEY, config.DISCLOSURE_KEM,
         config.DISCLOSURE_PUBLIC_KEY) = self._saved

    def _build_v3_store(self):
        db.init_db(self.path)
        conn = db.get_connection(self.path)
        try:
            crypto_store.set_meta(conn, "disclosure_public_key", self.old_public)
            crypto_store.set_meta(conn, "disclosure_kem", self.old_kem)
            source = models.create_source(conn, "cam", "Cam")
            self.requester_id = models.create_user(conn, "officer1", "pw", "requester")
            self.approver_id = models.create_user(conn, "supervisor1", "pw", "approver")
            public, wrapped, salt = approvals.generate_signing_key("pw")
            models.set_signing_key(conn, self.requester_id, public, wrapped, salt)

            self.now = timeutil.now()
            cipher = models.cipher_for(conn)
            self.target_plate = "CASE001"
            for index in range(self.RECORDS):
                plate = self.target_plate if index % 8 == 0 else f"BULK{index:03d}"
                captured = timeutil.to_canonical(self.now - timedelta(hours=index + 1))
                blind = cipher.blind_index(plate)
                envelope = seal_as_v3(self.old_public,
                                      {"plate": plate, "location": f"Junction {index}"},
                                      captured, "CAM-1", blind)
                conn.execute(
                    "INSERT INTO lpr_events (plate, captured_at, camera_id, confidence, "
                    "location, source_id, source_ref, plate_index, record_ct, wrapped_key, "
                    "ephemeral_pub, record_uid, seal_version, seal_kem, recipient_key_id, "
                    "ingested_at) VALUES ('',?,?,?,NULL,'claimed',?,?,?,?,?,?,?,?,?,?)",
                    (captured, "CAM-1", 0.95, source, blind, envelope["record_ct"],
                     envelope["wrapped_key"], envelope["ephemeral_pub"],
                     envelope["record_uid"], envelope["seal_version"],
                     envelope["seal_kem"], envelope["recipient_key_id"],
                     timeutil.now_iso()))

            self.auth_id = models.create_authorization(
                conn, "CASE-1", "Warrant 1", "Investigation", self.target_plate,
                timeutil.to_canonical(self.now - timedelta(days=10)),
                timeutil.to_canonical(self.now), self.requester_id)
            helpers.approve_signed(conn, self.auth_id, self.approver_id)
        finally:
            conn.close()

    # -- helpers ----------------------------------------------------------

    def reseal(self, *extra):
        return subprocess.run(
            [sys.executable, SCRIPT, "reseal-v4", "--db", self.path,
             "--target-public-key", self.target_public, *extra],
            capture_output=True, text=True, timeout=120)

    def disclose(self, private_material=None):
        config.DISCLOSURE_PRIVATE_KEY = private_material
        conn = db.get_connection(self.path)
        try:
            requester = models.get_user_by_id(conn, self.requester_id)
            key = approvals.unwrap_signing_key(requester, "pw")
            return policy.evaluate_disclosure(
                conn, self.auth_id, self.target_plate, requester, presence_key=key)
        finally:
            conn.close()

    def envelope_summary(self):
        conn = db.get_connection(self.path)
        try:
            return {(row["seal_version"], row["seal_kem"]): row["n"] for row in
                    conn.execute("SELECT seal_version, seal_kem, COUNT(*) n "
                                 "FROM lpr_events GROUP BY 1, 2")}
        finally:
            conn.close()


class TestTheReseal(ResealTest):
    def test_the_store_starts_as_genuine_v3(self):
        self.assertEqual(self.envelope_summary(),
                         {(sealing.LEGACY_VERSION, None): self.RECORDS})

    def test_the_same_records_disclose_before_and_after(self):
        """The check that matters. Everything else can be right while this is
        wrong, and a store that migrates cleanly and discloses nothing is the
        failure the v1 ceremony was built to catch."""
        before = self.disclose(f"{self.old_kem}:{self.old_private}")
        self.assertTrue(before[0], before[1])
        self.assertEqual(len(before[2]), 5)

        result = self.reseal("--apply")
        self.assertEqual(result.returncode, 0, result.stderr)

        after = self.disclose(f"{kem.P256_ECDH}:{self.target_private}")
        self.assertTrue(after[0], after[1])
        self.assertEqual([event["plate"] for event in after[2]],
                         [event["plate"] for event in before[2]])
        self.assertEqual([event["location"] for event in after[2]],
                         [event["location"] for event in before[2]])

    def test_every_record_moves_to_v4(self):
        self.assertEqual(self.reseal("--apply").returncode, 0)
        self.assertEqual(self.envelope_summary(),
                         {(sealing.FORMAT_VERSION, kem.P256_ECDH): self.RECORDS})

    def test_a_dry_run_changes_nothing(self):
        result = self.reseal()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Dry run", result.stdout)
        self.assertEqual(self.envelope_summary(),
                         {(sealing.LEGACY_VERSION, None): self.RECORDS})

    def test_the_old_key_opens_nothing_afterwards(self):
        self.reseal("--apply")
        conn = db.get_connection(self.path)
        try:
            row = dict(conn.execute("SELECT * FROM lpr_events LIMIT 1").fetchone())
        finally:
            conn.close()
        opener = sealing.RecordOpener(self.old_private, self.old_kem)
        with self.assertRaises(sealing.SealingError):
            opener.open(row, row["captured_at"], row["camera_id"], row["plate_index"])

    def test_resealing_twice_is_a_no_op(self):
        self.assertEqual(self.reseal("--apply").returncode, 0)
        again = self.reseal("--apply")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("To reseal: 0 record(s)", again.stdout)

    def test_the_target_key_may_not_be_the_current_one(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "reseal-v4", "--db", self.path,
             "--target-public-key", self.old_public, "--target-kem", self.old_kem,
             "--apply"], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 1)
        self.assertIn("already use", result.stderr)

    def test_a_target_key_is_required(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "reseal-v4", "--db", self.path],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 1)
        self.assertIn("--target-public-key is required", result.stderr)

    def test_the_manifest_records_the_move(self):
        self.reseal("--apply")
        import json

        with open(os.path.join(self.dir, "justikey.ceremony.json")) as handle:
            manifest = json.load(handle)
        stage = [s for s in manifest["stages"] if s["stage"] == "reseal-v4"][0]
        self.assertEqual(stage["from_kem"], kem.X25519_ECDH)
        self.assertEqual(stage["to_kem"], kem.P256_ECDH)
        self.assertEqual(stage["resealed"], self.RECORDS)

    def test_credentials_are_untouched(self):
        """A reseal moves observations. TOTP secrets were never under the
        disclosure key and must not be disturbed by pretending otherwise."""
        self.reseal("--apply")
        conn = db.get_connection(self.path)
        try:
            officer = models.get_user_by_username(conn, "officer1")
            self.assertTrue(models.totp_secret_for(conn, officer))
        finally:
            conn.close()


class TestWhatTheRehearsalFound(ResealTest):
    """Two bugs the 5,013-record rehearsal surfaced before any test existed."""

    def test_the_ceremony_migrates_the_schema_it_needs(self):
        """A v3 store has no seal_kem column, because there was only one
        suite. The ceremony used to fail with a raw SQLite error."""
        conn = db.get_connection(self.path)
        try:
            conn.execute("ALTER TABLE lpr_events DROP COLUMN seal_kem")
            columns = {row["name"] for row in
                       conn.execute("PRAGMA table_info(lpr_events)")}
            self.assertNotIn("seal_kem", columns)
        finally:
            conn.close()

        result = self.reseal("--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.envelope_summary(),
                         {(sealing.FORMAT_VERSION, kem.P256_ECDH): self.RECORDS})

    def test_configuration_chooses_a_fresh_store_suite_but_never_reinterprets_one(self):
        """JUSTIKEY_DISCLOSURE_KEM was honoured when reading a store's suite
        and ignored when creating its key, so a store configured as X25519 got
        a P-256 key and then read itself as X25519."""
        fresh = os.path.join(self.dir, "fresh.db")
        config.DISCLOSURE_KEM = kem.X25519_ECDH
        db.init_db(fresh)
        conn = db.get_connection(fresh)
        try:
            public_hex = disclosure.public_key_for(conn, fresh, create=True)
            self.assertEqual(len(bytes.fromhex(public_hex)), 32)  # X25519, not P-256
            self.assertEqual(disclosure.disclosure_kem(conn), kem.X25519_ECDH)
        finally:
            conn.close()

        # And an environment variable cannot reinterpret a store already sealed.
        config.DISCLOSURE_KEM = kem.P256_ECDH
        conn = db.get_connection(fresh)
        try:
            self.assertEqual(disclosure.disclosure_kem(conn), kem.X25519_ECDH)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
