"""Signed ingest: the secret never transits, and requests cannot be replayed."""
import os
import shutil
import sys
import tempfile
import unittest
from datetime import timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from justikey import crypto_store, db, models, timeutil  # noqa: E402

SKIP = not crypto_store.CRYPTOGRAPHY_AVAILABLE


@unittest.skipIf(SKIP, "signing sources require encryption at rest")
class SignedSourceTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "justikey.db")
        db.init_db(self.path)
        self.conn = db.get_connection(self.path)
        self.sid = models.create_source(self.conn, "gate", "Gate", auth_mode="hmac")
        self.secret = models.issue_source_credential(self.conn, self.sid)
        self.body = b'{"plate":"ABC123"}'

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def sign(self, body=None, timestamp=None, nonce="n1"):
        body = self.body if body is None else body
        timestamp = timestamp or timeutil.now_iso()
        return timestamp, nonce, models.compute_signature(self.secret, timestamp, nonce, body)

    def auth(self, body=None, timestamp=None, nonce="n1", signature=None, key_id="gate"):
        ts, nc, sig = self.sign(body, timestamp, nonce)
        return models.authenticate_signed_source(
            self.conn, key_id, timestamp or ts, nonce, signature or sig,
            self.body if body is None else body)


class TestSignatureVerification(SignedSourceTest):
    def test_a_correctly_signed_request_is_accepted(self):
        source, reason = self.auth()
        self.assertIsNotNone(source, reason)
        self.assertEqual(source["source_key"], "gate")

    def test_the_secret_is_never_stored_in_the_clear(self):
        self.conn.close()
        with open(self.path, "rb") as fh:
            raw = fh.read()
        self.assertNotIn(self.secret.encode(), raw)
        self.conn = db.get_connection(self.path)

    def test_a_tampered_body_invalidates_the_signature(self):
        ts, nonce, sig = self.sign()
        source, reason = models.authenticate_signed_source(
            self.conn, "gate", ts, nonce, sig, b'{"plate":"EVIL99"}')
        self.assertIsNone(source)
        self.assertIn("signature", reason)

    def test_a_wrong_secret_is_rejected(self):
        ts, nonce = timeutil.now_iso(), "n9"
        bad = models.compute_signature("not-the-secret", ts, nonce, self.body)
        source, reason = models.authenticate_signed_source(
            self.conn, "gate", ts, nonce, bad, self.body)
        self.assertIsNone(source)

    def test_missing_headers_are_rejected(self):
        source, reason = models.authenticate_signed_source(
            self.conn, "gate", None, None, None, self.body)
        self.assertIsNone(source)
        self.assertIn("missing", reason)


class TestReplayProtection(SignedSourceTest):
    def test_a_replayed_request_is_refused(self):
        self.assertIsNotNone(self.auth(nonce="same")[0])
        source, reason = self.auth(nonce="same")
        self.assertIsNone(source)
        self.assertIn("replay", reason)

    def test_a_fresh_nonce_still_works_after_a_replay_attempt(self):
        self.auth(nonce="a")
        self.auth(nonce="a")                       # replay, refused
        self.assertIsNotNone(self.auth(nonce="b")[0])

    def test_a_stale_timestamp_is_refused(self):
        stale = timeutil.to_canonical(
            timeutil.now() - timedelta(seconds=config_window() + 60))
        source, reason = self.auth(timestamp=stale, nonce="old")
        self.assertIsNone(source)
        self.assertIn("window", reason)

    def test_a_future_timestamp_is_refused(self):
        future = timeutil.to_canonical(
            timeutil.now() + timedelta(seconds=config_window() + 60))
        source, reason = self.auth(timestamp=future, nonce="future")
        self.assertIsNone(source)
        self.assertIn("window", reason)

    def test_a_failed_signature_does_not_burn_the_nonce(self):
        """Otherwise anyone could pre-spend a sender's nonces."""
        ts, nonce = timeutil.now_iso(), "contested"
        models.authenticate_signed_source(self.conn, "gate", ts, nonce, "0" * 64, self.body)
        source, reason = self.auth(timestamp=ts, nonce=nonce)
        self.assertIsNotNone(source, reason)

    def test_nonces_are_scoped_per_source(self):
        other = models.create_source(self.conn, "other", "Other", auth_mode="hmac")
        secret2 = models.issue_source_credential(self.conn, other)
        self.auth(nonce="shared")
        ts = timeutil.now_iso()
        sig = models.compute_signature(secret2, ts, "shared", self.body)
        source, reason = models.authenticate_signed_source(
            self.conn, "other", ts, "shared", sig, self.body)
        self.assertIsNotNone(source, reason)


class TestDowngradeResistance(SignedSourceTest):
    def test_a_signing_source_cannot_authenticate_as_bearer(self):
        self.assertIsNone(models.authenticate_source(self.conn, self.secret))

    def test_a_bearer_source_cannot_authenticate_as_signing(self):
        bid = models.create_source(self.conn, "plain", "Plain", auth_mode="bearer")
        secret = models.issue_source_credential(self.conn, bid)
        ts, nonce = timeutil.now_iso(), "n"
        sig = models.compute_signature(secret, ts, nonce, self.body)
        source, reason = models.authenticate_signed_source(
            self.conn, "plain", ts, nonce, sig, self.body)
        self.assertIsNone(source)
        self.assertIn("not configured for signed", reason)

    def test_a_revoked_signing_source_is_refused(self):
        models.revoke_source(self.conn, self.sid)
        self.assertIsNone(self.auth(nonce="after-revoke")[0])

    def test_rotation_overlaps_then_retires_the_old_secret(self):
        replacement = models.issue_source_credential(self.conn, self.sid, "new")
        self.assertIsNotNone(self.auth(nonce="old-key")[0])
        ts = timeutil.now_iso()
        sig = models.compute_signature(replacement, ts, "new-key", self.body)
        self.assertIsNotNone(models.authenticate_signed_source(
            self.conn, "gate", ts, "new-key", sig, self.body)[0])


def config_window():
    from justikey import config
    return config.INGEST_SIGNATURE_WINDOW_SECONDS


class TestNeedToKnow(unittest.TestCase):
    """An approver needs pending work and their own decisions -- not a
    browsable history of every plate the agency has investigated."""

    def setUp(self):
        self.conn = db.get_connection(":memory:")
        self.conn.executescript(db.SCHEMA)
        self.r1 = models.create_user(self.conn, "officer1", "pw", "requester")
        self.a1 = models.create_user(self.conn, "supervisor1", "pw", "approver")
        self.a2 = models.create_user(self.conn, "supervisor2", "pw", "approver")
        self.aud = models.create_user(self.conn, "auditor1", "pw", "auditor")
        window = ("2026-01-01T00:00:00.000000+00:00", "2026-02-01T00:00:00.000000+00:00")
        self.decided = models.create_authorization(
            self.conn, "C1", "W1", "p", "AAA111", *window, self.r1)
        models.approve_authorization(self.conn, self.decided, self.a1)
        self.other = models.create_authorization(
            self.conn, "C2", "W2", "p", "BBB222", *window, self.r1)
        models.approve_authorization(self.conn, self.other, self.a2)
        self.pending = models.create_authorization(
            self.conn, "C3", "W3", "p", "CCC333", *window, self.r1)

    def tearDown(self):
        self.conn.close()

    def plates_visible_to(self, user_id):
        user = models.get_user_by_id(self.conn, user_id)
        return {r["target_plate"] for r in models.list_authorizations(self.conn, user)}

    def test_an_approver_sees_pending_work_and_their_own_decisions(self):
        self.assertEqual(self.plates_visible_to(self.a1), {"AAA111", "CCC333"})

    def test_an_approver_does_not_see_another_approvers_closed_cases(self):
        self.assertNotIn("BBB222", self.plates_visible_to(self.a1))

    def test_the_auditor_still_sees_everything(self):
        self.assertEqual(self.plates_visible_to(self.aud), {"AAA111", "BBB222", "CCC333"})

    def test_a_requester_still_sees_only_their_own(self):
        self.assertEqual(self.plates_visible_to(self.r1), {"AAA111", "BBB222", "CCC333"})


if __name__ == "__main__":
    unittest.main()


class TestCapabilityProofOfConcept(unittest.TestCase):
    """The PoC makes a security claim, so it needs a check that it stays true."""

    def test_the_proof_of_concept_still_demonstrates_its_claims(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", "capability_poc.py")],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("plaintext recovered by the app itself : 0 of 4", result.stdout)
        self.assertIn("2 of 4 records released", result.stdout)
        self.assertNotIn("would be a flaw", result.stdout,
                         "an attack the capability model should refuse was allowed")
