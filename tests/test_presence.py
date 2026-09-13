"""Requester proof-of-presence at disclosure (stage 4, threat-model finding 5).

The question every test here asks is the one the threat model asks: with the
application fully compromised -- holding the database, and so holding every
approval row -- can it spend an approval in an officer's name while that
officer is nowhere near a keyboard?
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
from justikey import (approvals, config, custody, db, disclosure, models,  # noqa: E402
                      policy, presence, sealing, timeutil, webauthn)

SKIP = not sealing.SEALING_AVAILABLE
if not SKIP:
    from authenticator import Authenticator  # noqa: E402

RP_ID = "justikey.example"
ORIGIN = "https://justikey.example"


@unittest.skipIf(SKIP, "sealing requires the cryptography package")
class PresenceTest(unittest.TestCase):
    def setUp(self):
        self._saved = (config.PRESENCE_MODE, config.WEBAUTHN_RP_ID, config.WEBAUTHN_ORIGIN)
        config.WEBAUTHN_RP_ID, config.WEBAUTHN_ORIGIN = RP_ID, ORIGIN
        self.addCleanup(self._restore)

        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "justikey.db")
        db.init_db(self.path)
        self.conn = db.get_connection(self.path)
        self.addCleanup(self.conn.close)
        self.addCleanup(shutil.rmtree, self.dir, True)

        self.source = models.create_source(self.conn, "cam", "Cam")
        self.requester_id = models.create_user(self.conn, "officer1", "pw", "requester")
        self.approver_id = models.create_user(self.conn, "supervisor1", "pw", "approver")
        self.now = timeutil.now()
        models.insert_event(
            self.conn, "SECRET99", timeutil.to_canonical(self.now - timedelta(hours=1)),
            "CAM-1", 0.95, "Elm Street Depot", "claimed", source_ref=self.source)
        self.auth_id = self.authorize()

    def _restore(self):
        (config.PRESENCE_MODE, config.WEBAUTHN_RP_ID,
         config.WEBAUTHN_ORIGIN) = self._saved

    def authorize(self, plate="SECRET99"):
        auth_id = models.create_authorization(
            self.conn, "CASE-1", "Warrant 1", "Investigation", plate,
            timeutil.to_canonical(self.now - timedelta(days=1)),
            timeutil.to_canonical(self.now + timedelta(days=1)), self.requester_id)
        helpers.approve_signed(self.conn, auth_id, self.approver_id)
        return auth_id

    def enrol_software(self, password="pw"):
        public, wrapped, salt = approvals.generate_signing_key(password)
        models.set_signing_key(self.conn, self.requester_id, public, wrapped, salt)
        return self.requester()

    def enrol_hardware(self):
        self.enrol_software()
        token = Authenticator(rp_id=RP_ID, origin=ORIGIN)
        models.enrol_webauthn_credential(
            self.conn, self.requester_id, token.credential_id, token.public_key,
            "test key", rp_id=RP_ID, origin=ORIGIN)
        return token

    def requester(self):
        return models.get_user_by_id(self.conn, self.requester_id)

    def statement_for(self, auth_id=None):
        auth = models.get_authorization(self.conn, auth_id or self.auth_id)
        approver = models.get_user_by_id(self.conn, self.approver_id)
        return approvals.build_statement(
            auth, "officer1", "supervisor1", auth["approved_at"],
            auth["approval_expires_at"],
            approver_key_id=approvals.signing_key_id(approver["signing_pub"])), auth["approval_signature"]

    def rows_for(self, statement):
        return [dict(r) for r in models.search_events(
            self.conn, statement["target_plate"],
            statement["window_start"], statement["window_end"])]

    def service(self):
        return disclosure.service_for(self.conn, self.path)

    def software_proof(self, statement, password="pw"):
        """What an officer who is actually present produces."""
        credential = models.presence_credential(self.conn, self.requester())
        proof_statement = presence.build(statement, custody.credential_key_id(credential))
        key = approvals.unwrap_signing_key(self.requester(), password)
        return proof_statement, presence.sign(key, proof_statement)

    def hardware_proof(self, token, statement):
        credential = models.presence_credential(self.conn, self.requester())
        proof_statement = presence.build(statement, custody.credential_key_id(credential))
        return proof_statement, custody.webauthn_proof(token.assert_challenge(
            webauthn.challenge_for(presence.canonical(proof_statement))))


class TestTheBearerHole(PresenceTest):
    """Finding 5, before and after."""

    def test_without_an_enrolled_key_an_approval_is_a_bearer_token(self):
        """The state the threat model described. Recorded so the improvement
        is measured against something real rather than asserted."""
        statement, signature = self.statement_for()
        opened = self.service().disclose(
            self.rows_for(statement), statement, signature, "officer1")
        self.assertEqual([o["plate"] for o in opened], ["SECRET99"])

    def test_with_a_key_enrolled_a_stored_approval_is_not_enough(self):
        self.enrol_software()
        statement, signature = self.statement_for()
        with self.assertRaises(disclosure.DisclosureError) as caught:
            self.service().disclose(self.rows_for(statement), statement, signature, "officer1")
        self.assertIn("present", str(caught.exception))

    def test_a_present_requester_can_still_work(self):
        self.enrol_software()
        statement, signature = self.statement_for()
        proof_statement, proof = self.software_proof(statement)
        service = self.service()
        opened = service.disclose(self.rows_for(statement), statement, signature,
                                  "officer1", proof_statement, proof)
        self.assertEqual([o["plate"] for o in opened], ["SECRET99"])
        self.assertEqual(service.last_presence["custody"], "software")


class TestProofBinding(PresenceTest):
    def setUp(self):
        super().setUp()
        self.enrol_software()

    def spend(self, statement, signature, proof_statement, proof, requester="officer1"):
        return self.service().disclose(
            self.rows_for(statement), statement, signature, requester,
            proof_statement, proof)

    def test_a_proof_is_spent_once(self):
        statement, signature = self.statement_for()
        proof_statement, proof = self.software_proof(statement)
        self.spend(statement, signature, proof_statement, proof)
        with self.assertRaises(disclosure.DisclosureError) as caught:
            self.spend(statement, signature, proof_statement, proof)
        self.assertIn("already been used", str(caught.exception))

    def test_a_proof_does_not_transfer_to_another_approval(self):
        first, _ = self.statement_for()
        second, second_signature = self.statement_for(self.authorize())
        proof_statement, proof = self.software_proof(first)
        with self.assertRaises(disclosure.DisclosureError) as caught:
            self.spend(second, second_signature, proof_statement, proof)
        self.assertIn("different approval", str(caught.exception))

    def test_a_proof_does_not_survive_the_scope_being_edited(self):
        """The approver signed a scope; the proof covers that scope's digest."""
        statement, signature = self.statement_for()
        proof_statement, proof = self.software_proof(statement)
        widened = dict(statement, window_end=timeutil.to_canonical(
            self.now + timedelta(days=400)))
        with self.assertRaises(disclosure.DisclosureError):
            self.spend(widened, signature, proof_statement, proof)

    def test_an_expired_proof_is_refused(self):
        statement, signature = self.statement_for()
        credential = models.presence_credential(self.conn, self.requester())
        stale = presence.build(
            statement, custody.credential_key_id(credential), ttl_seconds=60,
            issued_at=timeutil.to_canonical(self.now - timedelta(hours=2)))
        key = approvals.unwrap_signing_key(self.requester(), "pw")
        with self.assertRaises(disclosure.DisclosureError) as caught:
            self.spend(statement, signature, stale, presence.sign(key, stale))
        self.assertIn("expired", str(caught.exception))

    def test_a_proof_cannot_grant_itself_a_long_life(self):
        """Otherwise a compromised application issues one good for a year."""
        statement, signature = self.statement_for()
        credential = models.presence_credential(self.conn, self.requester())
        forever = presence.build(statement, custody.credential_key_id(credential),
                                 ttl_seconds=86400 * 365)
        key = approvals.unwrap_signing_key(self.requester(), "pw")
        with self.assertRaises(disclosure.DisclosureError) as caught:
            self.spend(statement, signature, forever, presence.sign(key, forever))
        self.assertIn("lifetime", str(caught.exception))

    def test_a_proof_signed_by_someone_else_is_refused(self):
        """The proof names the officer's enrolled key; only that key can make it."""
        statement, signature = self.statement_for()
        proof_statement, _ = self.software_proof(statement)
        public, wrapped, salt = approvals.generate_signing_key("other")
        impostor = approvals.unwrap_signing_key(
            {"signing_pub": public, "signing_key_ct": wrapped,
             "signing_key_salt": salt}, "other")
        with self.assertRaises(disclosure.DisclosureError) as caught:
            self.spend(statement, signature, proof_statement,
                       presence.sign(impostor, proof_statement))
        self.assertIn("does not cover this statement", str(caught.exception))

    def test_a_refused_proof_does_not_consume_a_disclosure(self):
        """Otherwise an attacker exhausts an officer's budget by failing."""
        statement, signature = self.statement_for()
        proof_statement, proof = self.software_proof(statement)
        self.spend(statement, signature, proof_statement, proof)

        for _ in range(5):
            with self.assertRaises(disclosure.DisclosureError):
                self.service().disclose(self.rows_for(statement), statement, signature,
                                        "officer1")
        auth = models.get_authorization(self.conn, self.auth_id)
        fresh_statement, fresh_signature = self.statement_for()
        proof_statement, proof = self.software_proof(fresh_statement)
        service = self.service()
        service.disclose(self.rows_for(fresh_statement), fresh_statement, fresh_signature,
                         "officer1", proof_statement, proof)
        self.assertEqual(service.last_use_count, 2)      # not 7


class TestConcurrentSpend(PresenceTest):
    """Two requests racing must not both get through.

    One service object shared across threads, exactly as the server holds it;
    UsageStore opens its own connection per claim, which is the part that has
    to be thread-safe.
    """

    def setUp(self):
        super().setUp()
        self.enrol_software()
        self.statement, self.signature = self.statement_for()
        self.rows = self.rows_for(self.statement)
        self.service = disclosure.service_for(self.conn, self.path)

    def race(self, proofs):
        """`proofs` is built on this thread: the test's own connection is not
        shared with the workers, only the service object is."""
        import threading
        threads = len(proofs)
        succeeded, unexpected = [], []
        barrier, lock = threading.Barrier(threads), threading.Lock()

        def attempt(index):
            proof_statement, proof = proofs[index]
            barrier.wait()
            try:
                self.service.disclose(self.rows, self.statement, self.signature,
                                      "officer1", proof_statement, proof)
            except disclosure.DisclosureError:
                return
            except Exception as exc:                       # noqa: BLE001
                with lock:
                    unexpected.append(f"{type(exc).__name__}: {exc}")
                return
            with lock:
                succeeded.append(index)

        workers = [threading.Thread(target=attempt, args=(i,)) for i in range(threads)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        self.assertEqual(unexpected, [])
        return succeeded

    def fresh_proofs(self, count):
        return [self.software_proof(self.statement) for _ in range(count)]

    def test_one_proof_of_presence_survives_exactly_one_of_sixteen_requests(self):
        """The uniqueness constraint on presence_nonces.nonce is the backstop."""
        one = self.software_proof(self.statement)
        self.assertEqual(len(self.race([one] * 16)), 1)

    def test_concurrent_requests_cannot_exceed_the_remaining_budget(self):
        self.service.max_disclosures = 4
        self.assertEqual(len(self.race(self.fresh_proofs(16))), 4)

    def test_a_request_refused_by_the_cap_does_not_burn_a_confirmation(self):
        """Both spends commit together or not at all: being refused by the cap
        must not also cost the requester their confirmation."""
        self.service.max_disclosures = 2
        self.race(self.fresh_proofs(8))
        spent = self.conn.execute(
            "SELECT COUNT(*) c FROM presence_nonces").fetchone()["c"]
        self.assertEqual(spent, 2)

    def test_a_failed_presence_spend_does_not_advance_the_disclosure_count(self):
        proof_statement, proof = self.software_proof(self.statement)
        self.service.disclose(self.rows, self.statement, self.signature,
                              "officer1", proof_statement, proof)
        first = self.service.last_use_count
        for _ in range(3):
            with self.assertRaises(disclosure.DisclosureError):
                self.service.disclose(self.rows, self.statement, self.signature,
                                      "officer1", proof_statement, proof)
        again_statement, again_proof = self.software_proof(self.statement)
        self.service.disclose(self.rows, self.statement, self.signature,
                              "officer1", again_statement, again_proof)
        self.assertEqual(self.service.last_use_count, first + 1)


class TestHardwareCustody(PresenceTest):
    def test_a_touched_security_key_opens_records(self):
        token = self.enrol_hardware()
        statement, signature = self.statement_for()
        proof_statement, proof = self.hardware_proof(token, statement)
        service = self.service()
        opened = service.disclose(self.rows_for(statement), statement, signature,
                                  "officer1", proof_statement, proof)
        self.assertEqual([o["plate"] for o in opened], ["SECRET99"])
        self.assertEqual(service.last_presence["custody"], "hardware")

    def test_knowing_the_password_is_no_longer_enough(self):
        """The whole point of enrolling hardware. A compromised application
        that captured the officer's password still cannot disclose."""
        self.enrol_hardware()
        statement, signature = self.statement_for()
        credential = models.presence_credential(self.conn, self.requester())
        proof_statement = presence.build(statement, custody.credential_key_id(credential))
        key = approvals.unwrap_signing_key(self.requester(), "pw")
        with self.assertRaises(disclosure.DisclosureError) as caught:
            self.service().disclose(
                self.rows_for(statement), statement, signature, "officer1",
                proof_statement, presence.sign(key, proof_statement))
        self.assertIn("hardware authenticator", str(caught.exception))

    def test_a_captured_assertion_cannot_be_replayed(self):
        token = self.enrol_hardware()
        statement, signature = self.statement_for()
        proof_statement, proof = self.hardware_proof(token, statement)
        self.service().disclose(self.rows_for(statement), statement, signature,
                                "officer1", proof_statement, proof)
        with self.assertRaises(disclosure.DisclosureError):
            self.service().disclose(self.rows_for(statement), statement, signature,
                                    "officer1", proof_statement, proof)

    def test_an_assertion_for_another_origin_is_refused(self):
        token = self.enrol_hardware()
        statement, signature = self.statement_for()
        credential = models.presence_credential(self.conn, self.requester())
        proof_statement = presence.build(statement, custody.credential_key_id(credential))
        proof = custody.webauthn_proof(token.assert_challenge(
            webauthn.challenge_for(presence.canonical(proof_statement)),
            origin="https://phishing.example"))
        with self.assertRaises(disclosure.DisclosureError) as caught:
            self.service().disclose(self.rows_for(statement), statement, signature,
                                    "officer1", proof_statement, proof)
        self.assertIn("origin", str(caught.exception))


class TestPresenceModes(PresenceTest):
    def test_enrolled_mode_does_not_lock_out_the_unenrolled(self):
        """Migration posture: a deployment can enrol people gradually."""
        config.PRESENCE_MODE = "enrolled"
        statement, signature = self.statement_for()
        service = disclosure.DisclosureService(
            sealing.RecordOpener(disclosure.load_private_key(self.path)),
            b"idx", disclosure.local_approver_registry(self.conn),
            requester_registry=disclosure.local_requester_registry(self.conn),
            presence_mode="enrolled")
        self.assertIsNone(service.verify_presence(statement, "officer1", None, None))

    def test_required_mode_refuses_an_unenrolled_requester(self):
        statement, _ = self.statement_for()
        service = disclosure.DisclosureService(
            sealing.RecordOpener(disclosure.load_private_key(self.path)),
            b"idx", {}, requester_registry={}, presence_mode="required")
        with self.assertRaises(disclosure.DisclosureError) as caught:
            service.verify_presence(statement, "officer1", None, None)
        self.assertIn("no signing key enrolled", str(caught.exception))

    def test_off_mode_asks_for_nothing(self):
        self.enrol_software()
        statement, signature = self.statement_for()
        service = self.service()
        service.presence_mode = "off"
        opened = service.disclose(self.rows_for(statement), statement, signature, "officer1")
        self.assertEqual(len(opened), 1)


class TestThroughThePolicyEngine(PresenceTest):
    """The path the web application actually takes."""

    def test_policy_denies_without_a_proof_and_names_the_reason(self):
        self.enrol_software()
        allowed, reason, events = policy.evaluate_disclosure(
            self.conn, self.auth_id, "SECRET99", self.requester())
        self.assertFalse(allowed)
        self.assertEqual(reason, "presence_required")
        self.assertEqual(events, [])
        self.assertIn("present", policy.DENIAL_MESSAGES[reason])

    def test_policy_allows_with_the_requesters_key(self):
        self.enrol_software()
        key = approvals.unwrap_signing_key(self.requester(), "pw")
        allowed, reason, events = policy.evaluate_disclosure(
            self.conn, self.auth_id, "SECRET99", self.requester(), presence_key=key)
        self.assertTrue(allowed, reason)
        self.assertEqual([e["plate"] for e in events], ["SECRET99"])
        self.assertEqual(policy.last_presence_custody(), "software")

    def test_policy_records_hardware_custody_distinctly(self):
        token = self.enrol_hardware()

        def sign_with_the_token(proof_statement):
            return custody.webauthn_proof(token.assert_challenge(
                webauthn.challenge_for(presence.canonical(proof_statement))))

        allowed, reason, events = policy.evaluate_disclosure(
            self.conn, self.auth_id, "SECRET99", self.requester(),
            presence_proof=sign_with_the_token)
        self.assertTrue(allowed, reason)
        self.assertEqual(policy.last_presence_custody(), "hardware")

    def test_an_unenrolled_requester_is_unaffected_in_enrolled_mode(self):
        allowed, reason, events = policy.evaluate_disclosure(
            self.conn, self.auth_id, "SECRET99", self.requester())
        self.assertTrue(allowed, reason)
        self.assertEqual(policy.last_presence_custody(), "none")


if __name__ == "__main__":
    unittest.main()
