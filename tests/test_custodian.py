"""Stage 5 attack suite: key isolation.

Objective: compromise of the disclosure-service process must not reveal a
reusable archive-decryption secret **or provide an unrestricted cryptographic
oracle.**

The second clause is the one these tests are mostly about. A non-exportable
key in a KMS satisfies the first on its own; it does nothing about a
compromised service that calls DeriveSharedSecret once per row and walks the
table. So the operation the custodian offers is `open(record, identity,
approval, presence, registry_versions)` and never `derive(ephemeral_pub)`,
and it re-verifies every fact for itself before agreeing to anything.

Where AWS is involved, tests/fake_kms.py enforces the documented policy
semantics -- attested calls get CiphertextForRecipient and an empty
SharedSecret, and kms:RecipientAttestation:ImageSha384 refuses a mismatched
or absent attestation. These tests prove JustiKey behaves correctly given
that behaviour; they are not evidence about AWS itself.
"""
import hashlib
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
from justikey import (approvals, custodian, custody, db, disclosure, kem,  # noqa: E402
                      models, presence, sealing, timeutil)

SKIP = not sealing.SEALING_AVAILABLE
if not SKIP:
    from fake_kms import AccessDeniedException, FakeKms, image_sha384  # noqa: E402

PLATE = "SECRET99"
LOCATION = "Elm Street Depot"
IMAGE = "sha384-of-the-approved-custodian-enclave"


@unittest.skipIf(SKIP, "stage 5 requires the cryptography package")
class CustodianTest(unittest.TestCase):
    """A v4 store, a real approval, a real proof of presence, and a KMS."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "justikey.db")

        self.image = image_sha384(IMAGE)
        self.kms = FakeKms(allowed_image_sha384=self.image)
        self.public_hex = self.kms.public_raw.hex()

        os.environ["JUSTIKEY_DISCLOSURE_PUBLIC_KEY"] = self.public_hex
        os.environ["JUSTIKEY_DISCLOSURE_KEM"] = kem.P256_ECDH
        self.addCleanup(os.environ.pop, "JUSTIKEY_DISCLOSURE_PUBLIC_KEY", None)
        self.addCleanup(os.environ.pop, "JUSTIKEY_DISCLOSURE_KEM", None)
        from justikey import config
        self._saved = (config.DISCLOSURE_PUBLIC_KEY, config.DISCLOSURE_KEM)
        config.DISCLOSURE_PUBLIC_KEY, config.DISCLOSURE_KEM = self.public_hex, kem.P256_ECDH
        self.addCleanup(self._restore_config)

        db.init_db(self.path)
        self.conn = db.get_connection(self.path)
        self.addCleanup(self.conn.close)
        self.source = models.create_source(self.conn, "cam", "Cam")
        self.requester_id = models.create_user(self.conn, "officer1", "pw", "requester")
        self.approver_id = models.create_user(self.conn, "supervisor1", "pw", "approver")
        public, wrapped, salt = approvals.generate_signing_key("pw")
        models.set_signing_key(self.conn, self.requester_id, public, wrapped, salt)

        self.now = timeutil.now()
        self.record_id = models.insert_event(
            self.conn, PLATE, timeutil.to_canonical(self.now - timedelta(hours=1)),
            "CAM-1", 0.95, LOCATION, "claimed", source_ref=self.source)
        self.auth_id = self.authorize()

    def _restore_config(self):
        from justikey import config
        config.DISCLOSURE_PUBLIC_KEY, config.DISCLOSURE_KEM = self._saved

    # -- fixtures ---------------------------------------------------------

    def authorize(self, plate=PLATE):
        auth_id = models.create_authorization(
            self.conn, "CASE-1", "Warrant 1", "Investigation", plate,
            timeutil.to_canonical(self.now - timedelta(days=1)),
            timeutil.to_canonical(self.now + timedelta(days=1)), self.requester_id)
        helpers.approve_signed(self.conn, auth_id, self.approver_id)
        return auth_id

    def requester(self):
        return models.get_user_by_id(self.conn, self.requester_id)

    def statement_for(self, auth_id=None):
        auth = models.get_authorization(self.conn, auth_id or self.auth_id)
        approver = models.get_user_by_id(self.conn, self.approver_id)
        return approvals.build_statement(
            auth, "officer1", "supervisor1", auth["approved_at"],
            auth["approval_expires_at"],
            approver_key_id=approvals.signing_key_id(approver["signing_pub"])), \
            auth["approval_signature"]

    def envelope(self, record_id=None):
        row = self.conn.execute("SELECT * FROM lpr_events WHERE id=?",
                                (record_id or self.record_id,)).fetchone()
        return dict(row)

    def identity(self, envelope=None):
        envelope = envelope or self.envelope()
        return {k: envelope[k] for k in
                ("record_uid", "captured_at", "camera_id", "plate_index")}

    def proof(self, statement):
        credential = models.presence_credential(self.conn, self.requester())
        proof_statement = presence.build(statement, custody.credential_key_id(credential))
        key = approvals.unwrap_signing_key(self.requester(), "pw")
        return proof_statement, presence.sign(key, proof_statement)

    def index_of(self, plate):
        return models.scope_token(self.conn, plate)

    # -- the custodian under test -----------------------------------------

    def agreement(self, attested=True, image=None):
        return custodian.KmsAgreement(
            self.kms, self.kms.key_arn, self.kms.public_raw,
            recipient=FakeKms.attestation(image or self.image) if attested else None,
            enclave_decrypt=FakeKms.enclave_decrypt if attested else None)

    def custodian(self, attested=True, image=None, registry_versions=None, **kwargs):
        return custodian.Custodian(
            self.agreement(attested, image),
            approvers=disclosure.local_approver_registry(self.conn),
            requesters=disclosure.local_requester_registry(self.conn),
            usage=disclosure.UsageStore(self.path),
            registry_versions=registry_versions,
            **kwargs)

    def open_it(self, custodian_=None, envelope=None, identity=None, statement=None,
                signature=None, requester="officer1", proof_statement=None,
                proof=None, registry_versions=None, blind_index_of=None):
        if statement is None:
            statement, signature = self.statement_for()
        if proof_statement is None and proof is None:
            proof_statement, proof = self.proof(statement)
        envelope = envelope if envelope is not None else self.envelope()
        return (custodian_ or self.custodian()).open(
            envelope, identity if identity is not None else self.identity(envelope),
            statement, signature, requester, proof_statement, proof,
            registry_versions=registry_versions,
            blind_index_of=blind_index_of or self.index_of)


class TestTheAuthorizedPath(CustodianTest):
    def test_a_fully_authorized_disclosure_opens_exactly_one_record(self):
        result = self.open_it()
        self.assertEqual(result["fields"]["plate"], PLATE)
        self.assertEqual(result["fields"]["location"], LOCATION)
        self.assertEqual(result["suite"], kem.P256_ECDH)
        self.assertEqual(result["backend"], "aws-kms")
        self.assertEqual(result["presence"], "software")

    def test_the_record_is_sealed_as_v4_under_p256(self):
        envelope = self.envelope()
        self.assertEqual(envelope["seal_version"], sealing.FORMAT_VERSION)
        self.assertEqual(envelope["seal_kem"], kem.P256_ECDH)

    def test_the_custodian_exposes_no_bare_agreement_operation(self):
        """The oracle, restated as an API, is the thing being avoided."""
        instance = self.custodian()
        for forbidden in ("derive", "derive_shared_secret", "agree", "unwrap", "decrypt"):
            self.assertFalse(hasattr(instance, forbidden),
                             f"Custodian.{forbidden} would restore the oracle")

    def test_scope_must_be_re_derived_by_the_custodian_itself(self):
        with self.assertRaises(custodian.CustodianError) as caught:
            self.custodian().open(self.envelope(), self.identity(),
                                  *self.statement_for(), "officer1")
        self.assertIn("its own scope function", str(caught.exception))


class TestTheArchiveWalkingOracle(CustodianTest):
    """The attack the whole stage exists to remove."""

    def test_an_arbitrary_ephemeral_key_without_authorization_is_refused(self):
        """A compromised service holding every row's ephemeral_pub gets nothing
        from the custodian without a complete, valid disclosure context."""
        statement, signature = self.statement_for()
        proof_statement, proof = self.proof(statement)
        instance = self.custodian()

        for description, kwargs in (
                ("no approval at all", {"statement": {}, "signature": ""}),
                ("no proof of presence", {"proof_statement": {}, "proof": {}}),
        ):
            with self.subTest(description):
                with self.assertRaises(custodian.CustodianError):
                    instance.open(self.envelope(), self.identity(),
                                  kwargs.get("statement", statement),
                                  kwargs.get("signature", signature), "officer1",
                                  kwargs.get("proof_statement", proof_statement),
                                  kwargs.get("proof", proof),
                                  blind_index_of=self.index_of)

    def test_one_valid_approval_does_not_open_a_different_record(self):
        """The heart of it: an approval for one plate must not walk the table."""
        other_id = models.insert_event(
            self.conn, "OTHER11", timeutil.to_canonical(self.now - timedelta(hours=2)),
            "CAM-2", 0.9, "Dock Road", "claimed", source_ref=self.source)
        other = self.envelope(other_id)
        with self.assertRaises(custodian.CustodianError) as caught:
            self.open_it(envelope=other, identity=self.identity(other))
        self.assertIn("not the plate the approval covers", str(caught.exception))

    def test_a_record_outside_the_window_is_refused(self):
        old_id = models.insert_event(
            self.conn, PLATE, timeutil.to_canonical(self.now - timedelta(days=400)),
            "CAM-1", 0.9, "Long ago", "claimed", source_ref=self.source)
        old = self.envelope(old_id)
        with self.assertRaises(custodian.CustodianError) as caught:
            self.open_it(envelope=old, identity=self.identity(old))
        self.assertIn("outside the approved time window", str(caught.exception))

    def test_identity_cannot_be_detached_from_the_envelope(self):
        """Supplying another record's identity alongside this envelope."""
        other_id = models.insert_event(
            self.conn, PLATE, timeutil.to_canonical(self.now - timedelta(hours=3)),
            "CAM-3", 0.9, "Sidings", "claimed", source_ref=self.source)
        with self.assertRaises(custodian.CustodianError) as caught:
            self.open_it(envelope=self.envelope(),
                         identity=self.identity(self.envelope(other_id)))
        self.assertIn("does not match the envelope", str(caught.exception))


class TestAttestation(CustodianTest):
    """The one control that does not depend on JustiKey's code being correct."""

    def test_a_compromised_parent_calling_kms_directly_is_refused(self):
        """Same IAM credentials, same key, no enclave attestation."""
        with self.assertRaises(AccessDeniedException) as caught:
            self.kms.derive_shared_secret(
                KeyId=self.kms.key_arn, KeyAgreementAlgorithm="ECDH",
                PublicKey=custodian._spki(kem.P256Suite.generate()[1]))
        self.assertIn("RecipientAttestation", str(caught.exception))

    def test_an_unattested_custodian_against_an_attesting_key_is_refused(self):
        with self.assertRaises(custodian.AgreementUnavailable):
            self.open_it(custodian_=self.custodian(attested=False))

    def test_a_modified_enclave_image_is_refused(self):
        other = image_sha384("a rebuilt custodian nobody approved")
        with self.assertRaises(custodian.AgreementUnavailable) as caught:
            self.open_it(custodian_=self.custodian(image=other))
        self.assertIn("does not match", str(caught.exception))

    def test_a_revoked_image_stops_working(self):
        self.open_it()                                   # approved today
        self.kms.revoked_images.add(self.image)
        with self.assertRaises(custodian.AgreementUnavailable) as caught:
            self.open_it()
        self.assertIn("revoked", str(caught.exception))

    def test_an_attested_call_never_returns_a_plaintext_secret_to_the_parent(self):
        response = self.kms.derive_shared_secret(
            KeyId=self.kms.key_arn, KeyAgreementAlgorithm="ECDH",
            PublicKey=custodian._spki(kem.P256Suite.generate()[1]),
            Recipient=FakeKms.attestation(self.image))
        self.assertEqual(response["SharedSecret"], b"")
        self.assertTrue(response["CiphertextForRecipient"])

    def test_a_backend_returning_a_plaintext_secret_on_an_attested_call_is_refused(self):
        """If the attested path ever hands the parent a usable secret, that is
        not the attested path and must not be trusted."""
        class Leaky:
            def derive_shared_secret(self, **kwargs):
                return {"SharedSecret": b"x" * 32, "CiphertextForRecipient": b"for-enclave:00"}

        agreement = custodian.KmsAgreement(
            Leaky(), self.kms.key_arn, self.kms.public_raw,
            recipient=FakeKms.attestation(self.image),
            enclave_decrypt=FakeKms.enclave_decrypt)
        with self.assertRaises(custodian.CustodianError) as caught:
            agreement.agree(kem.P256Suite.generate()[1])
        self.assertIn("not the attested path", str(caught.exception))

    def test_only_an_attested_configuration_claims_to_meet_the_objective(self):
        self.assertTrue(self.agreement(attested=True).meets_stage_5)
        self.assertFalse(self.agreement(attested=False).meets_stage_5)
        self.assertFalse(custodian.LocalAgreement(
            *reversed(list(reversed([sealing.generate_keypair(kem.P256_ECDH)[0],
                                     kem.P256_ECDH])))).meets_stage_5)


class TestPointValidation(CustodianTest):
    def test_a_point_not_on_the_curve_never_reaches_the_backend(self):
        """The invalid-curve attack: refused before it becomes a KMS call."""
        envelope = self.envelope()
        raw = sealing._unb64(envelope["ephemeral_pub"])
        prime = 2**256 - 2**224 + 2**192 + 2**96 - 1
        bad_y = (int.from_bytes(raw[33:], "big") + 1) % prime
        envelope["ephemeral_pub"] = sealing._b64(
            b"\x04" + raw[1:33] + bad_y.to_bytes(32, "big"))

        before = len(self.kms.calls)
        with self.assertRaises(custodian.CustodianError) as caught:
            self.open_it(envelope=envelope, identity=self.identity())
        self.assertIn("not a point on P-256", str(caught.exception))
        self.assertEqual(len(self.kms.calls), before, "the bad point reached KMS")

    def test_a_malformed_ephemeral_key_is_refused(self):
        for bad in (b"", b"\x04" + b"\x00" * 64, b"\x02" * 33, b"\xaa" * 32):
            envelope = self.envelope()
            envelope["ephemeral_pub"] = sealing._b64(bad)
            with self.assertRaises(custodian.CustodianError):
                self.open_it(envelope=envelope, identity=self.identity())


class TestEditedScopeAndReplay(CustodianTest):
    def test_a_widened_window_is_refused(self):
        statement, signature = self.statement_for()
        proof_statement, proof = self.proof(statement)
        widened = dict(statement, window_end=timeutil.to_canonical(
            self.now + timedelta(days=400)))
        with self.assertRaises(custodian.CustodianError) as caught:
            self.open_it(statement=widened, signature=signature,
                         proof_statement=proof_statement, proof=proof)
        self.assertIn("signature does not cover", str(caught.exception))

    def test_a_swapped_target_plate_is_refused(self):
        statement, signature = self.statement_for()
        proof_statement, proof = self.proof(statement)
        swapped = dict(statement, target_plate="OTHER11")
        with self.assertRaises(custodian.CustodianError):
            self.open_it(statement=swapped, signature=signature,
                         proof_statement=proof_statement, proof=proof)

    def test_a_proof_of_presence_is_spent_once(self):
        statement, signature = self.statement_for()
        proof_statement, proof = self.proof(statement)
        instance = self.custodian()
        self.open_it(custodian_=instance, statement=statement, signature=signature,
                     proof_statement=proof_statement, proof=proof)
        with self.assertRaises(custodian.CustodianError) as caught:
            self.open_it(custodian_=instance, statement=statement, signature=signature,
                         proof_statement=proof_statement, proof=proof)
        self.assertIn("already been used", str(caught.exception))

    def test_the_disclosure_cap_is_enforced_by_the_custodian(self):
        instance = self.custodian(max_disclosures=3)
        opened = 0
        for _ in range(8):
            try:
                self.open_it(custodian_=instance)
            except custodian.CustodianError:
                break
            opened += 1
        self.assertEqual(opened, 3)

    def test_concurrent_opens_cannot_duplicate_a_disclosure(self):
        import threading

        instance = self.custodian(max_disclosures=2)
        prepared = []
        for _ in range(10):
            statement, signature = self.statement_for()
            proof_statement, proof = self.proof(statement)
            prepared.append((statement, signature, proof_statement, proof))

        envelope, identity = self.envelope(), self.identity()
        succeeded, unexpected = [], []
        barrier, lock = threading.Barrier(len(prepared)), threading.Lock()

        def attempt(index):
            statement, signature, proof_statement, proof = prepared[index]
            barrier.wait()
            try:
                instance.open(envelope, identity, statement, signature, "officer1",
                              proof_statement, proof, blind_index_of=self.index_of)
            except custodian.CustodianError:
                return
            except Exception as exc:                       # noqa: BLE001
                with lock:
                    unexpected.append(f"{type(exc).__name__}: {exc}")
                return
            with lock:
                succeeded.append(index)

        workers = [threading.Thread(target=attempt, args=(i,)) for i in range(len(prepared))]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        self.assertEqual(unexpected, [])
        self.assertEqual(len(succeeded), 2)


class TestRegistryVersioning(CustodianTest):
    def test_a_caller_working_from_older_registry_state_is_refused(self):
        instance = self.custodian(registry_versions={"approver": 4, "requester": 2})
        with self.assertRaises(custodian.CustodianError) as caught:
            self.open_it(custodian_=instance,
                         registry_versions={"approver": 3, "requester": 2})
        self.assertIn("registry v3", str(caught.exception))

    def test_a_caller_that_states_no_version_is_refused(self):
        instance = self.custodian(registry_versions={"approver": 4})
        with self.assertRaises(custodian.CustodianError) as caught:
            self.open_it(custodian_=instance, registry_versions={})
        self.assertIn("did not state", str(caught.exception))

    def test_matching_versions_are_accepted(self):
        instance = self.custodian(registry_versions={"approver": 4, "requester": 2})
        result = self.open_it(custodian_=instance,
                              registry_versions={"approver": 4, "requester": 2})
        self.assertEqual(result["fields"]["plate"], PLATE)


class TestSuiteAndKeyBinding(CustodianTest):
    def test_a_record_naming_an_unaccepted_suite_is_refused(self):
        envelope = dict(self.envelope(), seal_kem=kem.X25519_ECDH)
        with self.assertRaises(custodian.CustodianError) as caught:
            self.open_it(envelope=envelope, identity=self.identity())
        self.assertIn("does not accept", str(caught.exception))

    def test_a_v4_record_with_its_suite_stripped_is_refused(self):
        """Defaulting a missing suite would let a stripped field choose the
        primitive, which is what binding it into the AAD exists to prevent."""
        envelope = dict(self.envelope(), seal_kem=None)
        with self.assertRaises(custodian.CustodianError) as caught:
            self.open_it(envelope=envelope, identity=self.identity())
        self.assertIn("must name its key-agreement suite", str(caught.exception))

    def test_a_record_sealed_to_another_key_is_refused(self):
        envelope = dict(self.envelope(), recipient_key_id="0" * 16)
        with self.assertRaises(custodian.CustodianError) as caught:
            self.open_it(envelope=envelope, identity=self.identity())
        self.assertIn("does not hold", str(caught.exception))

    def test_key_rotation_leaves_historical_records_openable(self):
        """A second key version, no exportable master, both openable."""
        first = self.open_it()
        self.assertEqual(first["fields"]["plate"], PLATE)
        old_kms, old_public = self.kms, self.public_hex

        from justikey import config, crypto_store
        self.kms = FakeKms(allowed_image_sha384=self.image,
                           key_arn="arn:aws:kms:test:key/agree-v2")
        # Rotation, as a deployment actually performs it: the database's
        # pinned recipient key is replaced, so new records seal to the new
        # version while old ones keep naming the old one.
        config.DISCLOSURE_PUBLIC_KEY = self.kms.public_raw.hex()
        crypto_store.set_meta(self.conn, "disclosure_public_key",
                              self.kms.public_raw.hex())
        self.conn._sealer_loaded = False
        new_id = models.insert_event(
            self.conn, PLATE, timeutil.to_canonical(self.now - timedelta(minutes=30)),
            "CAM-9", 0.99, "After rotation", "claimed", source_ref=self.source)

        self.assertNotEqual(self.envelope(new_id)["recipient_key_id"],
                            self.envelope(self.record_id)["recipient_key_id"])

        fresh = self.open_it(envelope=self.envelope(new_id),
                             identity=self.identity(self.envelope(new_id)))
        self.assertEqual(fresh["fields"]["location"], "After rotation")

        # The old key version still opens its own records, through its own
        # custodian, with nothing exportable restored.
        self.kms, self.public_hex = old_kms, old_public
        historical = self.open_it()
        self.assertEqual(historical["fields"]["location"], LOCATION)


class TestFailClosed(CustodianTest):
    def test_an_unreachable_backend_opens_nothing(self):
        class Unreachable:
            def derive_shared_secret(self, **kwargs):
                raise OSError("connection refused")

        agreement = custodian.KmsAgreement(
            Unreachable(), self.kms.key_arn, self.kms.public_raw,
            recipient=FakeKms.attestation(self.image),
            enclave_decrypt=FakeKms.enclave_decrypt)
        instance = custodian.Custodian(
            agreement, approvers=disclosure.local_approver_registry(self.conn),
            requesters=disclosure.local_requester_registry(self.conn),
            usage=disclosure.UsageStore(self.path))
        with self.assertRaises(custodian.AgreementUnavailable):
            self.open_it(custodian_=instance)

    def test_a_recipient_without_a_way_to_decrypt_is_a_refusal_not_a_fallback(self):
        with self.assertRaises(custodian.CustodianError) as caught:
            custodian.KmsAgreement(self.kms, self.kms.key_arn, self.kms.public_raw,
                                   recipient=FakeKms.attestation(self.image))
        self.assertIn("no way to decrypt", str(caught.exception))

    def test_kms_refuses_a_suite_it_cannot_perform(self):
        with self.assertRaises(custodian.CustodianError) as caught:
            custodian.KmsAgreement(self.kms, self.kms.key_arn, self.kms.public_raw,
                                   kem_name=kem.X25519_ECDH)
        self.assertIn("NIST ECC only", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
