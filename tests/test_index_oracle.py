"""Attack 13: /index as a keyed-PRF oracle.

Moving the blind-index key into the enclave is not the same as moving its
capability. If the custodian will mint a scope token for any plate asked of
it, then a compromised parent holding the sealed archive runs:

    for every plausible plate:
        token = custodian /index(plate)
        compare token with the stored blind indexes

Plates are low-entropy, so this is materially different from attacking a
random secret. The attacker still cannot decrypt a row -- and does not need
to, having learned which sealed row is which vehicle.

Measured against the code before the split: 25 of 25 records identified,
100% correct, in 0.44 seconds against a 270-plate candidate space. The
600/min rate limit only sets a pace: ~20 days for the whole AAA999 space, and
minutes for a targeted subset.

THE FIX. Two capabilities, two credentials:

    index         a token for ANY plate. Ingest only, on a host that holds no
                  archive, and an attested custodian refuses to offer it.
    search-token  a token for exactly the plate an approver signed for, after
                  the custodian verifies the approval. Spends nothing.

So mapping the archive now needs both the ingest capability (which has no
archive) and the archive (which has no capability).
"""
import itertools
import os
import random
import shutil
import sys
import tempfile
import threading
import unittest
from datetime import timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import helpers  # noqa: E402
from justikey import (approvals, config, custodian, db, disclosure, kem,  # noqa: E402
                      models, sealing, servicekit, timeutil)

SKIP = not sealing.SEALING_AVAILABLE

DISCLOSURE_SECRET = "disclosure-host-secret"
INGEST_SECRET = "ingest-host-secret"
INDEX_KEY = bytes.fromhex("ab" * 32)


@unittest.skipIf(SKIP, "stage 5 requires the cryptography package")
class IndexOracleTest(unittest.TestCase):
    """A sealed archive, a custodian, and a parent that holds the archive."""

    def setUp(self):
        import custodian_server

        self.module = custodian_server
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "justikey.db")
        self.ledger = os.path.join(self.dir, "custodian.db")

        private_hex, public_hex = sealing.generate_keypair(kem.P256_ECDH)
        self._saved = (config.DISCLOSURE_PUBLIC_KEY, config.DISCLOSURE_KEM,
                       config.CUSTODIAN_URL, config.CUSTODIAN_CLIENT_SECRET,
                       config.CUSTODIAN_INGEST_SECRET)
        self.addCleanup(self._restore)
        config.DISCLOSURE_PUBLIC_KEY = public_hex
        config.DISCLOSURE_KEM = kem.P256_ECDH
        config.CUSTODIAN_URL = "http://127.0.0.1:1"     # custodian-backed
        config.CUSTODIAN_CLIENT_SECRET = DISCLOSURE_SECRET
        config.CUSTODIAN_INGEST_SECRET = INGEST_SECRET

        servicekit.init_ledger(self.ledger)
        self._saved_state = dict(custodian_server.STATE)
        self.addCleanup(self._restore_state)
        custodian_server.STATE.clear()
        custodian_server.STATE.update({
            "record": servicekit.LedgerWriter(self.ledger),
            "usage": disclosure.UsageStore(self.ledger),
            "client_secrets": {"disclosure": DISCLOSURE_SECRET,
                               "ingest": INGEST_SECRET},
            "allow_ingest_tokens": True,
            "index_key": INDEX_KEY,
            "index_limit": 0,               # measure the ceiling, not the throttle
            "index_lock": threading.Lock(),
            "index_calls": [], "search_calls": [],
            "registry_versions": {"approver": 1, "requester": 1},
            "custodian": None,              # filled in once users exist
        })

        self._seal_archive(private_hex)

    def _restore(self):
        (config.DISCLOSURE_PUBLIC_KEY, config.DISCLOSURE_KEM, config.CUSTODIAN_URL,
         config.CUSTODIAN_CLIENT_SECRET, config.CUSTODIAN_INGEST_SECRET) = self._saved

    def _restore_state(self):
        self.module.STATE.clear()
        self.module.STATE.update(self._saved_state)

    def _seal_archive(self, private_hex):
        letters, digits = "ABC", "0123456789"
        self.space = [f"{a}{b}{c}{d}"
                      for a, b, c in itertools.product(letters, repeat=3)
                      for d in digits]

        db.init_db(self.path)
        self.conn = db.get_connection(self.path)
        self.addCleanup(self.conn.close)
        # Ingest indexes at the custodian, with the ingest capability.
        self.conn._index_client = _DirectIngest(self.module)

        source = models.create_source(self.conn, "cam", "Cam")
        self.requester_id = models.create_user(self.conn, "officer1", "pw", "requester")
        self.approver_id = models.create_user(self.conn, "supervisor1", "pw", "approver")
        # The custodian snapshots its registries at construction, as the real
        # one does at startup, so the approver's key has to exist first.
        public, wrapped, salt = approvals.generate_signing_key("pw")
        models.set_signing_key(self.conn, self.approver_id, public, wrapped, salt)
        self.now = timeutil.now()

        random.seed(7)
        self.archive = random.sample(self.space, 25)
        for offset, plate in enumerate(self.archive):
            models.insert_event(
                self.conn, plate,
                timeutil.to_canonical(self.now - timedelta(hours=offset + 1)),
                "CAM-1", 0.95, f"Depot {offset}", "claimed", source_ref=source)

        self.module.STATE["custodian"] = custodian.Custodian(
            custodian.LocalAgreement(private_hex, kem.P256_ECDH),
            approvers=disclosure.local_approver_registry(self.conn),
            requesters=disclosure.local_requester_registry(self.conn),
            usage=disclosure.UsageStore(self.ledger),
            presence_mode="off",
            registry_versions={"approver": 1, "requester": 1})

        self.stored = {row["plate_index"]: row["id"] for row in
                       self.conn.execute("SELECT id, plate_index FROM lpr_events")}

    # -- the attack -------------------------------------------------------

    def enumerate_archive(self, role, operation, payload_for):
        """What a compromised parent does: a token per candidate, compared."""
        mapped, granted = {}, 0
        for candidate in self.space:
            reply, status = self.module.dispatch(
                operation, payload_for(candidate), role=role)
            if status != 200:
                continue
            granted += 1
            row_id = self.stored.get(reply["plate_index"])
            if row_id is not None:
                mapped[row_id] = candidate
        return mapped, granted

    def approved_statement(self, plate):
        auth_id = models.create_authorization(
            self.conn, "CASE-1", "Warrant 1", "Investigation", plate,
            timeutil.to_canonical(self.now - timedelta(days=1)),
            timeutil.to_canonical(self.now + timedelta(days=1)), self.requester_id)
        helpers.approve_signed(self.conn, auth_id, self.approver_id)
        auth = models.get_authorization(self.conn, auth_id)
        approver = models.get_user_by_id(self.conn, self.approver_id)
        return approvals.build_statement(
            auth, "officer1", "supervisor1", auth["approved_at"],
            auth["approval_expires_at"],
            approver_key_id=approvals.signing_key_id(approver["signing_pub"])), \
            auth["approval_signature"]


class _DirectIngest:
    """The ingest host's client, which holds the ingest capability."""

    def __init__(self, module):
        self.module = module

    def blind_index(self, plate):
        reply, status = self.module.dispatch("index", {"plate": plate}, role="ingest")
        assert status == 200, reply
        return reply["plate_index"]


class TestTheOracleIsClosed(IndexOracleTest):
    def test_the_disclosure_host_cannot_enumerate_with_index(self):
        """The attack, run in full. Was 25 of 25; must now be 0."""
        mapped, granted = self.enumerate_archive(
            "disclosure", "index", lambda plate: {"plate": plate})
        self.assertEqual(granted, 0)
        self.assertEqual(mapped, {})

    def test_the_disclosure_host_cannot_enumerate_with_search_token(self):
        """The approved-scope operation is not an oracle either: without a
        verified approval there is no token."""
        mapped, granted = self.enumerate_archive(
            "disclosure", "search-token",
            lambda plate: {"statement": {"target_plate": plate}, "signature": "",
                           "registry_versions": {"approver": 1, "requester": 1}})
        self.assertEqual(granted, 0)
        self.assertEqual(mapped, {})

    def test_a_forged_approval_yields_no_token(self):
        """The statement is well-formed this time; only the signature is not."""
        statement, _ = self.approved_statement(self.archive[0])
        reply, status = self.module.dispatch(
            "search-token",
            {"statement": dict(statement, target_plate=self.archive[1]),
             "signature": "00" * 64,
             "registry_versions": {"approver": 1, "requester": 1}},
            role="disclosure")
        self.assertEqual(status, 403)
        self.assertIn("signature does not cover", reply["error"])


class TestTheApprovedPathStillWorks(IndexOracleTest):
    def test_an_approved_scope_yields_exactly_one_token(self):
        target = self.archive[3]
        statement, signature = self.approved_statement(target)
        reply, status = self.module.dispatch(
            "search-token",
            {"statement": statement, "signature": signature,
             "registry_versions": {"approver": 1, "requester": 1}},
            role="disclosure")
        self.assertEqual(status, 200, reply)
        # It matches that plate's records, and nothing else in the archive.
        matched = [row_id for index, row_id in self.stored.items()
                   if index == reply["plate_index"]]
        self.assertEqual(len(matched), 1)
        self.assertEqual(self.archive[matched[0] - 1], target)

    def test_a_search_token_spends_nothing(self):
        """`open` stays the single transactional point, so a search that finds
        nothing costs the requester none of their approval."""
        statement, signature = self.approved_statement(self.archive[0])
        for _ in range(5):
            _, status = self.module.dispatch(
                "search-token",
                {"statement": statement, "signature": signature,
                 "registry_versions": {"approver": 1, "requester": 1}},
                role="disclosure")
            self.assertEqual(status, 200)

        conn = db.get_connection(self.ledger)
        try:
            spent = conn.execute(
                "SELECT COUNT(*) c FROM authorization_usage").fetchone()["c"]
        finally:
            conn.close()
        self.assertEqual(spent, 0)

    def test_ingest_can_still_index_with_its_own_credential(self):
        reply, status = self.module.dispatch(
            "index", {"plate": self.archive[0]}, role="ingest")
        self.assertEqual(status, 200)
        self.assertIn(reply["plate_index"], self.stored)


class TestTheProductionGate(unittest.TestCase):
    """An attested custodian must not offer the arbitrary-plate operation."""

    def test_the_server_refuses_an_ingest_secret_when_attested(self):
        import subprocess

        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        attestation = os.path.join(directory, "attestation.bin")
        with open(attestation, "wb") as handle:
            handle.write(b"a document obtained out of band")
        _, public_hex = sealing.generate_keypair(kem.P256_ECDH)

        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", "custodian_server.py"),
             "--client-secret", "d" * 32, "--ingest-secret", "i" * 32,
             "--index-key", "11" * 32, "--presence-mode", "off",
             "--ledger", os.path.join(directory, "ledger.db"),
             "--kms-key-arn", "arn:aws:kms:test:key/agree",
             "--public-key", public_hex, "--attestation-file", attestation,
             "--transport", "vsock"],
            capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        if "boto3" not in result.stderr:
            self.assertEqual(result.returncode, 5)
            self.assertIn("must not offer ingest scope tokens", result.stderr)


if __name__ == "__main__":
    unittest.main()
