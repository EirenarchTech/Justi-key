"""The custodian as its own process (stage 5).

Everything to the left of the custodian is assumed compromised, so the value
of a separate process is that it shares no code path, no database and no
credentials with the disclosure service. These tests exercise it over its
real HTTP transport rather than as a library call, because the boundary is
the thing being built.
"""
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import timedelta
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import helpers  # noqa: E402
from justikey import (approvals, config, custodian, custody, db, disclosure,  # noqa: E402
                      kem, models, presence, registry, sealing, servicekit,
                      timeutil)

SKIP = not sealing.SEALING_AVAILABLE
if not SKIP:
    from fake_kms import FakeKms, image_sha384  # noqa: E402

PLATE = "SECRET99"
LOCATION = "Elm Street Depot"


@unittest.skipIf(SKIP, "stage 5 requires the cryptography package")
class CustodianProcessTest(unittest.TestCase):
    """A custodian on a real socket, and an application that holds no key."""

    def setUp(self):
        import custodian_server

        self.module = custodian_server
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "justikey.db")
        self.ledger = os.path.join(self.dir, "custodian-audit.db")
        self.secret = "custodian-client-secret"
        self.index_key = bytes.fromhex("11" * 32)

        self.image = image_sha384("approved-enclave")
        self.kms = FakeKms(allowed_image_sha384=self.image)
        self.public_hex = self.kms.public_raw.hex()

        self._saved = (config.DISCLOSURE_PUBLIC_KEY, config.DISCLOSURE_KEM,
                       config.CUSTODIAN_URL, config.CUSTODIAN_CLIENT_SECRET)
        self.addCleanup(self._restore)
        config.DISCLOSURE_PUBLIC_KEY = self.public_hex
        config.DISCLOSURE_KEM = kem.P256_ECDH

        self._build_store()
        self._start_custodian()

        config.CUSTODIAN_URL = f"http://127.0.0.1:{self.port}"
        config.CUSTODIAN_CLIENT_SECRET = self.secret

    def _restore(self):
        (config.DISCLOSURE_PUBLIC_KEY, config.DISCLOSURE_KEM,
         config.CUSTODIAN_URL, config.CUSTODIAN_CLIENT_SECRET) = self._saved

    def _build_store(self):
        db.init_db(self.path)
        self.conn = db.get_connection(self.path)
        self.addCleanup(self.conn.close)
        self.source = models.create_source(self.conn, "cam", "Cam")
        self.requester_id = models.create_user(self.conn, "officer1", "pw", "requester")
        self.approver_id = models.create_user(self.conn, "supervisor1", "pw", "approver")
        public, wrapped, salt = approvals.generate_signing_key("pw")
        models.set_signing_key(self.conn, self.requester_id, public, wrapped, salt)

        self.now = timeutil.now()
        # Seal against the custodian's key, with indexes under the same key
        # the custodian will use to re-derive scope.
        self.conn._index_client = _StaticIndex(self.index_key)
        self._saved_remote = disclosure.is_remote
        disclosure.is_remote = lambda: True
        self.addCleanup(setattr, disclosure, "is_remote", self._saved_remote)

        self.plates = [PLATE] + [f"CAR{i:03d}" for i in range(9)]
        self.record_ids = {}
        for offset, plate in enumerate(self.plates):
            self.record_ids[plate] = models.insert_event(
                self.conn, plate,
                timeutil.to_canonical(self.now - timedelta(hours=offset + 1)),
                "CAM-1", 0.95, LOCATION if plate == PLATE else f"Depot {offset}",
                "claimed", source_ref=self.source)
        self.auth_id = self.authorize()

        # Registries, as the custodian will hold them.
        self.approvers_path = os.path.join(self.dir, "approvers.json")
        self.requesters_path = os.path.join(self.dir, "requesters.json")
        self._write_registries()

    def _write_registries(self, version=1):
        for path, role in ((self.approvers_path, "approver"),
                           (self.requesters_path, "requester")):
            principals = disclosure._registry(self.conn, role)
            with open(path, "w") as fh:
                json.dump(registry.wrap(principals, version), fh)

    def _start_custodian(self, presence_mode="required", attested=True):
        servicekit.init_ledger(self.ledger)
        record = servicekit.LedgerWriter(self.ledger)
        admitted, versions = {}, {}
        for role, path in (("approver", self.approvers_path),
                           ("requester", self.requesters_path)):
            principals, _, detail = servicekit.admit_registry(self.ledger, role, path)
            admitted[role], versions[role] = principals, detail["version"]

        agreement = custodian.KmsAgreement(
            self.kms, self.kms.key_arn, self.kms.public_raw,
            recipient=FakeKms.attestation(self.image) if attested else None,
            enclave_decrypt=FakeKms.enclave_decrypt if attested else None)
        usage = disclosure.UsageStore(self.ledger)

        self._saved_state = dict(self.module.STATE)
        self.module.STATE.clear()
        self.module.STATE.update({
            "record": record, "usage": usage, "client_secret": self.secret,
            "index_key": self.index_key, "index_limit": 0,
            "index_lock": threading.Lock(), "index_calls": [],
            "registry_versions": versions,
            "custodian": custodian.Custodian(
                agreement, approvers=admitted["approver"],
                requesters=admitted["requester"], usage=usage,
                presence_mode=presence_mode, registry_versions=versions),
        })
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.module.Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_custodian)

    def _stop_custodian(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.module.STATE.clear()
        self.module.STATE.update(self._saved_state)

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

    def statement_for(self):
        auth = models.get_authorization(self.conn, self.auth_id)
        approver = models.get_user_by_id(self.conn, self.approver_id)
        return approvals.build_statement(
            auth, "officer1", "supervisor1", auth["approved_at"],
            auth["approval_expires_at"],
            approver_key_id=approvals.signing_key_id(approver["signing_pub"])), \
            auth["approval_signature"]

    def proof(self, statement):
        credential = models.presence_credential(self.conn, self.requester())
        proof_statement = presence.build(statement, custody.credential_key_id(credential))
        key = approvals.unwrap_signing_key(self.requester(), "pw")
        return proof_statement, presence.sign(key, proof_statement)

    def versions(self):
        """What the custodian holds -- the caller must state the same."""
        return dict(self.module.STATE["registry_versions"])

    def service(self):
        return disclosure.service_for(self.conn, self.path)

    def rows_for(self, statement):
        return [dict(r) for r in models.search_events(
            self.conn, statement["target_plate"],
            statement["window_start"], statement["window_end"])]


class _StaticIndex:
    """Stands in for the index client, using the custodian's key."""

    def __init__(self, key):
        self.key = key

    def blind_index(self, plate):
        import hashlib
        import hmac
        return hmac.new(self.key, str(plate).strip().upper().encode("utf-8"),
                        hashlib.sha256).hexdigest()


class TestTheApplicationHoldsNoKey(CustodianProcessTest):
    def test_the_service_reports_a_custodian_and_no_opener(self):
        service = self.service()
        self.assertIsNotNone(service._custodian)
        with self.assertRaises(disclosure.DisclosureError) as caught:
            service._opener.open({}, "", "", "")
        self.assertIn("holds no disclosure private key", str(caught.exception))

    def test_an_authorized_disclosure_works_across_the_process_boundary(self):
        statement, signature = self.statement_for()
        proof_statement, proof = self.proof(statement)
        service = self.service()
        opened = service.disclose(self.rows_for(statement), statement, signature,
                                  "officer1", proof_statement, proof)
        self.assertEqual([o["plate"] for o in opened], [PLATE])
        self.assertEqual(opened[0]["location"], LOCATION)
        self.assertEqual(service.last_presence["custody"], "software")

    def test_the_custodian_advertises_whether_it_is_attested(self):
        with urllib.request.urlopen(
                f"http://127.0.0.1:{self.port}/publickey", timeout=5) as response:
            info = json.loads(response.read().decode("utf-8"))
        self.assertTrue(info["attested"])
        self.assertEqual(info["kem"], kem.P256_ECDH)
        self.assertEqual(info["backend"], "aws-kms")


class TestTheBoundaryRefuses(CustodianProcessTest):
    def post(self, path, payload, secret=None, nonce=None):
        import secrets as _secrets

        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        timestamp = timeutil.now_iso()
        nonce = nonce or _secrets.token_urlsafe(16)
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "X-JustiKey-Client-Id": "disclosure-service",
                     "X-JustiKey-Timestamp": timestamp,
                     "X-JustiKey-Nonce": nonce,
                     "X-JustiKey-Signature": servicekit.request_signature(
                         secret or self.secret, timestamp, nonce, body)})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_an_unauthenticated_caller_is_refused(self):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/open", data=b"{}", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(caught.exception.code, 401)

    def test_a_wrong_client_secret_is_refused(self):
        status, _ = self.post("/index", {"plate": PLATE}, secret="the wrong secret")
        self.assertEqual(status, 401)

    def test_a_replayed_request_is_refused(self):
        nonce = "a-fixed-transport-nonce"
        self.assertEqual(self.post("/index", {"plate": PLATE}, nonce=nonce)[0], 200)
        status, payload = self.post("/index", {"plate": PLATE}, nonce=nonce)
        self.assertEqual(status, 401)
        self.assertIn("already been used", payload["error"])

    def test_there_is_no_endpoint_that_derives_a_secret(self):
        """The oracle, restated as a route, is the thing being avoided."""
        for path in ("/derive", "/agree", "/unwrap", "/key", "/privatekey", "/decrypt"):
            with self.subTest(path):
                self.assertEqual(self.post(path, {})[0], 404)

    def test_an_open_without_authorization_is_refused(self):
        row = dict(self.conn.execute(
            "SELECT * FROM lpr_events WHERE id=?",
            (self.record_ids[PLATE],)).fetchone())
        status, payload = self.post("/open", {
            "envelope": {k: row.get(k) for k in custodian.ENVELOPE_FIELDS},
            "identity": {k: row[k] for k in
                         ("record_uid", "captured_at", "camera_id", "plate_index")},
            "statement": {}, "signature": "", "requester": "officer1",
            "registry_versions": self.versions()})
        self.assertEqual(status, 403)
        self.assertIn("unsupported approval schema", payload["error"])

    def test_a_non_dict_approval_is_refused(self):
        row = dict(self.conn.execute(
            "SELECT * FROM lpr_events WHERE id=?",
            (self.record_ids[PLATE],)).fetchone())
        status, payload = self.post("/open", {
            "envelope": {k: row.get(k) for k in custodian.ENVELOPE_FIELDS},
            "identity": {k: row[k] for k in
                         ("record_uid", "captured_at", "camera_id", "plate_index")},
            "statement": "not an approval", "signature": "", "requester": "officer1",
            "registry_versions": self.versions()})
        self.assertEqual(status, 403)
        self.assertIn("malformed approval", payload["error"])

    def test_a_caller_that_states_no_registry_version_is_refused_first(self):
        """The outermost precondition: neither side opens anything while they
        disagree about whose keys count."""
        row = dict(self.conn.execute(
            "SELECT * FROM lpr_events WHERE id=?",
            (self.record_ids[PLATE],)).fetchone())
        status, payload = self.post("/open", {
            "envelope": {k: row.get(k) for k in custodian.ENVELOPE_FIELDS},
            "identity": {k: row[k] for k in
                         ("record_uid", "captured_at", "camera_id", "plate_index")},
            "statement": {}, "signature": "", "requester": "officer1"})
        self.assertEqual(status, 403)
        self.assertIn("did not state which approver registry", payload["error"])


class TestTheArchiveAcrossTheBoundary(CustodianProcessTest):
    def test_one_approval_replayed_across_every_record_yields_one_plate(self):
        """The stage 5 claim, measured through the real transport."""
        statement, signature = self.statement_for()
        rows = [dict(r) for r in self.conn.execute(
            "SELECT * FROM lpr_events ORDER BY id")]
        self.assertEqual(len(rows), len(self.plates))

        client = custodian.RemoteCustodian(
            f"http://127.0.0.1:{self.port}", "disclosure-service", self.secret)
        opened = []
        for row in rows:
            proof_statement, proof = self.proof(statement)
            identity = {k: row[k] for k in
                        ("record_uid", "captured_at", "camera_id", "plate_index")}
            try:
                result = client.open(row, identity, statement, signature, "officer1",
                                     proof_statement, proof,
                                     registry_versions=self.versions())
            except custodian.CustodianError:
                continue
            opened.append(result["fields"]["plate"])

        self.assertEqual(opened, [PLATE])

    def test_the_custodian_ledger_records_every_refusal(self):
        statement, signature = self.statement_for()
        rows = [dict(r) for r in self.conn.execute(
            "SELECT * FROM lpr_events ORDER BY id")]
        client = custodian.RemoteCustodian(
            f"http://127.0.0.1:{self.port}", "disclosure-service", self.secret)
        for row in rows:
            proof_statement, proof = self.proof(statement)
            identity = {k: row[k] for k in
                        ("record_uid", "captured_at", "camera_id", "plate_index")}
            try:
                client.open(row, identity, statement, signature, "officer1",
                            proof_statement, proof,
                            registry_versions=self.versions())
            except custodian.CustodianError:
                pass

        conn = db.get_connection(self.ledger)
        try:
            kinds = [r["event_type"] for r in
                     conn.execute("SELECT event_type FROM audit_log ORDER BY seq")]
            details = [json.loads(r["details"]) for r in
                       conn.execute("SELECT details FROM audit_log ORDER BY seq")]
            from justikey import audit
            self.assertTrue(audit.verify_chain(conn)[0])
        finally:
            conn.close()
        self.assertEqual(kinds.count("open_granted"), 1)
        self.assertEqual(kinds.count("open_refused"), len(self.plates) - 1)
        # The plate never enters the custodian's ledger, or the ledger would
        # rebuild the archive the custodian exists to protect.
        blob = json.dumps(details)
        for plate in self.plates:
            self.assertNotIn(plate, blob)


class TestCustodianStateIsAuthoritative(CustodianProcessTest):
    def test_the_disclosure_service_does_not_also_spend_the_approval(self):
        """Two components both spending would halve every cap and make the two
        ledgers disagree about what happened."""
        statement, signature = self.statement_for()
        proof_statement, proof = self.proof(statement)
        service = self.service()
        service.disclose(self.rows_for(statement), statement, signature,
                         "officer1", proof_statement, proof)

        application_side = db.get_connection(self.path)
        try:
            spent_here = application_side.execute(
                "SELECT COUNT(*) c FROM authorization_usage").fetchone()["c"]
        finally:
            application_side.close()

        custodian_side = db.get_connection(self.ledger)
        try:
            spent_there = custodian_side.execute(
                "SELECT disclosure_count FROM authorization_usage "
                "WHERE nonce=?", (statement["nonce"],)).fetchone()
        finally:
            custodian_side.close()

        self.assertEqual(spent_here, 0, "the application spent it too")
        self.assertEqual(spent_there["disclosure_count"], 1)

    def test_a_proof_of_presence_is_spent_by_the_custodian(self):
        statement, signature = self.statement_for()
        proof_statement, proof = self.proof(statement)
        service = self.service()
        service.disclose(self.rows_for(statement), statement, signature,
                         "officer1", proof_statement, proof)
        with self.assertRaises(custodian.CustodianError):
            self.service().disclose(self.rows_for(statement), statement, signature,
                                    "officer1", proof_statement, proof)

    def test_registry_versions_must_agree_across_the_boundary(self):
        statement, signature = self.statement_for()
        proof_statement, proof = self.proof(statement)
        service = self.service()
        service.registry_versions = {"approver": 99, "requester": 99}
        with self.assertRaises(custodian.CustodianError) as caught:
            service.disclose(self.rows_for(statement), statement, signature,
                             "officer1", proof_statement, proof)
        self.assertIn("registry v99", str(caught.exception))


class TestTheApplicationHoldsNoIndexKey(CustodianProcessTest):
    """Finding 1, one domain deeper.

    A custodian holds the index key exactly as a disclosure service does, so
    the application must neither hold it nor be able to derive it -- and
    ingest must mint scope tokens there, or records are indexed under one key
    and searched under another.
    """

    def test_resolving_an_index_key_locally_is_refused(self):
        from justikey import crypto_store

        with self.assertRaises(crypto_store.EncryptionError) as caught:
            crypto_store.resolve_index_key(self.path)
        self.assertIn("custodian", str(caught.exception))

    def test_ingest_mints_its_index_at_the_custodian(self):
        """Indexed under one key and searched under another is a store that
        looks perfect and finds nothing."""
        conn = db.get_connection(self.path)
        self.addCleanup(conn.close)
        token = models.scope_token(conn, PLATE)
        self.assertEqual(token, _StaticIndex(self.index_key).blind_index(PLATE))

    def test_the_index_client_prefers_the_custodian(self):
        client = disclosure.index_client()
        self.assertIsInstance(client, custodian.RemoteCustodian)


class TestFailsClosed(CustodianProcessTest):
    def test_an_unreachable_custodian_opens_nothing(self):
        statement, signature = self.statement_for()
        proof_statement, proof = self.proof(statement)
        service = self.service()
        self._stop_custodian()
        self.addCleanup(lambda: None)          # already stopped

        with self.assertRaises(custodian.AgreementUnavailable):
            service.disclose(self.rows_for(statement), statement, signature,
                             "officer1", proof_statement, proof)

    def test_a_kms_outage_is_a_503_and_not_a_fallback(self):
        class Unreachable:
            def derive_shared_secret(self, **kwargs):
                raise OSError("connection refused")

        self.module.STATE["custodian"].agreement = custodian.KmsAgreement(
            Unreachable(), self.kms.key_arn, self.kms.public_raw,
            recipient=FakeKms.attestation(self.image),
            enclave_decrypt=FakeKms.enclave_decrypt)

        statement, signature = self.statement_for()
        proof_statement, proof = self.proof(statement)
        with self.assertRaises(custodian.AgreementUnavailable):
            self.service().disclose(self.rows_for(statement), statement, signature,
                                    "officer1", proof_statement, proof)


if __name__ == "__main__":
    unittest.main()
