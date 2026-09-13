"""How many times one approval may be spent, and who gets to decide.

The application keeps a disclosure count, but a compromised application would
simply not run the code that checks it: with a genuine signed approval lifted
from its own database it can call the disclosure service directly. So the cap
has to be enforced by the side that holds the key, has to survive a restart,
and has to hold when several requests arrive at once.

Separately, a signed request stays valid for the clock-skew window, so anyone
who captured one could resend it verbatim. Transport nonces are spendable once.
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
from justikey import (approvals, db, disclosure, models, sealing,  # noqa: E402
                      timeutil)

SKIP = not sealing.SEALING_AVAILABLE


class ApprovalFixture(unittest.TestCase):
    """A sealed database with one observation and one signed approval."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "justikey.db")
        db.init_db(self.path)
        self.conn = db.get_connection(self.path)
        self.source = models.create_source(self.conn, "cam", "Cam")
        self.requester_id = models.create_user(self.conn, "officer1", "pw", "requester")
        self.approver_id = models.create_user(self.conn, "supervisor1", "pw", "approver")
        self.now = timeutil.now()
        models.insert_event(
            self.conn, "SECRET99", timeutil.to_canonical(self.now - timedelta(hours=1)),
            "CAM-1", 0.95, "Elm Street Depot", "claimed", source_ref=self.source)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def approved(self, plate="SECRET99", days=1, expires_in_days=None):
        """Return (statement, signature) exactly as the service will see them."""
        auth_id = models.create_authorization(
            self.conn, "CASE-1", "Warrant 1", "Investigation", plate,
            timeutil.to_canonical(self.now - timedelta(days=days)),
            timeutil.to_canonical(self.now + timedelta(days=days)), self.requester_id)
        helpers.approve_signed(self.conn, auth_id, self.approver_id)
        auth = models.get_authorization(self.conn, auth_id)
        approver = models.get_user_by_id(self.conn, self.approver_id)
        expires = auth["approval_expires_at"]
        if expires_in_days is not None:
            expires = timeutil.to_canonical(self.now + timedelta(days=expires_in_days))
        statement = approvals.build_statement(
            auth, "officer1", "supervisor1", auth["approved_at"], expires,
            approver_key_id=approvals.signing_key_id(approver["signing_pub"]))
        return statement, auth["approval_signature"]

    def candidates(self, statement):
        return [dict(row) for row in models.search_events(
            self.conn, statement["target_plate"],
            statement["window_start"], statement["window_end"])]


@unittest.skipIf(SKIP, "sealing requires the cryptography package")
class TestTheServiceOwnsTheCap(ApprovalFixture):
    """Going straight to the service, the way a compromised application would."""

    def service(self, max_disclosures=None):
        svc = disclosure.service_for(self.conn, self.path)
        if max_disclosures is not None:
            svc.max_disclosures = max_disclosures
        return svc

    def test_one_approval_stops_at_the_cap(self):
        statement, signature = self.approved()
        rows = self.candidates(statement)
        self.assertEqual(len(rows), 1)
        svc = self.service(max_disclosures=5)

        opened = 0
        for _ in range(20):
            try:
                revealed = svc.disclose(rows, statement, signature, "officer1")
            except disclosure.DisclosureError as exc:
                self.assertIn("limit is 5", str(exc))
                break
            self.assertEqual(revealed[0]["plate"], "SECRET99")
            opened += 1
        else:
            self.fail("the cap was never reached")
        self.assertEqual(opened, 5)

    def test_the_count_survives_a_restart(self):
        """In-process state would be reset by anything that restarts the service."""
        statement, signature = self.approved()
        rows = self.candidates(statement)
        for _ in range(3):
            self.service(max_disclosures=3).disclose(rows, statement, signature, "officer1")

        fresh = self.service(max_disclosures=3)     # a brand-new service object
        with self.assertRaises(disclosure.DisclosureError):
            fresh.disclose(rows, statement, signature, "officer1")

    def test_concurrent_requests_cannot_overshoot(self):
        """Read-then-increment has to be one transaction, or N threads all see 4."""
        statement, signature = self.approved()
        rows = self.candidates(statement)
        svc = self.service(max_disclosures=5)

        granted, start = [], threading.Barrier(12)
        lock = threading.Lock()

        def attempt():
            start.wait()
            try:
                svc.disclose(rows, statement, signature, "officer1")
            except disclosure.DisclosureError:
                return
            with lock:
                granted.append(1)

        threads = [threading.Thread(target=attempt) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(granted), 5)

    def test_each_approval_is_counted_separately(self):
        """Exhausting one approval must not spend another one's budget."""
        first, first_sig = self.approved()
        second, second_sig = self.approved()
        self.assertNotEqual(first["nonce"], second["nonce"])
        rows = self.candidates(first)
        svc = self.service(max_disclosures=2)

        for _ in range(2):
            svc.disclose(rows, first, first_sig, "officer1")
        with self.assertRaises(disclosure.DisclosureError):
            svc.disclose(rows, first, first_sig, "officer1")
        self.assertEqual(len(svc.disclose(rows, second, second_sig, "officer1")), 1)

    def test_a_cap_of_zero_means_unlimited(self):
        """Deployments that do not want a cap say so explicitly."""
        statement, signature = self.approved()
        rows = self.candidates(statement)
        svc = self.service(max_disclosures=0)
        for _ in range(40):
            svc.disclose(rows, statement, signature, "officer1")

    def test_a_refused_attempt_does_not_consume_a_use(self):
        """Otherwise a wrong requester could burn a genuine approval's budget."""
        statement, signature = self.approved()
        rows = self.candidates(statement)
        svc = self.service(max_disclosures=2)

        with self.assertRaises(disclosure.DisclosureError):
            svc.disclose(rows, statement, signature, "someone-else")
        for _ in range(2):
            svc.disclose(rows, statement, signature, "officer1")
        with self.assertRaises(disclosure.DisclosureError):
            svc.disclose(rows, statement, signature, "officer1")


@unittest.skipIf(SKIP, "sealing requires the cryptography package")
class TestUsageStore(ApprovalFixture):
    def store(self):
        return disclosure.UsageStore(self.path)

    def test_expiry_closes_an_approval_permanently(self):
        past = timeutil.to_canonical(self.now - timedelta(minutes=1))
        store = self.store()
        ok, count, _ = store.claim("nonce-a", 1, past, 10)
        self.assertTrue(ok)                      # first use writes the expiry
        ok, _, reason = store.claim("nonce-a", 1, past, 10)
        self.assertFalse(ok)
        self.assertIn("expired", reason)

    def test_purge_only_removes_expired_rows(self):
        store = self.store()
        past = timeutil.to_canonical(self.now - timedelta(days=1))
        future = timeutil.to_canonical(self.now + timedelta(days=1))
        store.claim("old", 1, past, 10)
        store.claim("live", 2, future, 10)
        store.purge_expired()

        conn = db.get_connection(self.path)
        try:
            remaining = {row["nonce"] for row in
                         conn.execute("SELECT nonce FROM authorization_usage")}
        finally:
            conn.close()
        self.assertEqual(remaining, {"live"})

    def test_a_transport_nonce_is_spendable_once(self):
        store = self.store()
        self.assertTrue(store.claim_transport_nonce("abc", 300))
        self.assertFalse(store.claim_transport_nonce("abc", 300))
        self.assertTrue(store.claim_transport_nonce("def", 300))

    def test_transport_nonces_are_not_approval_nonces(self):
        """Two separate namespaces: spending one must not spend the other."""
        store = self.store()
        future = timeutil.to_canonical(self.now + timedelta(days=1))
        self.assertTrue(store.claim_transport_nonce("shared", 300))
        ok, count, _ = store.claim("shared", 1, future, 10)
        self.assertTrue(ok)
        self.assertEqual(count, 1)


@unittest.skipIf(SKIP, "sealing requires the cryptography package")
class TestTransportReplayOverHttp(ApprovalFixture):
    """A captured request is valid for the whole clock window unless spent."""

    def setUp(self):
        super().setUp()
        import disclosure_server

        self.module = disclosure_server
        self.secret = "client-secret-for-the-test"
        self.ledger = os.path.join(self.dir, "ledger.db")
        conn = db.get_connection(self.ledger)
        try:
            conn.executescript(disclosure_server.LEDGER_SCHEMA)
        finally:
            conn.close()

        private_hex, _ = sealing.generate_keypair()
        self.saved_state = dict(disclosure_server.STATE)
        usage = disclosure.UsageStore(self.ledger)
        disclosure_server.STATE.update({
            "ledger": self.ledger,
            "client_secret": self.secret,
            "index_limit": 0,
            "usage": usage,
            "service": disclosure.DisclosureService(
                sealing.RecordOpener(private_hex), b"index-key-material",
                {}, usage=usage, max_disclosures=25),
        })
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), disclosure_server.Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.module.STATE.clear()
        self.module.STATE.update(self.saved_state)
        super().tearDown()

    def signed_request(self, nonce):
        body = json.dumps({"plate": "SECRET99"}, separators=(",", ":")).encode("utf-8")
        timestamp = timeutil.now_iso()
        return urllib.request.Request(
            f"http://127.0.0.1:{self.port}/index", data=body, method="POST",
            headers={
                "Content-Type": "application/json",
                "X-JustiKey-Client-Id": "app",
                "X-JustiKey-Timestamp": timestamp,
                "X-JustiKey-Nonce": nonce,
                "X-JustiKey-Signature": disclosure.request_signature(
                    self.secret, timestamp, nonce, body),
            })

    def send(self, req):
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_replaying_a_captured_request_is_refused(self):
        captured = self.signed_request("nonce-1")
        status, payload = self.send(captured)
        self.assertEqual(status, 200)
        self.assertIn("plate_index", payload)

        # Same bytes, same headers, well inside the clock window.
        status, payload = self.send(self.signed_request("nonce-1"))
        self.assertEqual(status, 401)
        self.assertIn("already been used", payload["error"])

    def test_the_refusal_is_recorded_in_the_service_ledger(self):
        self.send(self.signed_request("nonce-2"))
        self.send(self.signed_request("nonce-2"))

        conn = db.get_connection(self.ledger)
        try:
            kinds = [row["event_type"] for row in
                     conn.execute("SELECT event_type FROM audit_log ORDER BY seq")]
        finally:
            conn.close()
        self.assertIn("transport_replay_refused", kinds)

    def test_a_fresh_nonce_still_works(self):
        self.assertEqual(self.send(self.signed_request("nonce-3"))[0], 200)
        self.assertEqual(self.send(self.signed_request("nonce-4"))[0], 200)


if __name__ == "__main__":
    unittest.main()
