"""The ingress relay on the parent instance.

The relay exists because vsock does not cross a network and the JustiKey
appliance is not on the parent. These tests are about what it refuses to
carry, and about it never being mistaken for an authorization boundary.
"""
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import parent_relay  # noqa: E402

from justikey import disclosure, servicekit, timeutil, transport  # noqa: E402


class RelayTest(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.secret = secrets.token_hex(32)
        self.calls = []
        self.reply = ({"fields": {"plate": "CAR007"}}, 200)

        def forward(operation, payload):
            self.calls.append((operation, payload))
            if isinstance(self.reply, Exception):
                raise self.reply
            return self.reply

        ledger = os.path.join(self.directory, "relay-audit.db")
        servicekit.init_ledger(ledger)
        parent_relay.STATE.clear()
        parent_relay.STATE.update({
            "client_secrets": {"disclosure": self.secret},
            "usage": disclosure.UsageStore(ledger),
            "record": servicekit.LedgerWriter(ledger),
            "slots": threading.Semaphore(4),
            "relay_rejected_over_capacity": 0,
            "forward": forward,
        })

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), parent_relay.Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        parent_relay.STATE.clear()
        shutil.rmtree(self.directory, ignore_errors=True)

    def client(self, secret=None):
        return transport.for_url(f"http://127.0.0.1:{self.port}", "disclosure",
                                 secret or self.secret, tls=transport.TlsPolicy())

    def raw(self, operation, body=b"{}", headers=None):
        import http.client

        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request("POST", f"/{operation}", body=body, headers=headers or {})
        response = connection.getresponse()
        status, raw = response.status, response.read()
        connection.close()
        return status, json.loads(raw.decode("utf-8"))

    def signed_headers(self, body, nonce=None, timestamp=None):
        timestamp = timestamp or timeutil.now_iso()
        nonce = nonce or secrets.token_urlsafe(16)
        return {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "X-JustiKey-Client-Id": "disclosure",
            "X-JustiKey-Timestamp": timestamp,
            "X-JustiKey-Nonce": nonce,
            "X-JustiKey-Signature": servicekit.request_signature(
                self.secret, timestamp, nonce, body),
        }

    # -- what it carries ---------------------------------------------------

    def test_an_open_is_forwarded_and_the_reply_returned(self):
        body, status = self.client().request("open", {"envelope": {"record_uid": "r1"}})
        self.assertEqual(status, 200)
        self.assertEqual(body, {"fields": {"plate": "CAR007"}})
        self.assertEqual(self.calls, [("open", {"envelope": {"record_uid": "r1"}})])

    def test_a_custodian_refusal_keeps_its_status(self):
        self.reply = ({"error": "presence proof required"}, 403)
        body, status = self.client().request("open", {})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "presence proof required")

    def test_search_token_and_publickey_are_carried(self):
        for operation in ("search-token", "publickey"):
            with self.subTest(operation):
                _body, status = self.client().request(operation, {})
                self.assertEqual(status, 200)

    # -- what it refuses ---------------------------------------------------

    def test_index_is_not_relayed(self):
        """`index` mints a scope token for an arbitrary plate. The whole point
        of attack 13's fix is that the disclosure side cannot reach it."""
        body, status = self.client().request("index", {"plate": "CAR007"})
        self.assertEqual(status, 404)
        self.assertIn("does not carry", body["error"])
        self.assertEqual(self.calls, [], "index reached the enclave")

    def test_an_unknown_operation_is_refused_by_name(self):
        for operation in ("derive", "agree", "..%2fopen", "open/extra"):
            with self.subTest(operation):
                _body, status = self.client().request(operation, {})
                self.assertEqual(status, 404)
        self.assertEqual(self.calls, [])

    def test_an_unauthenticated_request_never_reaches_the_enclave(self):
        status, body = self.raw("open", b"{}", {"Content-Length": "2"})
        self.assertEqual(status, 401)
        self.assertEqual(self.calls, [])

    def test_a_wrong_secret_is_refused(self):
        body, status = self.client(secret=secrets.token_hex(32)).request("open", {})
        self.assertEqual(status, 401)
        self.assertIn("signature", body["error"])
        self.assertEqual(self.calls, [])

    def test_a_replayed_request_is_refused(self):
        body = b'{"envelope":{"record_uid":"r1"}}'
        headers = self.signed_headers(body)
        first_status, _ = self.raw("open", body, headers)
        second_status, second = self.raw("open", body, headers)
        self.assertEqual(first_status, 200)
        self.assertEqual(second_status, 401)
        self.assertIn("nonce", second["error"])
        self.assertEqual(len(self.calls), 1)

    def test_a_body_too_large_for_one_frame_is_refused_before_forwarding(self):
        """servicekit allows 8 MiB; a vsock frame allows 1 MiB. The relay has
        to enforce the smaller one or the caller gets a framing error from the
        far side of a boundary it cannot see.

        The relay answers on Content-Length and closes without draining, so a
        large enough body races: the caller sees either the 413 or a dropped
        connection mid-send, depending on how much got into the socket buffer.
        Both are correct -- absorbing megabytes of a request already known to
        be unusable is the behaviour worth avoiding. What must hold either way
        is that nothing reached the enclave.
        """
        import http.client

        body = b"{" + b'"x":1,' * 400000 + b'"y":2}'
        self.assertGreater(len(body), transport.MAX_FRAME_BYTES)
        try:
            status, reply = self.raw("open", body, self.signed_headers(body))
        except (BrokenPipeError, ConnectionResetError,
                http.client.RemoteDisconnected):
            pass
        else:
            self.assertEqual(status, 413)
            self.assertIn("one frame", reply["error"])
        self.assertEqual(self.calls, [])

    def test_malformed_json_is_refused_before_forwarding(self):
        body = b"{not json"
        status, _reply = self.raw("open", body, self.signed_headers(body))
        self.assertEqual(status, 400)
        self.assertEqual(self.calls, [])

    # -- limits and failure ------------------------------------------------

    def test_at_capacity_the_relay_refuses_rather_than_queues(self):
        parent_relay.STATE["slots"] = threading.Semaphore(0)
        body, status = self.client().request("open", {})
        self.assertEqual(status, 503)
        self.assertIn("capacity", body["error"])
        self.assertEqual(self.calls, [])
        self.assertEqual(parent_relay.STATE["relay_rejected_over_capacity"], 1)

    def test_an_unreachable_custodian_is_a_bad_gateway_not_a_crash(self):
        self.reply = transport.TransportError("custodian unreachable on vsock 16:8091")
        body, status = self.client().request("open", {})
        self.assertEqual(status, 502)
        self.assertNotIn("vsock", json.dumps(body),
                         "the relay leaked its internal address to the caller")

    def test_the_capacity_slot_is_released_after_a_failure(self):
        self.reply = transport.TransportError("gone")
        self.client().request("open", {})
        self.reply = ({"ok": True}, 200)
        _body, status = self.client().request("open", {})
        self.assertEqual(status, 200)


class RelayStartupTest(unittest.TestCase):
    """A relay that would carry plaintext off the host refuses to start."""

    def run_relay(self, *arguments):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", "parent_relay.py"),
             *arguments],
            capture_output=True, text=True, timeout=60)

    def test_a_non_loopback_listener_without_tls_is_refused(self):
        result = self.run_relay("--enclave-cid", "16", "--appliance-secret", "s",
                                "--listen-host", "0.0.0.0")
        self.assertEqual(result.returncode, 6)
        self.assertIn("in clear", result.stderr)

    def test_mutual_tls_without_a_server_certificate_is_refused(self):
        result = self.run_relay("--enclave-cid", "16", "--appliance-secret", "s",
                                "--client-ca", "/tmp/ca.pem")
        self.assertEqual(result.returncode, 7)

    def test_no_appliance_secret_is_refused(self):
        environment = dict(os.environ)
        environment.pop("JUSTIKEY_RELAY_APPLIANCE_SECRET", None)
        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", "parent_relay.py"),
             "--enclave-cid", "16"],
            capture_output=True, text=True, timeout=60, env=environment)
        self.assertEqual(result.returncode, 2)

    def test_index_is_absent_from_the_relayed_operations(self):
        self.assertNotIn("index", parent_relay.RELAY_OPERATIONS)


if __name__ == "__main__":
    unittest.main()
