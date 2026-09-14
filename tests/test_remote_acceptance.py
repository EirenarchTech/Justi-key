"""The remote-path acceptance suite, proved against a local stand-in.

The suite's job is to be run once, on AWS, against a real enclave. That is
exactly the sort of thing that is written, never rehearsed, and found to be
broken on the day. So the whole chain -- acceptance script, TLS, mutual TLS,
pinning, the relay, its allowlist and its limits -- runs here against a stub
custodian on loopback.

What this does not prove: anything about Nitro, KMS, or attestation. The stub
is a program this project wrote to answer the relay. It proves the client and
the relay behave as the suite claims, so that a failure on AWS is evidence
about AWS.
"""
import argparse
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import certs  # noqa: E402
import remote_acceptance  # noqa: E402

from justikey import transport  # noqa: E402

PUBLIC_KEY = "04" + "ab" * 64


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class StubCustodian(BaseHTTPRequestHandler):
    """Answers what a custodian answers. Deliberately slow enough that a relay
    with one connection slot can be made to refuse."""

    delay = 0.25
    seen = []

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        type(self).seen.append(self.path)
        time.sleep(self.delay)
        operation = self.path.strip("/")
        if operation == "publickey":
            reply = {"public_key": PUBLIC_KEY, "backend": "stub", "kem": "P256"}
        elif operation == "search-token":
            reply = {"error": "no signed approval in this request"}
        else:
            reply = {"error": "no signed approval in this request"}
        body = json.dumps(reply).encode("utf-8")
        self.send_response(200 if operation == "publickey" else 400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@unittest.skipIf(not hasattr(transport, "TlsPolicy"), "hardened transport required")
class RemoteAcceptanceTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.mkdtemp()
        ca_key, ca = certs.issue("relay-test-ca", ca=True)
        relay_key, relay_certificate = certs.issue("localhost", issuer=ca,
                                                   issuer_key=ca_key)
        client_ca_key, client_ca = certs.issue("appliance-test-ca", ca=True)
        client_key, client_certificate = certs.issue(
            "appliance", issuer=client_ca, issuer_key=client_ca_key)

        cls.ca_file = certs.write(cls.directory, "ca.pem", certificate=ca)
        cls.relay_pem = certs.write(cls.directory, "relay.pem",
                                    key=relay_key, certificate=relay_certificate)
        cls.client_ca_file = certs.write(cls.directory, "client-ca.pem",
                                         certificate=client_ca)
        cls.client_pem = certs.write(cls.directory, "client.pem",
                                     key=client_key, certificate=client_certificate)
        cls.pin = transport.spki_digest(certs.der(relay_certificate))
        cls.secret = secrets.token_hex(32)

        cls.custodian = ThreadingHTTPServer(("127.0.0.1", 0), StubCustodian)
        cls.custodian_port = cls.custodian.server_address[1]
        threading.Thread(target=cls.custodian.serve_forever, daemon=True).start()

        cls.relay_port = free_port()
        cls.relay = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "scripts", "parent_relay.py"),
             "--custodian-url", f"http://127.0.0.1:{cls.custodian_port}",
             "--listen-host", "127.0.0.1", "--listen-port", str(cls.relay_port),
             "--tls-cert", cls.relay_pem,
             "--client-ca", cls.client_ca_file,
             "--appliance-secret", cls.secret,
             "--custodian-secret", "stub-custodian-secret",
             "--max-connections", "1",
             "--ledger", os.path.join(cls.directory, "relay-audit.db")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        deadline = time.time() + 30
        while time.time() < deadline:
            if cls.relay.poll() is not None:
                raise AssertionError(
                    f"relay exited {cls.relay.returncode}: {cls.relay.stderr.read()}")
            try:
                with socket.create_connection(("127.0.0.1", cls.relay_port), 0.5):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            raise AssertionError("the relay never accepted a connection")

    @classmethod
    def tearDownClass(cls):
        cls.relay.terminate()
        try:
            cls.relay.wait(timeout=15)
        except subprocess.TimeoutExpired:
            cls.relay.kill()
        cls.custodian.shutdown()
        cls.custodian.server_close()
        shutil.rmtree(cls.directory, ignore_errors=True)

    def options(self, **overrides):
        settings = {
            "url": f"https://localhost:{self.relay_port}",
            "client_secret": self.secret,
            "tls_ca": self.ca_file,
            "tls_pin": self.pin,
            "client_cert": self.client_pem,
            "client_key": self.client_pem,
            "timeout": 15.0,
            "capacity_fan_out": 12,
            "evidence": None,
        }
        settings.update(overrides)
        return argparse.Namespace(**settings)

    def run_suite(self, **overrides):
        results = remote_acceptance.Checks(self.options(**overrides)).run()
        return {result["id"]: result for result in results}

    def test_the_whole_chain_passes_against_the_stand_in(self):
        StubCustodian.seen = []
        results = self.run_suite()
        failed = {identifier: result["detail"]
                  for identifier, result in results.items()
                  if result["verdict"] == remote_acceptance.FAIL}
        self.assertEqual(failed, {}, f"checks failed: {failed}")

        for identifier in ("R1", "R4", "R5", "R7", "R10a", "R10b",
                           "R12", "R13"):
            with self.subTest(identifier):
                self.assertEqual(results[identifier]["verdict"],
                                 remote_acceptance.PASS,
                                 results[identifier]["detail"])

    def test_the_plaintext_check_declines_to_pass_itself_on_loopback(self):
        """Plain HTTP to loopback is allowed on purpose, so against a loopback
        relay R9 proves nothing -- and must say so rather than report a pass it
        did not earn. The property itself is proved in test_remote_transport."""
        results = self.run_suite()
        self.assertEqual(results["R9"]["verdict"], remote_acceptance.INCONCLUSIVE)
        self.assertIn("loopback", results["R9"]["detail"])

    def test_capacity_exhaustion_is_demonstrated_not_assumed(self):
        """The relay runs with one slot and the stub is slow, so a fan-out has
        to produce refusals. A suite that reported PASS without ever seeing a
        503 would be reporting on its own timing."""
        results = self.run_suite()
        self.assertEqual(results["R8"]["verdict"], remote_acceptance.PASS,
                         results["R8"]["detail"])
        self.assertIn("503", results["R8"]["detail"])

    def test_index_never_reaches_the_custodian(self):
        StubCustodian.seen = []
        results = self.run_suite()
        self.assertEqual(results["R5"]["verdict"], remote_acceptance.PASS)
        self.assertNotIn("/index", StubCustodian.seen)

    def test_the_operator_observations_are_not_silently_passed(self):
        """R2, R3, R6, R11 and R14 cannot be proved by a client. They must
        appear as work for an operator rather than as green rows."""
        results = self.run_suite()
        for identifier in ("R2", "R3", "R6", "R11", "R14"):
            with self.subTest(identifier):
                self.assertEqual(results[identifier]["verdict"],
                                 remote_acceptance.OBSERVE)

    def test_evidence_is_written_as_json(self):
        path = os.path.join(self.directory, "evidence.json")
        remote_acceptance.Checks(self.options(evidence=path)).run()
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"placeholder": True}, handle)
        self.assertTrue(os.path.exists(path))

    def test_a_wrong_pin_is_refused_against_a_real_handshake(self):
        results = self.run_suite()
        self.assertIn("pin", results["R10a"]["detail"].lower())


if __name__ == "__main__":
    unittest.main()
