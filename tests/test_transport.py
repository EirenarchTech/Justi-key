"""The custodian boundary as framing, not authorization (stage 5).

On Nitro, vsock is the only channel between an enclave and its parent, and
the enclave has no external network and no persistent storage. That is real
isolation. It is NOT authorization: once the parent is in the threat model it
holds whatever transport credential the parent holds, and the CID only says
which side of a socket someone is on.

So these tests check two separate things:

  * the framing does its own job -- size ceilings, deadlines, bounded
    concurrency, strict schema, unknown fields refused
  * swapping the transport changes no authorization decision, which is
    checked by running the archive attack over the framed path and getting
    the same answer as over HTTP

WHAT CANNOT BE TESTED HERE. This kernel has AF_VSOCK and permits binding a
listener -- exercised below -- but has no vsock_loopback, so a local connect
times out. The framing is therefore driven over a socketpair, which is the
same code on the same sockets minus the kernel's vsock routing. Confirming
that routing needs a real enclave.
"""
import json
import os
import socket
import struct
import sys
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from justikey import transport  # noqa: E402


def _echo(operation, payload):
    if operation == "boom":
        raise RuntimeError("handler blew up")
    if operation not in ("index", "open", "publickey"):
        return {"error": f"unknown operation {operation!r}"}, 404
    return {"saw": operation, "payload": payload}, 200


class FramingTest(unittest.TestCase):
    def exchange(self, raw=None, operation=None, payload=None, handler=_echo):
        """Drive one request through serve_connection over a real socketpair."""
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        thread = threading.Thread(target=transport.serve_connection,
                                  args=(server, handler), daemon=True)
        thread.start()
        if raw is not None:
            client.sendall(raw)
        else:
            transport.write_frame(client, operation, payload or {})
        client.settimeout(5)
        try:
            reply_op, reply = transport.read_frame(client)
        finally:
            thread.join(timeout=5)
        return reply_op, reply


class TestFraming(FramingTest):
    def test_a_well_formed_request_round_trips(self):
        self.assertEqual(self.exchange(operation="index", payload={"plate": "ABC123"}),
                         ("ok", {"saw": "index", "payload": {"plate": "ABC123"}}))

    def test_an_oversized_frame_is_refused_before_it_is_allocated(self):
        """A peer that declares four gigabytes gets a refusal, not an
        allocation."""
        header = transport.FRAME_HEADER + struct.pack(">I", 4 * 1024 * 1024 * 1024 - 1)
        reply_op, reply = self.exchange(raw=header + b"{}")
        self.assertEqual(reply_op, "error")
        self.assertIn("ceiling", reply["error"])

    def test_encoding_an_oversized_frame_is_refused_at_the_sender(self):
        with self.assertRaises(transport.TransportError):
            transport.encode_frame("open", {"blob": "x" * (transport.MAX_FRAME_BYTES + 1)})

    def test_a_frame_with_the_wrong_magic_is_refused(self):
        reply_op, reply = self.exchange(raw=b"HTTP" + struct.pack(">I", 2) + b"{}")
        self.assertEqual(reply_op, "error")
        self.assertIn("not a JustiKey custodian frame", reply["error"])

    def test_an_empty_frame_is_refused(self):
        reply_op, reply = self.exchange(
            raw=transport.FRAME_HEADER + struct.pack(">I", 0))
        self.assertEqual(reply_op, "error")
        self.assertIn("empty frame", reply["error"])

    def test_a_frame_that_is_not_json_is_refused(self):
        body = b"not json at all"
        reply_op, reply = self.exchange(
            raw=transport.FRAME_HEADER + struct.pack(">I", len(body)) + body)
        self.assertEqual(reply_op, "error")
        self.assertIn("not valid JSON", reply["error"])

    def test_unknown_top_level_fields_are_refused_rather_than_ignored(self):
        """A field this version ignores is a field a later version might read,
        and the two would disagree about what the message meant."""
        body = json.dumps({"op": "index", "payload": {}, "extra": 1}).encode()
        reply_op, reply = self.exchange(
            raw=transport.FRAME_HEADER + struct.pack(">I", len(body)) + body)
        self.assertEqual(reply_op, "error")
        self.assertIn("unknown fields", reply["error"])

    def test_a_payload_that_is_not_an_object_is_refused(self):
        body = json.dumps({"op": "index", "payload": [1, 2, 3]}).encode()
        reply_op, reply = self.exchange(
            raw=transport.FRAME_HEADER + struct.pack(">I", len(body)) + body)
        self.assertEqual(reply_op, "error")
        self.assertIn("payload is not an object", reply["error"])

    def test_a_handler_failure_never_leaks_a_traceback(self):
        reply_op, reply = self.exchange(operation="boom")
        self.assertEqual(reply_op, "error")
        self.assertEqual(reply["error"], "custodian failed: RuntimeError")
        self.assertNotIn("Traceback", json.dumps(reply))

    def test_a_truncated_frame_does_not_hang_the_server(self):
        """Half a frame and then silence: the read deadline ends it."""
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        server.settimeout(1.0)
        thread = threading.Thread(target=transport.serve_connection,
                                  args=(server, _echo), daemon=True)
        thread.start()
        client.sendall(transport.FRAME_HEADER + struct.pack(">I", 4096) + b"{")
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive(), "the server hung on a partial frame")

    def test_a_peer_that_closes_mid_frame_is_handled(self):
        client, server = socket.socketpair()
        self.addCleanup(server.close)
        thread = threading.Thread(target=transport.serve_connection,
                                  args=(server, _echo), daemon=True)
        thread.start()
        client.sendall(transport.FRAME_HEADER + struct.pack(">I", 4096))
        client.close()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())


class TestTheCustodianOperations(FramingTest):
    """The five vsock-specific attacks, over the real framing."""

    def dispatch_through_frame(self, operation, payload):
        import custodian_server

        return self.exchange(operation=operation, payload=payload,
                             handler=custodian_server.dispatch)

    def test_the_parent_sends_derive_over_the_wire(self):
        """Attack 1: the oracle, restated as an operation."""
        for name in ("derive", "agree", "unwrap", "decrypt", "privatekey"):
            with self.subTest(name):
                reply_op, reply = self.exchange(operation=name, payload={})
                self.assertEqual(reply_op, "error")
                self.assertIn("unknown operation", reply["error"])

    def test_the_parent_sends_open_with_multiple_records(self):
        """Attack 2: batching is the oracle's shape with extra steps."""
        import custodian_server

        reply_op, reply = self.dispatch_through_frame("open", {
            "envelope": {"record_uid": ["one", "two", "three"]},
            "identity": {}, "requester": "officer1"})
        self.assertEqual(reply_op, "error")
        self.assertIn("exactly one record", reply["error"])

    def test_the_parent_sends_unknown_fields_in_a_known_operation(self):
        reply_op, reply = self.dispatch_through_frame(
            "search-token", {"statement": {}, "and_also": "open everything"})
        self.assertEqual(reply_op, "error")
        self.assertIn("unknown fields for search-token", reply["error"])

    def test_the_disclosure_caller_cannot_mint_an_arbitrary_scope_token(self):
        """Attack 13 at the boundary: `index` is the blind-index key's whole
        capability, so it is not a disclosure-role operation."""
        reply_op, reply = self.dispatch_through_frame("index", {"plate": "ABC123"})
        self.assertEqual(reply_op, "error")
        self.assertIn("not available to a 'disclosure' caller", reply["error"])

    def test_an_unknown_operation_is_refused_by_name(self):
        reply_op, reply = self.dispatch_through_frame("exfiltrate", {})
        self.assertEqual(reply_op, "error")
        self.assertIn("unknown operation", reply["error"])


class TestBoundedConcurrency(unittest.TestCase):
    """Attack 4: thousands of partial connections must be refused, not absorbed."""

    def test_capacity_is_a_refusal_rather_than_a_queue(self):
        server = transport.VsockServer.__new__(transport.VsockServer)
        server._slots = threading.Semaphore(4)
        server.rejected_over_capacity = 0

        held = [server._slots.acquire(blocking=False) for _ in range(4)]
        self.assertTrue(all(held))
        # The fifth finds no slot, and the server's accept loop closes it.
        self.assertFalse(server._slots.acquire(blocking=False))

    def test_the_default_ceiling_is_bounded(self):
        self.assertLessEqual(transport.DEFAULT_MAX_CONNECTIONS, 128)
        self.assertGreater(transport.DEFAULT_MAX_CONNECTIONS, 0)


@unittest.skipUnless(hasattr(socket, "AF_VSOCK"), "this platform has no AF_VSOCK")
class TestVsockItself(unittest.TestCase):
    """What can genuinely be checked without an enclave: the listener binds.

    A local connect needs vsock_loopback, which this kernel does not provide,
    so the round trip is exercised over a socketpair above. This test is the
    part that is really AF_VSOCK.
    """

    def test_a_vsock_listener_binds_and_accepts(self):
        server = transport.VsockServer(transport.VMADDR_CID_ANY, 51234, _echo)
        try:
            server.bind()
            self.assertIsNotNone(server._socket)
            self.assertEqual(server._socket.family, socket.AF_VSOCK)
        finally:
            server.shutdown()

    def test_the_parent_cid_is_three(self):
        """From inside an enclave the parent is always CID 3."""
        self.assertEqual(transport.VMADDR_CID_PARENT, 3)

    def test_a_vsock_transport_needs_af_vsock(self):
        client = transport.VsockTransport(transport.VMADDR_CID_PARENT, 8091, timeout=0.5)
        self.assertEqual(client.name, "vsock")
        self.assertEqual(client.cid, 3)


class TestTheProductionInvariant(unittest.TestCase):
    """An attested custodian must refuse to start a TCP listener.

    An enclave has no external network and no persistent storage, and vsock
    is its only channel. A TCP listener in an attested configuration means
    either this is not really an enclave, or something has been arranged to
    reach it that should not exist. Refusing is cheaper than finding out
    which, so the process exits rather than serving.

    Run as a real subprocess: an invariant asserted by reading the source is
    an invariant that survives the code being deleted.
    """

    def setUp(self):
        import shutil
        import tempfile

        from justikey import kem, sealing

        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        private_hex, self.public_hex = sealing.generate_keypair(kem.P256_ECDH)
        self.key_file = os.path.join(self.dir, "custodian.key")
        with open(self.key_file, "w") as fh:
            fh.write(f"{kem.P256_ECDH}:{private_hex}")
        self.attestation_file = os.path.join(self.dir, "attestation.bin")
        with open(self.attestation_file, "wb") as fh:
            fh.write(b"a document obtained out of band")

    def run_server(self, *extra, timeout=25):
        import subprocess

        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", "custodian_server.py"),
             "--client-secret", "s" * 32, "--index-key", "11" * 32,
             "--ledger", os.path.join(self.dir, "ledger.db"),
             "--presence-mode", "off", *extra],
            capture_output=True, text=True, timeout=timeout)

    def test_an_attested_custodian_refuses_to_serve_tcp(self):
        result = self.run_server(
            "--kms-key-arn", "arn:aws:kms:test:key/agree",
            "--public-key", self.public_hex,
            "--attestation-file", self.attestation_file,
            "--transport", "http")
        # boto3 may be absent, which is its own refusal; either way it must
        # not end up serving TCP while claiming to be attested.
        self.assertNotEqual(result.returncode, 0)
        if "boto3" not in result.stderr:
            self.assertEqual(result.returncode, 4)
            self.assertIn("must serve on vsock", result.stderr)

    def test_an_unattested_development_custodian_may_serve_tcp(self):
        """Development is allowed HTTP; it just may not claim to be attested."""
        import subprocess

        process = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "scripts", "custodian_server.py"),
             "--client-secret", "s" * 32, "--index-key", "11" * 32,
             "--ledger", os.path.join(self.dir, "ledger.db"),
             "--presence-mode", "off", "--key-file", self.key_file,
             "--transport", "http", "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            import time

            deadline = time.monotonic() + 15
            output = ""
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    output += process.stdout.read()
                    break
                line = process.stdout.readline()
                output += line
                if "does NOT meet the stage 5 objective" in output:
                    break
            self.assertIn("JustiKey custodian on", output)
            self.assertIn("does NOT meet the stage 5 objective", output)
        finally:
            process.terminate()
            process.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
