"""The custodian is not always on this host.

An on-premises appliance talking to an enclave in a cloud account sends a
signed approval out and gets an opened plate record back. These tests are
about the transport refusing to carry that in clear, and about proving it is
talking to the endpoint it was configured for rather than to whoever
answered.
"""
import datetime
import http.server
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from justikey import transport


def _issue(common_name, issuer=None, issuer_key=None, ca=False):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(issuer.subject if issuer is not None else subject)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                              critical=True))
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
    certificate = builder.sign(issuer_key or key, hashes.SHA256())
    return key, certificate


def _write(directory, name, key=None, certificate=None):
    path = os.path.join(directory, name)
    with open(path, "wb") as handle:
        if certificate is not None:
            handle.write(certificate.public_bytes(serialization.Encoding.PEM))
        if key is not None:
            handle.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
    return path


class _Handler(http.server.BaseHTTPRequestHandler):
    received = []

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).received.append((self.path, body))
        payload = json.dumps({"ok": True, "path": self.path}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        pass


class TestPlaintextIsRefusedOffHost(unittest.TestCase):
    """`Custodian.open` returns the record's fields. That reply must not
    cross a network in clear because a URL said http."""

    def test_http_to_a_remote_host_is_refused(self):
        for url in ("http://custodian.example:8091",
                    "http://10.0.0.5:8091",
                    "http://[2001:db8::1]:8091"):
            with self.subTest(url):
                with self.assertRaises(transport.TransportError) as caught:
                    transport.for_url(url, "app", "secret", tls=transport.TlsPolicy())
                self.assertIn("plaintext", str(caught.exception))

    def test_http_to_loopback_is_still_allowed(self):
        for url in ("http://127.0.0.1:8091", "http://localhost:8091",
                    "http://[::1]:8091"):
            with self.subTest(url):
                chosen = transport.for_url(url, "app", "secret",
                                           tls=transport.TlsPolicy())
                self.assertEqual(chosen.name, "http")
                self.assertTrue(chosen.local)

    def test_https_to_a_remote_host_is_allowed(self):
        chosen = transport.for_url("https://custodian.example:8091", "app", "secret",
                                   tls=transport.TlsPolicy())
        self.assertEqual(chosen.port, 8091)
        self.assertFalse(chosen.local)

    def test_an_unknown_scheme_is_refused_rather_than_assumed_to_be_http(self):
        for url in ("ftp://host/x", "custodian.example:8091", "", "://"):
            with self.subTest(url):
                with self.assertRaises(transport.TransportError):
                    transport.for_url(url, "app", "secret",
                                      tls=transport.TlsPolicy())

    def test_tls_material_with_an_http_url_is_a_configuration_error(self):
        policy = transport.TlsPolicy(spki_pin="ab" * 32)
        with self.assertRaises(transport.TransportError) as caught:
            transport.for_url("http://127.0.0.1:8091", "app", "secret", tls=policy)
        self.assertIn("one of the two is wrong", str(caught.exception))

    def test_a_client_key_without_a_certificate_is_refused(self):
        with self.assertRaises(transport.TransportError):
            transport.TlsPolicy(client_key="/tmp/key.pem")


class TestPinnedServiceIdentity(unittest.TestCase):
    """Chain validation says the peer holds a certificate some CA signed.
    The pin says it holds the key this deployment was told to expect."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.mkdtemp()
        ca_key, ca_certificate = _issue("justikey-test-ca", ca=True)
        server_key, server_certificate = _issue(
            "localhost", issuer=ca_certificate, issuer_key=ca_key)
        cls.ca_file = _write(cls.directory, "ca.pem", certificate=ca_certificate)
        cls.server_file = _write(cls.directory, "server.pem",
                                 key=server_key, certificate=server_certificate)
        cls.pin = transport.spki_digest(
            server_certificate.public_bytes(serialization.Encoding.DER))

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.server_file)
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _Handler.received = []

    def _client(self, **policy):
        return transport.for_url(
            f"https://localhost:{self.port}", "disclosure", "secret",
            tls=transport.TlsPolicy(ca_file=self.ca_file, **policy))

    def test_a_matching_pin_completes_the_request(self):
        body, status = self._client(spki_pin=self.pin).request("open", {"a": 1})
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["path"], "/open")

    def test_the_pin_is_case_insensitive(self):
        _body, status = self._client(spki_pin=self.pin.upper()).request("open", {})
        self.assertEqual(status, 200)

    def test_a_wrong_pin_refuses_before_the_request_is_sent(self):
        client = self._client(spki_pin="cd" * 32)
        with self.assertRaises(transport.TransportError) as caught:
            client.request("open", {"statement": "signed approval"})
        self.assertIn("does not match the configured pin", str(caught.exception))
        self.assertEqual(_Handler.received, [],
                         "the approval reached a peer that failed the pin")

    def test_an_untrusted_chain_is_refused_even_with_the_right_pin(self):
        """The pin is additional to chain validation, not a replacement."""
        client = transport.for_url(
            f"https://localhost:{self.port}", "disclosure", "secret",
            tls=transport.TlsPolicy(spki_pin=self.pin))   # no CA -> system store
        with self.assertRaises(transport.TransportError):
            client.request("open", {})
        self.assertEqual(_Handler.received, [])

    def test_the_request_carries_the_authentication_headers(self):
        self._client(spki_pin=self.pin).request("search-token", {"x": 2})
        path, body = _Handler.received[0]
        self.assertEqual(path, "/search-token")
        self.assertEqual(json.loads(body.decode("utf-8")), {"x": 2})

    def test_an_unreachable_endpoint_raises_transport_error(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            dead = probe.getsockname()[1]
        client = transport.for_url(f"https://localhost:{dead}", "d", "s",
                                   tls=transport.TlsPolicy(ca_file=self.ca_file))
        with self.assertRaises(transport.TransportError):
            client.request("open", {})


class TestSpkiDigest(unittest.TestCase):

    def test_the_pin_follows_the_key_not_the_certificate(self):
        """Renewing a certificate for the same key keeps the pin valid --
        which is the reason it is over the SubjectPublicKeyInfo."""
        key = ec.generate_private_key(ec.SECP256R1())
        digests = set()
        for common_name in ("first.example", "second.example"):
            now = datetime.datetime.now(datetime.timezone.utc)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
            certificate = (x509.CertificateBuilder()
                           .subject_name(name).issuer_name(name)
                           .public_key(key.public_key())
                           .serial_number(x509.random_serial_number())
                           .not_valid_before(now - datetime.timedelta(minutes=5))
                           .not_valid_after(now + datetime.timedelta(days=1))
                           .sign(key, hashes.SHA256()))
            digests.add(transport.spki_digest(
                certificate.public_bytes(serialization.Encoding.DER)))
        self.assertEqual(len(digests), 1)

    def test_a_certificate_that_does_not_parse_is_refused(self):
        with self.assertRaises(transport.TransportError):
            transport.spki_digest(b"not a certificate")


if __name__ == "__main__":
    unittest.main()
