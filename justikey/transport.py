"""Framing for the custodian boundary: HTTP in development, vsock in production.

Stage 5 of docs/capability-model.md.

WHAT THIS LAYER IS FOR, AND WHAT IT IS NOT FOR

On AWS Nitro, vsock is the only channel between an enclave and its parent,
and the enclave has no external network and no persistent storage. That is a
genuine isolation property and it is worth having.

It is not an authorization property, and the distinction matters enough to
state twice. Once the parent is inside the threat model -- which it is, it
runs the disclosure service -- the parent holds whatever transport credential
the parent holds. A shared secret proves the caller is the parent; the parent
is the adversary. The CID proves which side of the socket someone is on;
being on that side is not permission to read a plate.

So the authorization remains, entirely and only:

    approver signature + requester presence + scope + registry versions
    + nonce and cap state + record identity

verified by the custodian, against its own copies. This module provides
framing, limits and isolation. It authorizes nothing, and nothing downstream
should read a successful frame as evidence of anything but a well-formed
message having arrived.

WHERE THE CUSTODIAN IS NOT ON THE SAME HOST

The original deployment put the disclosure service and the custodian on one
machine: the service on the parent instance, the custodian in its enclave,
vsock between them. Nothing left the host, so plain HTTP to 127.0.0.1 was an
honest development convenience.

An on-premises appliance talking to an enclave in a cloud account is a
different shape. `Custodian.open` returns the opened record's fields, so the
reply to a successful disclosure is plate data in transit. A transport that
will happily send that in clear text because the URL happened to say `http`
is not a development convenience, it is a silent downgrade.

So the scheme is now load-bearing in one more way: `http://` is accepted only
for a loopback address, and refused for anything else. There is no override.
A deployment that cannot present a certificate is a deployment that is not
ready to carry disclosures, and failing at startup is the cheap version of
finding that out.

`TlsPolicy` carries the rest: a private CA, an SPKI pin, and a client
certificate for mutual TLS. All three are optional and all three are
verified when present -- the pin in addition to ordinary chain validation,
never instead of it.

WHAT FRAMING STILL HAS TO GET RIGHT

A byte stream with no length discipline is a denial-of-service surface and a
request-smuggling surface. So: an explicit length prefix, a hard ceiling
checked before allocation, a read deadline, a bounded number of concurrent
connections, and a strict schema with unknown fields refused rather than
ignored -- because a field the server ignores is a field a future version
might start reading, and the two versions will disagree about what the
message meant.
"""
import hashlib
import hmac
import json
import socket
import struct
import threading

MAX_FRAME_BYTES = 1 * 1024 * 1024
FRAME_HEADER = b"JKC1"
HEADER_LENGTH = len(FRAME_HEADER) + 4
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_CONNECTIONS = 32

# AF_VSOCK well-known context identifiers. The parent instance is always 3
# from inside an enclave; an enclave gets its own CID at launch.
VMADDR_CID_ANY = 0xFFFFFFFF
VMADDR_CID_HOST = 2
VMADDR_CID_PARENT = 3


class TransportError(RuntimeError):
    """A frame was malformed, oversized, or the peer went away."""


# ---------------------------------------------------------------------------
# Frames
# ---------------------------------------------------------------------------

def encode_frame(operation, payload):
    body = json.dumps({"op": operation, "payload": payload},
                      separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME_BYTES:
        raise TransportError(
            f"frame is {len(body)} bytes, over the {MAX_FRAME_BYTES} ceiling")
    return FRAME_HEADER + struct.pack(">I", len(body)) + body


def _read_exactly(sock, count, deadline_error="peer closed mid-frame"):
    chunks, remaining = [], count
    while remaining:
        chunk = sock.recv(min(remaining, 65536))
        if not chunk:
            raise TransportError(deadline_error)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(sock):
    """One frame, or raise. The length is checked BEFORE anything is read.

    Reading the declared length first and allocating second is the whole
    point: a peer that claims four gigabytes gets a refusal, not an
    allocation.
    """
    header = _read_exactly(sock, HEADER_LENGTH, "peer closed before sending a frame")
    if header[:len(FRAME_HEADER)] != FRAME_HEADER:
        raise TransportError("not a JustiKey custodian frame")
    (length,) = struct.unpack(">I", header[len(FRAME_HEADER):])
    if length == 0:
        raise TransportError("empty frame")
    if length > MAX_FRAME_BYTES:
        raise TransportError(
            f"frame declares {length} bytes, over the {MAX_FRAME_BYTES} ceiling")
    body = _read_exactly(sock, length)
    try:
        message = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise TransportError(f"frame is not valid JSON: {exc}") from exc
    if not isinstance(message, dict):
        raise TransportError("frame is not an object")
    unknown = set(message) - {"op", "payload"}
    if unknown:
        raise TransportError(f"frame carries unknown fields: {sorted(unknown)}")
    operation = message.get("op")
    if not isinstance(operation, str):
        raise TransportError("frame names no operation")
    payload = message.get("payload")
    if payload is not None and not isinstance(payload, dict):
        raise TransportError("frame payload is not an object")
    return operation, payload or {}


def write_frame(sock, operation, payload):
    sock.sendall(encode_frame(operation, payload))


# ---------------------------------------------------------------------------
# Client transports
# ---------------------------------------------------------------------------

class VsockTransport:
    """Talks to a custodian over AF_VSOCK.

    One connection per request rather than a pool: the custodian is called
    once per record, connections are cheap on vsock, and a pooled connection
    is state shared between requests that are meant to be independent.
    """

    name = "vsock"

    def __init__(self, cid, port, timeout=None):
        if not hasattr(socket, "AF_VSOCK"):
            raise TransportError(
                "this platform has no AF_VSOCK; vsock is Linux-only and is the "
                "channel a Nitro enclave uses to reach its parent")
        self.cid = int(cid)
        self.port = int(port)
        self.timeout = timeout or DEFAULT_TIMEOUT_SECONDS

    def request(self, operation, payload):
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.cid, self.port))
            write_frame(sock, operation, payload)
            reply_op, reply = read_frame(sock)
        except TransportError:
            raise
        except OSError as exc:
            raise TransportError(
                f"custodian unreachable on vsock {self.cid}:{self.port}: {exc}") from exc
        finally:
            sock.close()
        if reply_op == "error":
            return reply, reply.get("status", 500)
        return reply, 200


def for_url(url, client_id=None, client_secret=None, timeout=None, tls=None):
    """Pick a transport from the URL scheme.

        vsock://16:8091          the enclave at CID 16, port 8091
        https://host:8091        a custodian reached over a network
        http://127.0.0.1:8091    development, loopback only

    The scheme is the whole configuration difference between a development
    deployment and a Nitro one, deliberately: nothing above this line should
    have to know which it is talking to.

    It is also the confidentiality decision. `http://` to anything but a
    loopback address is refused here rather than downgraded, because the
    reply to a successful `open` carries the plate record in clear.
    """
    text = (url or "").strip()
    if text.startswith("vsock://"):
        location = text[len("vsock://"):].strip("/")
        cid, _, port = location.partition(":")
        if not cid or not port:
            raise TransportError(
                f"malformed vsock address {url!r}; expected vsock://<cid>:<port>")
        try:
            return VsockTransport(int(cid), int(port), timeout)
        except ValueError as exc:
            raise TransportError(
                f"malformed vsock address {url!r}: {exc}") from exc
    if text.startswith(("http://", "https://")):
        return HttpTransport(text, client_id, client_secret, timeout, tls=tls)
    raise TransportError(
        f"unsupported custodian scheme in {url!r}; expected vsock://, https://, "
        "or http:// to a loopback address")


class TlsPolicy:
    """How the client authenticates the custodian endpoint, and itself.

    Three independent settings, all optional, all additive:

      ca_file      trust this CA instead of the system store, for a private
                   CA in front of the parent relay
      spki_pin     sha256 over the peer certificate's DER SubjectPublicKeyInfo,
                   hex. Checked *in addition to* chain validation, never
                   instead of it, and checked before the request body is
                   written so a wrong peer never sees the approval
      client_cert  mutual TLS: prove which appliance is calling
      client_key

    The pin is over the SPKI rather than the whole certificate so that
    renewing a certificate for the same key does not require reconfiguring
    every appliance. Pinning the enclave's own attested key -- so that the
    only peer that can answer is one whose attestation document names that
    key -- is the eventual form of this, and is not built.
    """

    def __init__(self, ca_file=None, spki_pin=None,
                 client_cert=None, client_key=None):
        self.ca_file = ca_file or None
        self.spki_pin = (spki_pin or "").strip().lower() or None
        self.client_cert = client_cert or None
        self.client_key = client_key or None
        if self.client_key and not self.client_cert:
            raise TransportError(
                "a TLS client key was configured without a client certificate")

    @classmethod
    def from_config(cls):
        from . import config

        return cls(ca_file=config.CUSTODIAN_TLS_CA,
                   spki_pin=config.CUSTODIAN_TLS_PIN,
                   client_cert=config.CUSTODIAN_TLS_CLIENT_CERT,
                   client_key=config.CUSTODIAN_TLS_CLIENT_KEY)

    @property
    def configured(self):
        return bool(self.ca_file or self.spki_pin or self.client_cert)

    def context(self):
        import ssl

        try:
            ctx = ssl.create_default_context(cafile=self.ca_file)
        except OSError as exc:
            raise TransportError(
                f"TLS CA file {self.ca_file!r} is unreadable: {exc}") from exc
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        if self.client_cert:
            try:
                ctx.load_cert_chain(self.client_cert, self.client_key)
            except OSError as exc:
                raise TransportError(
                    f"TLS client certificate is unusable: {exc}") from exc
        return ctx

    def check_pin(self, sock):
        """Compare the peer's public key against the pin, or do nothing.

        Called after the handshake and before anything is sent. A mismatch
        is a TransportError, not a warning: the alternative is handing a
        signed approval to whoever answered.
        """
        if not self.spki_pin:
            return
        der = sock.getpeercert(binary_form=True) if sock is not None else None
        if not der:
            raise TransportError("a pin is configured but the peer sent no certificate")
        if not hmac.compare_digest(spki_digest(der), self.spki_pin):
            raise TransportError(
                "the custodian endpoint's public key does not match the "
                "configured pin; refusing to send the request")


def spki_digest(certificate_der):
    """sha256 over a certificate's DER SubjectPublicKeyInfo, hex."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
    except Exception as exc:  # noqa: BLE001 - any parse failure means "do not trust"
        raise TransportError(f"the peer certificate did not parse: {exc!r}") from exc
    spki = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def is_loopback(host):
    """True for a host that cannot leave the machine."""
    import ipaddress

    name = (host or "").strip().strip("[]").lower()
    if name in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


class HttpTransport:
    """Talks to a custodian over HTTP.

    Loopback keeps plain HTTP, because that is the development and
    process-test arrangement and nothing crosses a wire. Every other host
    must be https, and the refusal happens in the constructor so a
    misconfigured deployment fails at startup rather than on the first
    disclosure.
    """

    name = "http"

    def __init__(self, url, client_id, client_secret, timeout=None, tls=None):
        from urllib.parse import urlsplit

        from . import config

        self.url = (url or "").rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        parts = urlsplit(self.url)
        self.scheme = parts.scheme
        self.host = parts.hostname
        self.path = parts.path or ""
        if not self.host:
            raise TransportError(f"no host in custodian URL {url!r}")
        self.port = parts.port or (443 if self.scheme == "https" else 80)
        self.local = is_loopback(self.host)

        if self.scheme == "http" and not self.local:
            raise TransportError(
                f"refusing a plaintext custodian URL to {self.host!r}: an open "
                "record is returned over this connection. Use https://, or "
                "vsock:// when the custodian is an enclave on this host.")

        if not client_secret:
            raise TransportError(
                f"no client secret for the custodian at {self.host!r}; an HTTP "
                "transport signs every request, so this fails now rather than "
                "inside the first handler thread that tries")

        self.tls = tls if tls is not None else TlsPolicy.from_config()
        if self.scheme == "http" and self.tls.configured:
            raise TransportError(
                "TLS material is configured but the custodian URL is http://; "
                "one of the two is wrong")
        self.timeout = timeout or config.DISCLOSURE_TIMEOUT_SECONDS

    def _connect(self):
        import http.client

        if self.scheme == "https":
            connection = http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout,
                context=self.tls.context())
        else:
            connection = http.client.HTTPConnection(
                self.host, self.port, timeout=self.timeout)
        connection.connect()
        if self.scheme == "https":
            try:
                self.tls.check_pin(connection.sock)
            except TransportError:
                connection.close()
                raise
        return connection

    def request(self, operation, payload):
        import http.client
        import secrets

        from . import servicekit, timeutil

        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        timestamp, nonce = timeutil.now_iso(), secrets.token_urlsafe(16)
        headers = {
            "Content-Type": "application/json",
            "X-JustiKey-Client-Id": self.client_id,
            "X-JustiKey-Timestamp": timestamp,
            "X-JustiKey-Nonce": nonce,
            "X-JustiKey-Signature": servicekit.request_signature(
                self.client_secret, timestamp, nonce, body),
        }
        try:
            connection = self._connect()
        except TransportError:
            raise
        except (OSError, ValueError) as exc:
            raise TransportError(f"custodian unreachable: {exc!r}") from exc

        try:
            connection.request("POST", f"{self.path}/{operation}",
                               body=body, headers=headers)
            response = connection.getresponse()
            status = response.status
            raw = response.read(MAX_FRAME_BYTES + 1)
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise TransportError(f"custodian unreachable: {exc!r}") from exc
        finally:
            connection.close()

        if len(raw) > MAX_FRAME_BYTES:
            raise TransportError(
                f"custodian response exceeds {MAX_FRAME_BYTES} bytes")
        try:
            return json.loads(raw.decode("utf-8")), status
        except (ValueError, UnicodeDecodeError):
            return {"error": f"custodian returned {status}"}, status


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class VsockServer:
    """Serves framed requests on AF_VSOCK.

    Concurrency is bounded by a semaphore rather than by whatever the kernel
    backlog allows: an enclave has a fixed memory allocation, and a parent
    that opens ten thousand half-finished connections should be refused
    rather than absorbed.
    """

    def __init__(self, cid, port, handler, max_connections=None, timeout=None):
        if not hasattr(socket, "AF_VSOCK"):
            raise TransportError("this platform has no AF_VSOCK")
        self.cid = int(cid)
        self.port = int(port)
        self.handler = handler
        self.timeout = timeout or DEFAULT_TIMEOUT_SECONDS
        self.max_connections = max_connections or DEFAULT_MAX_CONNECTIONS
        self._slots = threading.Semaphore(self.max_connections)
        self._socket = None
        self._stop = threading.Event()
        self.rejected_over_capacity = 0

    def bind(self):
        self._socket = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.cid, self.port))
        self._socket.listen(self.max_connections)
        return self

    def serve_forever(self):
        if self._socket is None:
            self.bind()
        while not self._stop.is_set():
            try:
                conn, _ = self._socket.accept()
            except OSError:
                if self._stop.is_set():
                    break
                continue
            if not self._slots.acquire(blocking=False):
                # Refuse loudly and immediately rather than queueing. A
                # request that cannot be served now will not be served better
                # by being held open.
                self.rejected_over_capacity += 1
                try:
                    conn.close()
                finally:
                    continue
            threading.Thread(target=self._serve_one, args=(conn,), daemon=True).start()

    def _serve_one(self, conn):
        try:
            conn.settimeout(self.timeout)
            serve_connection(conn, self.handler)
        finally:
            try:
                conn.close()
            finally:
                self._slots.release()

    def shutdown(self):
        self._stop.set()
        if self._socket is not None:
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._socket.close()


def serve_connection(sock, handler):
    """Read one frame, dispatch it, write one reply.

    One request per connection, deliberately. Keep-alive would mean tracking
    per-connection state across requests that the custodian treats as
    independent, and the saving does not buy anything on a local socket.
    """
    try:
        operation, payload = read_frame(sock)
    except TransportError as exc:
        try:
            write_frame(sock, "error", {"error": str(exc), "status": 400})
        except OSError:
            pass
        return
    except socket.timeout:
        return

    try:
        reply, status = handler(operation, payload)
    except Exception as exc:  # noqa: BLE001 - never leak a traceback to the peer
        reply, status = {"error": f"custodian failed: {type(exc).__name__}"}, 500
    if status == 200:
        write_frame(sock, "ok", reply)
    else:
        write_frame(sock, "error", dict(reply, status=status))
