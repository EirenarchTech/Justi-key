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

WHAT FRAMING STILL HAS TO GET RIGHT

A byte stream with no length discipline is a denial-of-service surface and a
request-smuggling surface. So: an explicit length prefix, a hard ceiling
checked before allocation, a read deadline, a bounded number of concurrent
connections, and a strict schema with unknown fields refused rather than
ignored -- because a field the server ignores is a field a future version
might start reading, and the two versions will disagree about what the
message meant.
"""
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


class HttpTransport:
    """Talks to a custodian over HTTP. Development and process tests."""

    name = "http"

    def __init__(self, url, client_id, client_secret, timeout=None):
        from . import config

        self.url = url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout or config.DISCLOSURE_TIMEOUT_SECONDS

    def request(self, operation, payload):
        import secrets
        from urllib import error, request as urlrequest

        from . import servicekit, timeutil

        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        timestamp, nonce = timeutil.now_iso(), secrets.token_urlsafe(16)
        req = urlrequest.Request(f"{self.url}/{operation}", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-JustiKey-Client-Id", self.client_id)
        req.add_header("X-JustiKey-Timestamp", timestamp)
        req.add_header("X-JustiKey-Nonce", nonce)
        req.add_header("X-JustiKey-Signature",
                       servicekit.request_signature(self.client_secret, timestamp,
                                                    nonce, body))
        try:
            with urlrequest.urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8")), response.status
        except error.HTTPError as exc:
            try:
                return json.loads(exc.read().decode("utf-8")), exc.code
            except (ValueError, UnicodeDecodeError):
                return {"error": f"custodian returned {exc.code}"}, exc.code
        except (error.URLError, OSError, ValueError) as exc:
            raise TransportError(f"custodian unreachable: {exc!r}") from exc


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
