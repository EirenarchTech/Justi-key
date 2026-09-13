"""Plumbing shared by the disclosure service and the custodian.

Both are small HTTP services in their own trust domain, and both need the
same four things: authenticate the caller, refuse a replayed request, keep an
append-only ledger of what they decided, and admit their registries only when
version and digest account for themselves.

Extracted rather than copied. Two copies of an authentication routine is how
one of them quietly loses a check -- and the check most likely to be lost is
the one added last, which here is transport-nonce spending.
"""
import hashlib
import hmac
import json

from . import audit, db, registry, timeutil

MAX_BODY_BYTES = 8 * 1024 * 1024
CLOCK_SKEW_SECONDS = 300

# Ledger plus the state a key-holding service owns rather than trusts. Both
# services keep all of it: the custodian because it is authoritative, the
# disclosure service because it may be running without a custodian.
SERVICE_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seq INTEGER UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    details TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS authorization_usage (
    nonce TEXT PRIMARY KEY,
    authorization_id INTEGER,
    disclosure_count INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL,
    first_used_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_authorization_usage_expiry ON authorization_usage(expires_at);

CREATE TABLE IF NOT EXISTS webauthn_counters (
    credential_id TEXT PRIMARY KEY,
    sign_count INTEGER NOT NULL,
    last_used_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS presence_nonces (
    nonce TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL,
    used_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_presence_nonces_expiry ON presence_nonces(expires_at);

CREATE TABLE IF NOT EXISTS transport_nonces (
    nonce TEXT PRIMARY KEY,
    seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transport_nonces_seen ON transport_nonces(seen_at);
"""


def request_signature(secret, timestamp, nonce, body):
    """Authenticate one service to another.

    Subordinate to the approver's signature: this establishes only that the
    caller is the known peer, so an arbitrary host cannot make the service
    work through its key. The approval is what authorizes an opening.
    """
    digest = hashlib.sha256(body or b"").hexdigest()
    base = f"{timestamp}\n{nonce}\n{digest}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()


def init_ledger(path):
    conn = db.get_connection(path)
    try:
        conn.executescript(SERVICE_SCHEMA)
    finally:
        conn.close()


def get_meta(conn, key):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def set_meta(conn, key, value):
    conn.execute("INSERT INTO meta (key, value) VALUES (?,?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


def read_registry_file(path):
    with open(path, "r") as fh:
        return json.load(fh)


def parse_registry(data, role):
    """Validate enrolment entries. A malformed one is a refusal, not a skip."""
    parsed = {}
    for username, entry in data.items():
        if not isinstance(entry, dict) or "public_key" not in entry:
            raise ValueError(f"{role} {username!r} needs a public_key")
        record_entry = {"public_key": entry["public_key"],
                        "revoked": bool(entry.get("revoked"))}
        hardware = entry.get("webauthn")
        if hardware:
            for field in ("credential_id", "public_key"):
                if not hardware.get(field):
                    raise ValueError(
                        f"{role} {username!r}: webauthn enrolment needs {field}")
            record_entry["webauthn"] = dict(hardware)
        parsed[username] = record_entry
    return parsed


def admit_registry(ledger, role, path):
    """Load a registry and refuse it if it rolled back or was swapped.

    Called at startup, before the service answers anything. A registry that
    cannot be admitted is a configuration failure, not a degraded mode:
    continuing would mean answering requests against keys whose provenance the
    service has just discovered it cannot account for.
    """
    version, principals = (registry.unwrap(read_registry_file(path)) if path
                           else (0, {}))
    conn = db.get_connection(ledger)
    try:
        recorded = get_meta(conn, registry.REGISTRY_VERSION_KEY % role)
        last_version = int(recorded) if recorded is not None else None
        last_digest = get_meta(conn, registry.REGISTRY_DIGEST_KEY % role)
        status, detail = registry.check(role, version, principals,
                                        last_version, last_digest)
        if status != "unchanged":
            set_meta(conn, registry.REGISTRY_VERSION_KEY % role, version)
            set_meta(conn, registry.REGISTRY_DIGEST_KEY % role, detail["digest"])
        return parse_registry(principals, role), status, detail
    finally:
        conn.close()


class LedgerWriter:
    """Serialized appends to one service's own hash chain.

    audit.append_event already wraps each append in BEGIN IMMEDIATE, which
    holds across processes; the lock removes in-process contention too, so
    concurrent decisions cannot interleave into a forked chain.
    """

    def __init__(self, path):
        import threading

        self.path = path
        self._lock = threading.Lock()

    def __call__(self, event_type, actor, details):
        with self._lock:
            conn = db.get_connection(self.path)
            try:
                audit.append_event(conn, event_type, actor, details)
            finally:
                conn.close()


class AuthenticatedHandler:
    """Mixin: read and authenticate a request body, or respond and return None.

    Expects the concrete handler to expose `state`, a mapping carrying
    `client_secret`, `usage` and `record`.
    """

    server_version = "JustiKey/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authenticated_body(self):
        state = self.state
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            self._json(400, {"error": "invalid Content-Length"})
            return None
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            self._json(413, {"error": "request body too large"})
            return None
        body = self.rfile.read(length) if length else b""

        client = self.headers.get("X-JustiKey-Client-Id")
        timestamp = self.headers.get("X-JustiKey-Timestamp")
        nonce = self.headers.get("X-JustiKey-Nonce")
        signature = self.headers.get("X-JustiKey-Signature")
        if not all([client, timestamp, nonce, signature]):
            self._json(401, {"error": "unauthenticated request"})
            return None
        try:
            skew = abs((timeutil.now() - timeutil.parse_dt(timestamp)).total_seconds())
        except ValueError:
            self._json(401, {"error": "malformed timestamp"})
            return None
        if skew > CLOCK_SKEW_SECONDS:
            self._json(401, {"error": "timestamp outside the accepted window"})
            return None
        expected = request_signature(state["client_secret"], timestamp, nonce, body)
        if not hmac.compare_digest(expected, signature):
            state["record"]("client_auth_failed", f"client:{client[:64]}",
                            {"reason": "bad signature"})
            self._json(401, {"error": "invalid client signature"})
            return None
        # A valid signature is not enough: the whole request, headers included,
        # stays valid for the clock window, so anyone who captured one could
        # replay it verbatim. Each nonce is spendable once.
        if not state["usage"].claim_transport_nonce(nonce, CLOCK_SKEW_SECONDS):
            state["record"]("transport_replay_refused", f"client:{client[:64]}",
                            {"reason": "request nonce already spent"})
            self._json(401, {"error": "request nonce has already been used"})
            return None
        return body

    def _payload(self):
        """Authenticated body, parsed as JSON. Responds and returns None on
        anything malformed."""
        body = self._authenticated_body()
        if body is None:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(400, {"error": "invalid JSON"})
            return None
