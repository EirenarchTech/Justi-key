#!/usr/bin/env python3
"""The JustiKey disclosure service: a separate security domain.

Stage 3 of docs/capability-model.md.

This process holds the two keys the web application must not have:

    the disclosure private key  -- opens sealed observations
    the blind-index key         -- turns a plate into a scope token

Run it as its own OS principal, ideally on its own host, reachable only by
the application. Then compromising the web application completely -- its
database, its environment, arbitrary SQL -- still does not yield historical
observations, because nothing the application holds can open a record or
enumerate the index.

    python3 scripts/disclosure_server.py --port 8090 \\
        --approvers approvers.json --ledger disclosure-audit.db

Vocabulary is deliberately minimal. Every request is authenticated with a
shared client secret, and every decision is written to this service's own
append-only, hash-chained ledger before a response is returned:

    GET  /healthz     liveness
    GET  /publickey   the key the application seals against
    POST /index       a scope token for one plate (rate limited, recorded)
    POST /disclose    open the records an approval covers

AUTHORIZATION USAGE

The cap on how many times one approval may be spent lives here, not in the
application. The service keeps `approval nonce -> disclosure count -> expiry`
in its own ledger database and updates it atomically before opening anything,
so attempt 26 is refused whatever the caller claims about the first 25.

PROOF OF PRESENCE

An approval alone is a bearer capability: whoever holds the row can spend it
in the requester's name. With --requesters, the service also demands a
freshly signed proof that the requester is here for this specific disclosure,
checked against a key this service holds and the application does not. See
justikey/presence.py.

APPROVER ENROLMENT

Approver public keys live here, in --approvers, not in the request. A
compromised application presenting its own key is the attack this defeats, so
the service never accepts a key from its caller.

    {"supervisor1": {"public_key": "<hex>", "revoked": false}}
"""
import argparse
import hmac
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import audit, db, disclosure, sealing, timeutil  # noqa: E402

MAX_BODY_BYTES = 8 * 1024 * 1024
CLOCK_SKEW_SECONDS = 300

# Just the ledger. This service stores no observations of its own: it opens
# records on request and keeps the record of having done so.
LEDGER_SCHEMA = """
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

-- How often each approval has actually been spent. The application asks for
-- disclosures; this service decides whether one is still owed. Keeping the
-- count here means a compromised application calling /disclose directly,
-- with a genuine signed approval, still runs out.
CREATE TABLE IF NOT EXISTS authorization_usage (
    nonce TEXT PRIMARY KEY,
    authorization_id INTEGER,
    disclosure_count INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL,
    first_used_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_authorization_usage_expiry ON authorization_usage(expires_at);

-- Proofs that the requester was present, spendable once each. An approval
-- may be used N times, but each human confirmation authorizes one of them.
CREATE TABLE IF NOT EXISTS presence_nonces (
    nonce TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL,
    used_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_presence_nonces_expiry ON presence_nonces(expires_at);

-- Transport nonces, spent once each, so a captured authenticated request
-- cannot simply be resent inside the clock-skew window.
CREATE TABLE IF NOT EXISTS transport_nonces (
    nonce TEXT PRIMARY KEY,
    seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transport_nonces_seen ON transport_nonces(seen_at);
"""

STATE = {}
# The ledger is the evidentiary heart of this service, so writes to it are
# serialized. audit.append_event already wraps each append in BEGIN IMMEDIATE,
# which holds across processes; this lock removes even in-process contention,
# so concurrent disclosures cannot interleave into a forked chain.
LEDGER_LOCK = threading.Lock()
INDEX_LOCK = threading.Lock()
INDEX_CALLS = []


def record(event_type, actor, details):
    with LEDGER_LOCK:
        conn = db.get_connection(STATE["ledger"])
        try:
            audit.append_event(conn, event_type, actor, details)
        finally:
            conn.close()


def index_rate_ok():
    """Bound how fast scope tokens can be minted.

    The application must be able to index observations as they arrive, but
    that same endpoint is the one channel through which a compromised
    application could grind the plate space. Offline enumeration is gone;
    this makes the remaining online path slow and, because every call is
    recorded, loud.
    """
    limit, window = STATE["index_limit"], 60.0
    if limit <= 0:
        return True
    now = time.monotonic()
    with INDEX_LOCK:
        while INDEX_CALLS and now - INDEX_CALLS[0] > window:
            INDEX_CALLS.pop(0)
        if len(INDEX_CALLS) >= limit:
            return False
        INDEX_CALLS.append(now)
        return True


class Handler(BaseHTTPRequestHandler):
    server_version = "JustiKeyDisclosure/1.0"
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

    # -- caller authentication -------------------------------------------

    def _authenticated_body(self):
        """Read and authenticate the request body, or respond and return None."""
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
        expected = disclosure.request_signature(STATE["client_secret"], timestamp, nonce, body)
        if not hmac.compare_digest(expected, signature):
            record("client_auth_failed", f"client:{client[:64]}", {"reason": "bad signature"})
            self._json(401, {"error": "invalid client signature"})
            return None
        # A valid signature is not enough: the whole request, headers included,
        # stays valid for the clock window, so anyone who captured one could
        # replay it verbatim. Each nonce is spendable once.
        if not STATE["usage"].claim_transport_nonce(nonce, CLOCK_SKEW_SECONDS):
            record("transport_replay_refused", f"client:{client[:64]}",
                   {"reason": "request nonce already spent"})
            self._json(401, {"error": "request nonce has already been used"})
            return None
        return body

    # -- routes -----------------------------------------------------------

    def do_GET(self):
        if self.path == "/healthz":
            return self._json(200, {"status": "ok"})
        if self.path == "/publickey":
            return self._json(200, {"public_key": STATE["service"]._opener.public_hex,
                                    "key_id": STATE["service"]._opener.key_id,
                                    "seal_version": sealing.FORMAT_VERSION})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path not in ("/index", "/disclose"):
            self._json(404, {"error": "not found"})
            return
        body = self._authenticated_body()
        if body is None:
            return
        try:
            payload = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(400, {"error": "invalid JSON"})
            return

        if self.path == "/index":
            return self._handle_index(payload)
        return self._handle_disclose(payload)

    def _handle_index(self, payload):
        plate = payload.get("plate")
        if not isinstance(plate, str) or not plate.strip():
            self._json(400, {"error": "plate is required"})
            return
        if not index_rate_ok():
            record("index_rate_limited", "client", {"limit_per_minute": STATE["index_limit"]})
            self._json(429, {"error": "scope-token rate limit exceeded"})
            return
        # The plate itself is never written to the ledger: recording every
        # observation's plate here would rebuild the archive this service
        # exists to protect.
        record("scope_token_issued", "client", {})
        self._json(200, {"plate_index": STATE["service"].blind_index(plate)})

    def _handle_disclose(self, payload):
        rows = payload.get("rows") or []
        statement = payload.get("statement")
        signature = payload.get("signature")
        requester = payload.get("requester")
        proof_statement = payload.get("presence")
        proof = payload.get("presence_proof")
        if not isinstance(rows, list) or len(rows) > disclosure.MAX_ROWS_PER_REQUEST:
            self._json(400, {"error": "invalid or oversized candidate set"})
            return

        try:
            opened = STATE["service"].disclose(rows, statement, signature, requester,
                                               proof_statement, proof)
        except disclosure.DisclosureError as exc:
            record("disclosure_refused", f"requester:{requester}", {
                "reason": str(exc),
                "case": (statement or {}).get("case_number") if isinstance(statement, dict) else None,
                "candidates": len(rows)})
            self._json(403, {"error": str(exc)})
            return
        except sealing.SealingError as exc:
            record("disclosure_failed", f"requester:{requester}", {
                "reason": str(exc), "candidates": len(rows)})
            self._json(409, {"error": str(exc)})
            return

        # Persist the authenticator's counter. A verifier that checks the
        # counter but never stores the new value is checking nothing.
        proved = STATE["service"].last_presence or {}
        if proved.get("custody") == "hardware":
            entry = STATE["service"].requesters.get(requester, {}).get("webauthn")
            if entry is not None:
                entry["sign_count"] = proved["sign_count"]
                save_requesters()

        # Recorded before the response is written: an opening that reached the
        # caller but not the ledger would be exactly the gap that matters.
        record("disclosure_granted", f"requester:{requester}", {
            "case": statement.get("case_number"),
            "authorization_id": statement.get("authorization_id"),
            "approver": statement.get("approver"),
            "use_count": STATE["service"].last_use_count,
            "use_limit": STATE["service"].max_disclosures,
            # Which custody the requester proved presence with. "software" and
            # "hardware" are materially different events and the ledger says
            # which, rather than recording both as "disclosed".
            "presence": (STATE["service"].last_presence or {}).get("custody", "none"),
            "candidates": len(rows), "opened": len(opened)})
        self._json(200, {"opened": opened})


def load_registry(path, role):
    """Enrolled keys for one role, read from this service's own file.

    Two files, two roles. A single list with a role field would put the
    distinction inside a value someone can edit; separate files make
    "approver" and "requester" a property of where the key is written down.

    An entry is either a software key:

        {"alice": {"public_key": "<hex>", "revoked": false}}

    or a hardware authenticator, whose private half has never existed on any
    host here:

        {"alice": {"public_key": "<hex>", "webauthn": {
            "credential_id": "...", "public_key": "<base64url COSE>",
            "sign_count": 0, "rp_id": "justikey.example", 
            "origin": "https://justikey.example"}}}
    """
    if not path:
        return {}
    with open(path, "r") as fh:
        data = json.load(fh)
    registry = {}
    for username, entry in data.items():
        if not isinstance(entry, dict) or "public_key" not in entry:
            raise ValueError(f"{role} {username!r} needs a public_key")
        record = {"public_key": entry["public_key"],
                  "revoked": bool(entry.get("revoked"))}
        hardware = entry.get("webauthn")
        if hardware:
            for field in ("credential_id", "public_key"):
                if not hardware.get(field):
                    raise ValueError(
                        f"{role} {username!r}: webauthn enrolment needs {field}")
            record["webauthn"] = dict(hardware)
        registry[username] = record
    return registry


def load_approvers(path):
    return load_registry(path, "approver")


def save_requesters():
    """Write the requester registry back, so sign counts survive a restart.

    A WebAuthn counter that resets on restart stops being able to detect a
    cloned authenticator, which is the only thing it is for.
    """
    path = STATE.get("requesters_path")
    if not path:
        return
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(STATE["service"].requesters, fh, indent=2, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def main():
    parser = argparse.ArgumentParser(description="JustiKey disclosure service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--key", default=os.environ.get("JUSTIKEY_DISCLOSURE_KEY"),
                        help="disclosure private key (hex)")
    parser.add_argument("--key-file", help="file holding the disclosure private key")
    parser.add_argument("--index-key", default=os.environ.get("JUSTIKEY_INDEX_KEY"),
                        help="blind-index key (hex); the application must not have this")
    parser.add_argument("--client-secret",
                        default=os.environ.get("JUSTIKEY_DISCLOSURE_CLIENT_SECRET"),
                        help="shared secret the application authenticates with")
    parser.add_argument("--approvers", help="JSON file of enrolled approver public keys")
    parser.add_argument("--requesters",
                        help="JSON file of enrolled requester keys, for proof of presence")
    parser.add_argument("--presence-mode", choices=("off", "enrolled", "required"),
                        default=os.environ.get("JUSTIKEY_PRESENCE_MODE", "enrolled"),
                        help="'required' refuses any disclosure without proof the "
                             "requester is present; 'enrolled' requires it from every "
                             "requester who has a key here")
    parser.add_argument("--ledger", default="disclosure-audit.db",
                        help="this service's own append-only ledger")
    parser.add_argument("--index-limit", type=int, default=600,
                        help="scope tokens per minute; 0 disables the limit")
    parser.add_argument("--max-disclosures", type=int, default=None,
                        help="times one approval may be spent; 0 disables the cap")
    args = parser.parse_args()

    private_hex = args.key
    if not private_hex and args.key_file:
        with open(args.key_file, "r") as fh:
            private_hex = fh.read().strip()
    if not private_hex:
        parser.error("a disclosure private key is required (--key or --key-file)")
    if not args.index_key:
        parser.error("--index-key is required: the application must not hold it")
    if not args.client_secret:
        parser.error("--client-secret is required")

    conn = db.get_connection(args.ledger)
    try:
        conn.executescript(LEDGER_SCHEMA)
    finally:
        conn.close()

    STATE["ledger"] = args.ledger
    STATE["client_secret"] = args.client_secret
    STATE["index_limit"] = args.index_limit
    STATE["usage"] = disclosure.UsageStore(args.ledger)
    STATE["usage"].purge_expired()
    STATE["requesters_path"] = args.requesters
    STATE["service"] = disclosure.DisclosureService(
        sealing.RecordOpener(private_hex),
        bytes.fromhex(args.index_key),
        load_approvers(args.approvers),
        usage=STATE["usage"],
        max_disclosures=args.max_disclosures,
        requester_registry=load_registry(args.requesters, "requester"),
        presence_mode=args.presence_mode)
    if args.presence_mode == "required" and not args.requesters:
        parser.error("--presence-mode required needs --requesters: with no enrolled "
                     "requesters every disclosure would be refused")

    opener = STATE["service"]._opener
    hardware = sorted(name for name, entry in STATE["service"].requesters.items()
                      if entry.get("webauthn"))
    record("service_started", "disclosure-service", {
        "key_id": opener.key_id, "approvers": sorted(STATE["service"].approvers),
        "max_disclosures": STATE["service"].max_disclosures,
        "presence_mode": STATE["service"].presence_mode,
        "requesters": sorted(STATE["service"].requesters),
        "requesters_on_hardware": hardware})

    print(f"JustiKey disclosure service on http://{args.host}:{args.port}")
    print(f"  public key : {opener.public_hex}")
    print(f"  key id     : {opener.key_id}")
    print(f"  approvers  : {', '.join(sorted(STATE['service'].approvers)) or '(none enrolled)'}")
    print(f"  ledger     : {args.ledger}")
    print(f"  use cap    : {STATE['service'].max_disclosures or 'unlimited'} per approval")
    print(f"  presence   : {args.presence_mode} "
          f"({len(STATE['service'].requesters)} requester(s) enrolled, "
          f"{len(hardware)} on hardware)")
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
