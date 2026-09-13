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

    {"version": 4,
     "principals": {"supervisor1": {"public_key": "<hex>", "revoked": false}}}

REGISTRY INTEGRITY

Deciding whose keys count is privileged configuration, so the registries are
versioned and their digests are committed to this service's own ledger. A
registry whose version went backwards, or whose contents changed without the
version moving, refuses to start the service -- see justikey/registry.py for
which attacks that does and does not stop.
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

from justikey import (audit, db, disclosure, registry, sealing,  # noqa: E402
                      servicekit, timeutil)

# Body ceiling and clock window come from servicekit, so the two services
# cannot drift apart on the limits that bound replay and resource use.
MAX_BODY_BYTES = servicekit.MAX_BODY_BYTES
CLOCK_SKEW_SECONDS = servicekit.CLOCK_SKEW_SECONDS

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

-- WebAuthn signature counters, owned by the verifying side.
--
-- Deliberately NOT kept in the registry file: that file is declarative
-- configuration whose digest is committed to the ledger, and a counter
-- advancing on every use would make routine activity indistinguishable from
-- someone changing whose keys count. Keeping it here also means re-exporting
-- a registry cannot silently reset a counter to zero, which would disarm the
-- cloned-authenticator check.
CREATE TABLE IF NOT EXISTS webauthn_counters (
    credential_id TEXT PRIMARY KEY,
    sign_count INTEGER NOT NULL,
    last_used_at TEXT NOT NULL
);

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


class Handler(servicekit.AuthenticatedHandler, BaseHTTPRequestHandler):
    """Authentication and framing come from servicekit, shared with the
    custodian: two copies of an authentication routine is how one of them
    quietly loses a check."""

    server_version = "JustiKeyDisclosure/1.0"

    @property
    def state(self):
        return STATE

    # -- routes -----------------------------------------------------------

    def do_GET(self):
        if self.path == "/healthz":
            return self._json(200, {"status": "ok"})
        if self.path == "/publickey":
            return self._json(200, {"public_key": STATE["service"]._opener.public_hex,
                                    "key_id": STATE["service"]._opener.key_id,
                                    "kem": STATE["service"]._opener.kem,
                                    "seal_version": sealing.FORMAT_VERSION})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path not in ("/index", "/disclose"):
            self._json(404, {"error": "not found"})
            return
        payload = self._payload()
        if payload is None:
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


def get_meta(conn, key):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def set_meta(conn, key, value):
    conn.execute("INSERT INTO meta (key, value) VALUES (?,?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


def admit_registry(ledger, role, path):
    """Load a registry and refuse it if it rolled back or was swapped.

    Called at startup, before the service will answer anything. A registry
    that cannot be admitted is a configuration failure, not a degraded mode:
    continuing would mean answering requests against keys whose provenance
    the service has just discovered it cannot account for.
    """
    version, principals = registry.unwrap(read_registry_file(path)) if path else (0, {})
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
        return principals, status, detail
    finally:
        conn.close()


def read_registry_file(path):
    with open(path, "r") as fh:
        return json.load(fh)


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
    _, data = registry.unwrap(read_registry_file(path))
    return parse_registry(data, role)


def parse_registry(data, role):
    parsed = {}
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
        parsed[username] = record
    return parsed


def load_approvers(path):
    return load_registry(path, "approver")


def main():
    parser = argparse.ArgumentParser(description="JustiKey disclosure service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--key", default=os.environ.get("JUSTIKEY_DISCLOSURE_KEY"),
                        help="disclosure private key (hex)")
    parser.add_argument("--key-file", help="file holding the disclosure private key")
    parser.add_argument("--kem", default=os.environ.get("JUSTIKEY_DISCLOSURE_KEM"),
                        help="key-agreement suite of the disclosure key; inferred "
                             "from the key material when it carries one")
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

    material = args.key
    if not material and args.key_file:
        with open(args.key_file, "r") as fh:
            material = fh.read().strip()
    if not material:
        parser.error("a disclosure private key is required (--key or --key-file)")
    # Key material carries its own suite (`<kem>:<hex>`); bare hex is the v3
    # form and is read as X25519. --kem overrides both, for a key handed over
    # out of band.
    kem_name, private_hex = disclosure.decode_key(material)
    if args.kem:
        kem_name = args.kem
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
    STATE["record"] = record
    # One role here: the application. The custodian splits ingest from
    # disclosure because it holds the index key; this service does not.
    STATE["client_secrets"] = {"application": args.client_secret}
    STATE["index_limit"] = args.index_limit
    STATE["usage"] = disclosure.UsageStore(args.ledger)
    STATE["usage"].purge_expired()

    # Admit the registries before answering anything. A rollback or a silent
    # swap stops the service rather than degrading it.
    admitted = {}
    try:
        for role, path in (("approver", args.approvers), ("requester", args.requesters)):
            principals, status, detail = admit_registry(args.ledger, role, path)
            admitted[role] = (parse_registry(principals, role), status, detail)
    except registry.RegistryError as exc:
        print(f"\nRefusing to start: {exc}", file=sys.stderr)
        sys.exit(3)

    STATE["service"] = disclosure.DisclosureService(
        sealing.RecordOpener(private_hex, kem_name),
        bytes.fromhex(args.index_key),
        admitted["approver"][0],
        usage=STATE["usage"],
        max_disclosures=args.max_disclosures,
        requester_registry=admitted["requester"][0],
        presence_mode=args.presence_mode)
    if args.presence_mode == "required" and not args.requesters:
        parser.error("--presence-mode required needs --requesters: with no enrolled "
                     "requesters every disclosure would be refused")

    opener = STATE["service"]._opener
    hardware = sorted(name for name, entry in STATE["service"].requesters.items()
                      if entry.get("webauthn"))
    for role, (_, status, detail) in admitted.items():
        if status != "unchanged":
            # A change in whose keys count is an event, not a startup detail.
            record(f"registry_{status}", "disclosure-service", dict(detail, role=role))
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
    for role, (_, status, detail) in admitted.items():
        print(f"  {role + ' reg':<11}: v{detail['version']} "
              f"({detail['principals']} enrolled, {status})")
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
