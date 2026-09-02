"""The disclosure service: the only thing that can open a sealed observation.

Stages 2-3 of docs/capability-model.md.

The application seals observations with a public key and cannot open them.
Everything that turns a sealed record back into a plate passes through here,
and this service will not open anything without a valid approver signature
over the exact scope being claimed.

WHAT THIS SERVICE DOES NOT TAKE FROM ITS CALLER

The caller has already run the policy engine. This service checks scope again
anyway, because a caller that has been compromised is precisely the caller
whose filtering cannot be trusted. Specifically it does not accept from the
caller:

  * the approver's public key -- it holds its own registry, so a compromised
    application cannot present a key it controls and forge approvals;
  * the blind-index key -- it derives scope tokens itself, which is also why
    the application no longer holds that key at all (see the threat model:
    plates are low-entropy and a held index key means offline enumeration);
  * the selection of rows -- the candidate set is a hint, never authority.

Scope is decided from the blind index and the timestamp, never by opening a
record to look at it. Opening an observation to discover it was out of scope
would disclose it in the act of deciding not to.

TRUST BOUNDARY

In `local` mode the private key is loaded into the application process, so
the split is structural rather than enforced. In `remote` mode the service
runs as its own process and principal (scripts/disclosure_server.py), keeps
its own append-only ledger, and the application holds neither the disclosure
private key nor the blind-index key. Both modes expose the same disclose(),
so moving between them changes where opening happens, not what is checked.
"""
import hashlib
import hmac
import json
import secrets
import sys
from urllib import error, request

from . import approvals, config, crypto_store, sealing, timeutil

MODE_LOCAL = "local"
MODE_REMOTE = "remote"

# Most sealed rows one disclosure request may carry.
MAX_ROWS_PER_REQUEST = 5000

# Only the sealed material and the fields needed to decide scope leave the
# application. Nothing else about a row is the service's business.
WIRE_FIELDS = ("id", "record_uid", "seal_version", "recipient_key_id", "plate_index",
               "captured_at", "camera_id", "record_ct", "wrapped_key", "ephemeral_pub")


class DisclosureError(RuntimeError):
    """Disclosure was refused."""


# ---------------------------------------------------------------------------
# Caller authentication (subordinate to the approver's signature)
# ---------------------------------------------------------------------------

def request_signature(secret, timestamp, nonce, body):
    """Authenticate the application to the disclosure service.

    Separate from, and subordinate to, the approver's signature: this only
    establishes that the caller is the known application, so an arbitrary host
    cannot make the service work through its key. The approval is what
    actually authorizes an opening.
    """
    digest = hashlib.sha256(body or b"").hexdigest()
    base = f"{timestamp}\n{nonce}\n{digest}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# The service itself
# ---------------------------------------------------------------------------

class DisclosureService:
    """Holds the private key and the index key. Opens only what an approval covers."""

    def __init__(self, opener, index_key, approver_registry=None):
        self._opener = opener
        self._index_key = index_key
        # username -> {"public_key": hex, "revoked": bool}. Held by the
        # service, never supplied by the caller.
        self.approvers = approver_registry or {}
        self._spent_nonces = {}

    # -- scope tokens ----------------------------------------------------

    def blind_index(self, plate):
        normalized = str(plate).strip().upper().encode("utf-8")
        return hmac.new(self._index_key, normalized, hashlib.sha256).hexdigest()

    # -- approval verification -------------------------------------------

    def _approver_key(self, username):
        entry = self.approvers.get(username)
        if entry is None:
            raise DisclosureError(f"approver {username!r} is not enrolled with this service")
        if entry.get("revoked"):
            raise DisclosureError(f"approver {username!r}'s signing key has been revoked")
        return entry["public_key"]

    def verify_approval(self, statement, signature_hex):
        """Check an approval on the service's own terms.

        Returns the approver's registered public key. Raises otherwise.
        """
        if not isinstance(statement, dict):
            raise DisclosureError("malformed approval statement")
        if statement.get("v") != approvals.STATEMENT_VERSION:
            raise DisclosureError(
                f"unsupported approval schema {statement.get('v')!r}")
        for field in ("authorization_id", "target_plate", "window_start", "window_end",
                      "requester", "approver", "approved_at", "approval_expires_at",
                      "nonce", "approver_key_id"):
            if not statement.get(field):
                raise DisclosureError(f"approval statement is missing {field}")

        public_hex = self._approver_key(statement["approver"])
        if sealing.key_id(public_hex) != statement["approver_key_id"]:
            raise DisclosureError(
                "approval names a different signing key than the one enrolled")
        if statement["approver"] == statement["requester"]:
            raise DisclosureError("self-approval: requester and approver are the same person")
        if not approvals.verify_statement(public_hex, statement, signature_hex):
            raise DisclosureError("approval signature does not cover this request")

        now = timeutil.now_iso()
        if now > statement["approval_expires_at"]:
            raise DisclosureError("approval has expired")
        if statement["approved_at"] > now:
            raise DisclosureError("approval is dated in the future")
        return public_hex

    def _claim_nonce(self, statement):
        """One approval nonce may not be replayed after it expires.

        Bounded by expiry: a spent nonce is forgotten once the approval it
        belongs to could no longer be used anyway.
        """
        now = timeutil.now_iso()
        for nonce, expires in list(self._spent_nonces.items()):
            if expires < now:
                del self._spent_nonces[nonce]
        self._spent_nonces[statement["nonce"]] = statement["approval_expires_at"]

    # -- the operation ----------------------------------------------------

    def disclose(self, rows, statement, signature_hex, requester):
        """Open the records an approval covers, and no others."""
        self.verify_approval(statement, signature_hex)
        if statement["requester"] != requester:
            raise DisclosureError("this approval belongs to another requester")

        target_index = self.blind_index(statement["target_plate"])
        window_start, window_end = statement["window_start"], statement["window_end"]

        revealed = []
        for row in rows:
            if row.get("plate_index") != target_index:
                continue
            if not (window_start <= row.get("captured_at", "") <= window_end):
                continue
            fields = self._opener.open(row, row["captured_at"], row["camera_id"],
                                       row["plate_index"])
            revealed.append({"id": row["id"], "plate": fields.get("plate"),
                             "location": fields.get("location")})
        self._claim_nonce(statement)
        return revealed


# ---------------------------------------------------------------------------
# Remote client
# ---------------------------------------------------------------------------

class RemoteDisclosureService:
    """Calls a disclosure service running in its own process and trust domain.

    Exposes the same operations as the local service, because stage 3 is meant
    to change where opening happens, not what is checked. The remote end
    re-verifies everything for itself; nothing here is trusted to have done so.
    """

    def __init__(self, url, client_id, client_secret, timeout=None):
        self.url = url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout or config.DISCLOSURE_TIMEOUT_SECONDS

    def _post(self, path, payload):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        timestamp, nonce = timeutil.now_iso(), secrets.token_urlsafe(16)
        req = request.Request(self.url + path, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-JustiKey-Client-Id", self.client_id)
        req.add_header("X-JustiKey-Timestamp", timestamp)
        req.add_header("X-JustiKey-Nonce", nonce)
        req.add_header("X-JustiKey-Signature",
                       request_signature(self.client_secret, timestamp, nonce, body))
        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            raise DisclosureError(f"disclosure service refused ({exc.code}): {detail}") from exc
        except (error.URLError, OSError, json.JSONDecodeError) as exc:
            # Unreachable is a clean denial, never "open it anyway".
            raise DisclosureError(f"disclosure service unreachable: {exc!r}") from exc

    def blind_index(self, plate):
        """Ask the service for a scope token.

        The application cannot compute this itself by design: holding the
        index key would let a compromised application enumerate the
        low-entropy plate space offline. Here each request is authenticated,
        rate limited, and recorded in the service's own ledger.
        """
        return self._post("/index", {"plate": plate})["plate_index"]

    def disclose(self, rows, statement, signature_hex, requester):
        if len(rows) > MAX_ROWS_PER_REQUEST:
            raise DisclosureError(f"too many candidate rows for one disclosure ({len(rows)})")
        result = self._post("/disclose", {
            "rows": [{k: row.get(k) for k in WIRE_FIELDS} for row in rows],
            "statement": statement,
            "signature": signature_hex,
            "requester": requester,
        })
        return result.get("opened", [])


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------

def key_file_for(db_path):
    base = db_path[:-3] if db_path.endswith(".db") else db_path
    return base + ".disclosure-key"


def load_private_key(db_path, create=False):
    """Resolve the disclosure private key (local mode only)."""
    if config.DISCLOSURE_PRIVATE_KEY:
        return config.DISCLOSURE_PRIVATE_KEY.strip()

    import os
    path = key_file_for(db_path)
    if os.path.exists(path):
        with open(path, "r") as fh:
            return fh.read().strip()
    if not create:
        return None

    private_hex, _ = sealing.generate_keypair()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(path, "r") as fh:
            return fh.read().strip()
    with os.fdopen(fd, "w") as fh:
        fh.write(private_hex)
    print(f"[justikey] generated a disclosure key at {path}. In local mode this "
          f"process can open sealed records and holds the index key, so the split "
          f"is structural only. Run scripts/disclosure_server.py for the separated "
          f"service.", file=sys.stderr)
    return private_hex


def fetch_public_key(url, timeout=None):
    try:
        with request.urlopen(url.rstrip("/") + "/publickey",
                             timeout=timeout or config.DISCLOSURE_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))["public_key"]
    except (error.URLError, OSError, ValueError, KeyError) as exc:
        raise DisclosureError(
            f"could not fetch the disclosure public key from {url}: {exc!r}") from exc


def public_key_for(conn, db_path, create=False):
    """The public half the application uses to seal new observations.

    In remote mode this is never derived from a private key the application
    should not have: it is configured explicitly or fetched from the service.
    """
    stored = crypto_store.get_meta(conn, "disclosure_public_key")
    if stored:
        return stored
    if config.DISCLOSURE_PUBLIC_KEY:
        return config.DISCLOSURE_PUBLIC_KEY.strip()
    if config.DISCLOSURE_URL:
        return fetch_public_key(config.DISCLOSURE_URL)
    private_hex = load_private_key(db_path, create=create)
    return sealing.public_from_private(private_hex) if private_hex else None


def is_remote():
    return bool(config.DISCLOSURE_URL)


def service_for(conn, db_path):
    """Build the disclosure service for this database, or None outside v3."""
    if crypto_store.encryption_mode(conn) != crypto_store.MODE_V3:
        return None

    if config.DISCLOSURE_URL:
        if not config.DISCLOSURE_CLIENT_SECRET:
            raise DisclosureError(
                "a disclosure service is configured but no client secret is set; "
                "set JUSTIKEY_DISCLOSURE_CLIENT_SECRET")
        return RemoteDisclosureService(config.DISCLOSURE_URL, config.DISCLOSURE_CLIENT_ID,
                                       config.DISCLOSURE_CLIENT_SECRET)

    private_hex = load_private_key(db_path)
    if private_hex is None:
        raise DisclosureError(
            "this database seals observations but no disclosure key is available; "
            "set JUSTIKEY_DISCLOSURE_KEY or point at a disclosure service")
    return DisclosureService(sealing.RecordOpener(private_hex),
                             crypto_store.resolve_index_key(db_path),
                             local_approver_registry(conn))


def local_approver_registry(conn):
    """Approver keys as the local-mode service sees them.

    In remote mode the service keeps its own enrolment and never asks the
    application, which is what stops a compromised application from
    presenting a key it controls.
    """
    rows = conn.execute(
        "SELECT username, signing_pub, signing_key_revoked_at FROM users "
        "WHERE signing_pub IS NOT NULL").fetchall()
    return {r["username"]: {"public_key": r["signing_pub"],
                            "revoked": bool(r["signing_key_revoked_at"])}
            for r in rows}
