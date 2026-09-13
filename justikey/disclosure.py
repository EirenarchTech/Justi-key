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
import threading
from datetime import timedelta
from urllib import error, request

from . import (approvals, config, crypto_store, custody, kem, presence,  # noqa: F401
               sealing, timeutil)

MODE_LOCAL = "local"
MODE_REMOTE = "remote"

# Most sealed rows one disclosure request may carry.
MAX_ROWS_PER_REQUEST = 5000

# Only the sealed material and the fields needed to decide scope leave the
# application. Nothing else about a row is the service's business.
WIRE_FIELDS = ("id", "record_uid", "seal_version", "seal_kem", "recipient_key_id",
               "plate_index", "captured_at", "camera_id", "record_ct", "wrapped_key",
               "ephemeral_pub")


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

class UsageStore:
    """Persistent per-approval disclosure counter, owned by the key holder.

    The application also keeps a count, but a compromised application simply
    would not call the code that maintains it -- it can talk to /disclose
    directly with a legitimate signed approval lifted from the database. So
    the limit has to be enforced here, in the domain that holds the key, and
    it has to survive a restart.

    Keyed by the approval's nonce: one signed authorization, usable N times,
    counted by the trusted side, closed permanently at expiry.
    """

    def __init__(self, db_path):
        self.db_path = db_path

    def _connect(self):
        from . import db
        return db.get_connection(self.db_path)

    def claim(self, nonce, authorization_id, expires_at, limit,
              presence_nonce=None, presence_expires_at=None):
        """Spend everything one disclosure consumes, or nothing. Returns
        (ok, count, reason).

        The approval's count and the requester's proof of presence are spent
        in ONE transaction. Two transactions would leave a window where a
        crash, or a concurrent request losing a race, burned a human
        confirmation without the disclosure it paid for -- or, worse, spent
        the approval while the presence nonce insert failed, so the same proof
        stayed live.

        Two independent mechanisms guard each one, deliberately:

          BEGIN IMMEDIATE    serializes read-then-increment, so concurrent
                             requests cannot both observe count 25
          PRIMARY KEY        presence_nonces.nonce is unique, so even if the
                             logic above were wrong, the database refuses a
                             second spend of the same proof

        The uniqueness constraint is the backstop. It is the one that holds
        when the reasoning does not.
        """
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                now = timeutil.now_iso()
                if presence_nonce is not None:
                    conn.execute("DELETE FROM presence_nonces WHERE expires_at < ?", (now,))
                    spent = conn.execute(
                        "INSERT OR IGNORE INTO presence_nonces (nonce, expires_at, used_at) "
                        "VALUES (?,?,?)",
                        (presence_nonce, presence_expires_at or expires_at, now))
                    if spent.rowcount != 1:
                        conn.execute("COMMIT")
                        return False, 0, ("this proof of presence has already been used; "
                                          "the requester must confirm again")

                row = conn.execute(
                    "SELECT disclosure_count, expires_at FROM authorization_usage "
                    "WHERE nonce=?", (nonce,)).fetchone()
                if row is not None and now > row["expires_at"]:
                    conn.execute("ROLLBACK")
                    return False, row["disclosure_count"], "approval has expired"
                count = row["disclosure_count"] if row else 0
                if limit > 0 and count >= limit:
                    # Rolled back, not committed: a request refused by the cap
                    # must not also cost the requester their confirmation.
                    conn.execute("ROLLBACK")
                    return False, count, (
                        f"this approval has already been used {count} times; "
                        f"the limit is {limit}")
                if row is not None:
                    conn.execute(
                        "UPDATE authorization_usage SET disclosure_count=?, last_used_at=? "
                        "WHERE nonce=?", (count + 1, now, nonce))
                else:
                    conn.execute(
                        "INSERT INTO authorization_usage (nonce, authorization_id, "
                        "disclosure_count, expires_at, first_used_at, last_used_at) "
                        "VALUES (?,?,?,?,?,?)",
                        (nonce, authorization_id, 1, expires_at, now, now))
                conn.execute("COMMIT")
                return True, count + 1, None
            except Exception:
                conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()

    def claim_transport_nonce(self, nonce, window_seconds):
        """Spend a transport nonce once, so an authenticated request that was
        captured cannot simply be resent inside the clock window."""
        conn = self._connect()
        try:
            cutoff = timeutil.to_canonical(
                timeutil.now() - timedelta(seconds=window_seconds * 2))
            conn.execute("DELETE FROM transport_nonces WHERE seen_at < ?", (cutoff,))
            cur = conn.execute(
                "INSERT OR IGNORE INTO transport_nonces (nonce, seen_at) VALUES (?,?)",
                (nonce, timeutil.now_iso()))
            return cur.rowcount == 1
        finally:
            conn.close()

    def claim_presence_nonce(self, nonce, expires_at):
        """Spend one proof of presence. Returns False if it was already used.

        A third namespace, deliberately: approval nonces identify a capability
        that may be spent N times, transport nonces guard one HTTP request,
        and these guard one human confirmation. Collapsing any two of them
        would make one of the three limits silently weaker.
        """
        conn = self._connect()
        try:
            conn.execute("DELETE FROM presence_nonces WHERE expires_at < ?",
                         (timeutil.now_iso(),))
            cur = conn.execute(
                "INSERT OR IGNORE INTO presence_nonces (nonce, expires_at, used_at) "
                "VALUES (?,?,?)", (nonce, expires_at, timeutil.now_iso()))
            return cur.rowcount == 1
        finally:
            conn.close()

    def sign_count(self, credential_id):
        """The highest counter this verifier has seen for a credential.

        Owned here rather than in the registry file, so that a counter
        advancing during normal use never looks like a change to whose keys
        count -- and so that re-exporting a registry cannot silently reset a
        counter back to zero, which would disarm the cloned-authenticator
        check entirely.
        """
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT sign_count FROM webauthn_counters WHERE credential_id=?",
                (credential_id,)).fetchone()
            return row["sign_count"] if row else None
        finally:
            conn.close()

    def record_sign_count(self, credential_id, count):
        """Persist a counter, never downwards."""
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO webauthn_counters (credential_id, sign_count, last_used_at) "
                "VALUES (?,?,?) ON CONFLICT(credential_id) DO UPDATE SET "
                "sign_count=MAX(sign_count, excluded.sign_count), "
                "last_used_at=excluded.last_used_at",
                (credential_id, count, timeutil.now_iso()))
        finally:
            conn.close()

    def purge_expired(self):
        conn = self._connect()
        try:
            now = timeutil.now_iso()
            conn.execute("DELETE FROM authorization_usage WHERE expires_at < ?", (now,))
            conn.execute("DELETE FROM presence_nonces WHERE expires_at < ?", (now,))
        finally:
            conn.close()


class DisclosureService:
    """Holds the private key and the index key. Opens only what an approval covers."""

    def __init__(self, opener, index_key, approver_registry=None, usage=None,
                 max_disclosures=None, requester_registry=None, presence_mode=None,
                 custodian_client=None, registry_versions=None):
        self._opener = opener
        # When a custodian is configured this service stops being the thing
        # that opens records. It still checks everything it checked before --
        # a second opinion is the point -- but the custodian is authoritative,
        # and crucially it is the custodian that SPENDS the approval count and
        # the presence nonce. Two components both spending would halve every
        # cap and make the two ledgers disagree about what happened.
        self._custodian = custodian_client
        self.registry_versions = registry_versions or {}
        self._index_key = index_key
        # username -> {"public_key": hex, "revoked": bool}. Held by the
        # service, never supplied by the caller.
        self.approvers = approver_registry or {}
        # Requesters are enrolled separately from approvers, in their own
        # registry, so a requester's key can never be presented as an
        # approver's. Two roles, two lists, no field to get wrong.
        self.requesters = requester_registry or {}
        self.presence_mode = (config.PRESENCE_MODE if presence_mode is None
                              else presence_mode)
        self._usage = usage
        self.max_disclosures = (config.MAX_DISCLOSURES_PER_AUTHORIZATION
                                if max_disclosures is None else max_disclosures)
        # One service object serves concurrent requests, so the count from the
        # most recent claim is kept per-thread rather than on the instance:
        # two disclosures in flight must not report each other's number.
        self._local = threading.local()

    @property
    def last_use_count(self):
        """Uses spent by the approval this thread most recently disclosed on."""
        return getattr(self._local, "use_count", None)

    @property
    def last_presence(self):
        """What the most recent disclosure proved about the requester.

        None when presence was not required. Otherwise carries `custody`,
        which is the difference between "someone typed a password" and
        "someone touched a security key" -- a distinction an audit trail that
        records only "disclosed" cannot make.
        """
        return getattr(self._local, "presence", None)

    # -- scope tokens ----------------------------------------------------

    def blind_index(self, plate):
        if self._index_key is None:
            raise DisclosureError(
                "this service holds no index key; an approved search goes "
                "through search_token, and arbitrary-plate tokens belong to "
                "the ingest path")
        normalized = str(plate).strip().upper().encode("utf-8")
        return hmac.new(self._index_key, normalized, hashlib.sha256).hexdigest()

    def search_token(self, statement, signature):
        """The scope token for an approved search.

        With a custodian, this is NOT a blind index of an arbitrary plate --
        that operation is reserved to the ingest path, because a caller
        holding the archive and an arbitrary-plate oracle can map every row
        without opening one. The custodian verifies the approval and answers
        for that scope only.
        """
        if self._custodian is not None:
            return self._custodian.search_token(statement, signature,
                                                self.registry_versions)
        return self.blind_index(statement["target_plate"])

    def _disclose_via_custodian(self, rows, statement, requester,
                                proof_statement, proof):
        """One record, one call. Deliberately not a batch.

        Batching would let a caller hand over the whole table and have the
        custodian sort out which ones it likes -- convenient, and exactly the
        shape of the oracle stage 5 removes. Selecting candidates locally is
        fine (it narrows what is sent); it is the custodian re-deriving scope
        per record that makes the narrowing untrusted.
        """
        target_index = self.search_token(statement, self._local.signature)
        window_start, window_end = statement["window_start"], statement["window_end"]

        revealed = []
        for row in rows:
            if row.get("plate_index") != target_index:
                continue
            if not (window_start <= row.get("captured_at", "") <= window_end):
                continue
            identity = {"record_uid": row.get("record_uid"),
                        "captured_at": row.get("captured_at"),
                        "camera_id": row.get("camera_id"),
                        "plate_index": row.get("plate_index")}
            result = self._custodian.open(
                row, identity, statement, self._local.signature, requester,
                proof_statement, proof, registry_versions=self.registry_versions)
            fields = result.get("fields") or {}
            revealed.append({"id": row["id"], "plate": fields.get("plate"),
                             "location": fields.get("location")})
            self._local.use_count = result.get("use_count")
            self._local.presence = {"custody": result.get("presence", "none")}
        return revealed

    # -- approval verification -------------------------------------------

    def _approver_key(self, username):
        entry = self.approvers.get(username)
        if entry is None:
            raise DisclosureError(f"approver {username!r} is not enrolled with this service")
        if entry.get("revoked"):
            raise DisclosureError(f"approver {username!r}'s signing key has been revoked")
        return entry["public_key"]

    def _requester_credential(self, username):
        """The requester's enrolled key, as this service holds it.

        Same rule as approvers: never taken from the request. A compromised
        application that could supply the key it is proving presence with
        would be proving nothing at all.
        """
        entry = self.requesters.get(username)
        if entry is None:
            return None
        try:
            credential = custody.credential_from_registry(
                entry, rp_id=config.WEBAUTHN_RP_ID, origin=config.WEBAUTHN_ORIGIN)
        except custody.CustodyError as exc:
            raise DisclosureError(f"requester {username!r}: {exc}") from exc

        # The registry's counter is only a starting point; what this verifier
        # has actually seen wins, and never goes down.
        if custody.is_hardware(credential) and self._usage is not None:
            seen = self._usage.sign_count(credential["credential_id"])
            if seen is not None:
                credential["sign_count"] = max(credential.get("sign_count") or 0, seen)
        return credential

    def verify_presence(self, statement, requester, proof_statement, proof):
        """Require evidence the requester is actually here, if policy says so.

        Returns the single-use request nonce to spend, or None when presence
        is not required for this requester.
        """
        if self.presence_mode == "off":
            return None
        credential = self._requester_credential(requester)
        if credential is None:
            if self.presence_mode == "required":
                raise DisclosureError(
                    f"requester {requester!r} has no signing key enrolled with this "
                    f"service, and proof of presence is required")
            return None                      # 'enrolled': not yet migrated
        if not proof_statement or not proof:
            raise DisclosureError(
                "this disclosure needs proof that the requester is present; an "
                "approval on its own is not sufficient")
        try:
            result = presence.verify(
                credential, proof_statement, proof, statement, requester,
                require_user_verification=config.require_user_verification("requester"))
        except presence.PresenceError as exc:
            raise DisclosureError(str(exc)) from exc
        if result.get("custody") == "hardware" and self._usage is not None:
            # Persist before the disclosure proceeds. A verifier that checks
            # the counter and forgets to store it is checking nothing.
            self._usage.record_sign_count(result["credential_id"], result["sign_count"])
        self._local.presence = result
        return result

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
        if approvals.signing_key_id(public_hex) != statement["approver_key_id"]:
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

    # -- the operation ----------------------------------------------------

    def disclose(self, rows, statement, signature_hex, requester,
                 proof_statement=None, proof=None):
        """Open the records an approval covers, and no others."""
        self._local.presence = None
        self._local.signature = signature_hex
        self.verify_approval(statement, signature_hex)
        if statement["requester"] != requester:
            raise DisclosureError("this approval belongs to another requester")

        # Presence is verified before anything is spent: a request that cannot
        # show the requester is here must not consume the approval's budget,
        # or refusing it would still cost the officer a disclosure.
        presence_result = self.verify_presence(statement, requester, proof_statement, proof)

        if self._custodian is not None:
            return self._disclose_via_custodian(
                rows, statement, requester, proof_statement, proof)

        # Then spend both in one transaction. The approval's count stops a
        # compromised application replaying a genuine approval; the presence
        # nonce makes one human confirmation buy exactly one disclosure. They
        # commit together or not at all -- see UsageStore.claim.
        if self._usage is not None:
            ok, count, reason = self._usage.claim(
                statement["nonce"], statement.get("authorization_id"),
                statement["approval_expires_at"], self.max_disclosures,
                presence_nonce=(presence_result or {}).get("request_nonce"),
                presence_expires_at=(proof_statement or {}).get("expires_at"))
            if not ok:
                self._local.use_count = None
                raise DisclosureError(reason)
            self._local.use_count = count

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

    def search_token(self, statement, signature):
        """A scope token for an approved search.

        A stage 3 disclosure service has no separate approved-scope operation,
        so this is the plate's blind index. The enumeration concern that
        motivates `search-token` on a custodian applies here too, and is
        threat-model finding 1's residual: this endpoint answers for any plate
        the application names.
        """
        return self.blind_index(statement["target_plate"])

    def blind_index(self, plate):
        """Ask the service for a scope token.

        The application cannot compute this itself by design: holding the
        index key would let a compromised application enumerate the
        low-entropy plate space offline. Here each request is authenticated,
        rate limited, and recorded in the service's own ledger.
        """
        return self._post("/index", {"plate": plate})["plate_index"]

    def disclose(self, rows, statement, signature_hex, requester,
                 proof_statement=None, proof=None):
        if len(rows) > MAX_ROWS_PER_REQUEST:
            raise DisclosureError(f"too many candidate rows for one disclosure ({len(rows)})")
        payload = {
            "rows": [{k: row.get(k) for k in WIRE_FIELDS} for row in rows],
            "statement": statement,
            "signature": signature_hex,
            "requester": requester,
        }
        if proof_statement is not None:
            # Carried, never interpreted: this client does not decide whether
            # presence was adequate. The service holds the requester's
            # enrolled key and makes that judgement for itself.
            payload["presence"] = proof_statement
            payload["presence_proof"] = proof
        result = self._post("/disclose", payload)
        return result.get("opened", [])


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------

def key_file_for(db_path):
    base = db_path[:-3] if db_path.endswith(".db") else db_path
    return base + ".disclosure-key"


def encode_key(kem_name, private_hex):
    """Key material that says which suite it belongs to.

    A 32-byte hex string is a valid X25519 key and a valid P-256 scalar, so a
    bare hex file is ambiguous -- and an ambiguity in key material is resolved
    by whichever suite the reader happens to default to, which is how records
    get sealed under a primitive nobody chose.
    """
    return f"{kem_name}:{private_hex}"


def decode_key(material):
    """(kem_name, private_hex). Bare hex is read as X25519, which is what
    every key written before v4 was."""
    text = (material or "").strip()
    if ":" in text:
        name, _, private_hex = text.partition(":")
        return name.strip(), private_hex.strip()
    return kem.X25519_ECDH, text


def disclosure_kem(conn):
    """The suite this database's disclosure key uses.

    Resolved the same way the public key is, and for the same reason: in
    remote mode the application does not own this decision, the service does.
    Asking it is better than defaulting, because a default that disagrees
    with the key holder produces records nobody can open.
    """
    if config.DISCLOSURE_KEM:
        return config.DISCLOSURE_KEM
    stored = crypto_store.get_meta(conn, "disclosure_kem")
    if stored:
        return stored
    if config.DISCLOSURE_URL:
        name = fetch_key_info(config.DISCLOSURE_URL).get("kem")
        if name:
            crypto_store.set_meta(conn, "disclosure_kem", name)
            return name
    # A database sealed before v4 has no record of its suite because there was
    # only one. Do not guess forward.
    return kem.X25519_ECDH


def load_private_key(db_path, create=False, kem_name=None):
    """Resolve the disclosure private key (local mode only).

    Returns the hex scalar. Use `load_private_key_material` when the suite
    matters, which from v4 is everywhere that actually agrees a key.
    """
    return load_private_key_material(db_path, create=create, kem_name=kem_name)[1]


def load_private_key_material(db_path, create=False, kem_name=None):
    """(kem_name, private_hex) for the disclosure key, or (None, None)."""
    if config.DISCLOSURE_PRIVATE_KEY:
        return decode_key(config.DISCLOSURE_PRIVATE_KEY)

    import os
    path = key_file_for(db_path)
    if os.path.exists(path):
        with open(path, "r") as fh:
            return decode_key(fh.read())
    if not create:
        return None, None

    kem_name = kem_name or kem.DEFAULT_KEM
    private_hex, _ = sealing.generate_keypair(kem_name)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(path, "r") as fh:
            return decode_key(fh.read())
    with os.fdopen(fd, "w") as fh:
        fh.write(encode_key(kem_name, private_hex))
    print(f"[justikey] generated a disclosure key at {path}. In local mode this "
          f"process can open sealed records and holds the index key, so the split "
          f"is structural only. Run scripts/disclosure_server.py for the separated "
          f"service.", file=sys.stderr)
    return kem_name, private_hex


def fetch_key_info(url, timeout=None):
    """What the service will seal to: public key, key id, and suite."""
    try:
        with request.urlopen(url.rstrip("/") + "/publickey",
                             timeout=timeout or config.DISCLOSURE_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except (error.URLError, OSError, ValueError) as exc:
        raise DisclosureError(
            f"could not fetch the disclosure public key from {url}: {exc!r}") from exc


def fetch_public_key(url, timeout=None):
    info = fetch_key_info(url, timeout)
    try:
        return info["public_key"]
    except KeyError as exc:
        raise DisclosureError(
            f"{url} did not return a disclosure public key") from exc


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

    # Creating a key also fixes this database's suite, so record it: a
    # database that cannot say which primitive its records use would have to
    # guess, and guessing is what the suite field exists to prevent.
    existing = crypto_store.get_meta(conn, "disclosure_kem")
    kem_name, private_hex = load_private_key_material(
        db_path, create=create, kem_name=existing or kem.DEFAULT_KEM)
    if private_hex is None:
        return None
    if not existing:
        crypto_store.set_meta(conn, "disclosure_kem", kem_name)
    return sealing.public_from_private(private_hex, kem_name)


def is_remote():
    """True when the index key lives in another process, whichever one.

    A custodian counts. It holds the index key exactly as a disclosure
    service does, so ingest must mint scope tokens there too -- otherwise
    records are indexed under one key and searched under another, and the
    store is silently unsearchable. That is precisely the failure the v1 -> v3
    ceremony was built to catch, and it is available here just as easily.
    """
    return bool(config.DISCLOSURE_URL or config.CUSTODIAN_URL)


def service_for(conn, db_path):
    """Build the disclosure service for this database, or None outside v3."""
    if crypto_store.encryption_mode(conn) != crypto_store.MODE_V3:
        return None

    if config.DISCLOSURE_URL:
        return remote_client()

    if config.CUSTODIAN_URL:
        # The custodian holds the private key and the index key. This process
        # holds neither: it seals against a public key it cannot invert, gets
        # scope tokens from the custodian, and forwards candidates to be
        # opened one at a time.
        from . import custodian as _custodian

        if not config.CUSTODIAN_CLIENT_SECRET:
            raise DisclosureError(
                "a custodian is configured but no client secret is set; "
                "set JUSTIKEY_CUSTODIAN_CLIENT_SECRET")
        client = _custodian.RemoteCustodian(
            url=config.CUSTODIAN_URL, client_id=config.CUSTODIAN_CLIENT_ID,
            client_secret=config.CUSTODIAN_CLIENT_SECRET)
        info = client.key_info()
        return DisclosureService(
            _PublicOnlyOpener(info["public_key"], info["kem"]), None,
            local_approver_registry(conn), usage=UsageStore(db_path),
            requester_registry=local_requester_registry(conn),
            custodian_client=client,
            registry_versions=info.get("registry_versions"))

    kem_name, private_hex = load_private_key_material(db_path)
    if private_hex is None:
        raise DisclosureError(
            "this database seals observations but no disclosure key is available; "
            "set JUSTIKEY_DISCLOSURE_KEY or point at a disclosure service")
    return DisclosureService(sealing.RecordOpener(private_hex, kem_name),
                             crypto_store.resolve_index_key(db_path),
                             local_approver_registry(conn),
                             usage=UsageStore(db_path),
                             requester_registry=local_requester_registry(conn))


def index_client():
    """Whichever process holds the index key for this deployment.

    A custodian takes precedence: when both are configured the custodian is
    the deeper domain and is the one that re-derives scope at disclosure
    time, so it must be the one that minted the index at ingest time.
    """
    if config.CUSTODIAN_URL:
        from . import custodian as _custodian

        # Ingest mints tokens for arbitrary plates, which is a capability the
        # disclosure host must not have. It therefore authenticates with its
        # own secret; a host without that secret cannot index at all.
        if not config.CUSTODIAN_INGEST_SECRET:
            raise DisclosureError(
                "minting a scope token for an arbitrary plate is the ingest "
                "capability, and this host holds no ingest secret. Set "
                "JUSTIKEY_CUSTODIAN_INGEST_SECRET on the ingest host only -- a "
                "host with both this capability and the sealed archive can map "
                "every record without opening one.")
        return _custodian.RemoteCustodian(
            url=config.CUSTODIAN_URL, client_id="ingest",
            client_secret=config.CUSTODIAN_INGEST_SECRET)
    return remote_client()


def remote_client():
    """The client for a configured disclosure service.

    Deliberately not gated on the store's encryption mode, unlike
    `service_for`. Scope tokens are needed *during* a migration, while meta
    still says v1, so a client that existed only for a v3 store would make the
    migration impossible in the very configuration it targets.
    """
    if not config.DISCLOSURE_URL:
        raise DisclosureError("no disclosure service is configured")
    if not config.DISCLOSURE_CLIENT_SECRET:
        raise DisclosureError(
            "a disclosure service is configured but no client secret is set; "
            "set JUSTIKEY_DISCLOSURE_CLIENT_SECRET")
    return RemoteDisclosureService(config.DISCLOSURE_URL, config.DISCLOSURE_CLIENT_ID,
                                   config.DISCLOSURE_CLIENT_SECRET)


def _registry(conn, role):
    """Enrolled keys for one role, as the local-mode service sees them.

    In remote mode the service keeps its own enrolment and never asks the
    application, which is what stops a compromised application from
    presenting a key it controls.

    A live hardware credential wins over the software key: a principal who
    has enrolled an authenticator should not still be accepted on a password.
    """
    rows = conn.execute(
        "SELECT id, username, signing_pub, signing_key_revoked_at FROM users "
        "WHERE role=? AND signing_pub IS NOT NULL", (role,)).fetchall()
    registry = {}
    for row in rows:
        entry = {"public_key": row["signing_pub"],
                 "revoked": bool(row["signing_key_revoked_at"])}
        hardware = conn.execute(
            "SELECT credential_id, public_key, sign_count, rp_id, origin "
            "FROM webauthn_credentials WHERE user_id=? AND revoked_at IS NULL "
            "ORDER BY created_at ASC LIMIT 1", (row["id"],)).fetchone()
        if hardware is not None:
            entry["webauthn"] = dict(hardware)
        registry[row["username"]] = entry
    return registry


class _PublicOnlyOpener:
    """Stands where the opener used to, and cannot open anything.

    With a custodian configured this process has no private key at all, so
    what fills the opener's place must be incapable rather than merely
    unused -- if a code path ever reaches it, that path is a bug and should
    fail loudly instead of quietly working.
    """

    def __init__(self, public_hex, kem_name):
        self.public_hex = public_hex
        self.kem = kem_name
        self.key_id = kem.key_id(kem_name, bytes.fromhex(public_hex))

    def accepts(self, recipient_key_id):
        return recipient_key_id == self.key_id

    def open(self, *args, **kwargs):
        raise DisclosureError(
            "this process holds no disclosure private key; opening goes "
            "through the custodian")


def local_approver_registry(conn):
    return _registry(conn, "approver")


def local_requester_registry(conn):
    return _registry(conn, "requester")
