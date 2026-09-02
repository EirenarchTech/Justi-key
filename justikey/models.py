"""Data-access layer: users, sessions, LPR events, and authorizations."""
import hashlib
import hmac
from datetime import timedelta

from . import config, crypto_store, crypto_utils, timeutil


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def create_user(conn, username, password, role, totp_secret=None):
    pw_hash, salt = crypto_utils.hash_password(password)
    secret = totp_secret or crypto_utils.generate_totp_secret()
    cipher = cipher_for(conn)
    if cipher is None:
        stored, secret_ct = secret, None
    else:
        # A TOTP secret is a standing credential: whoever reads it can mint
        # valid second factors forever, so it must not sit in the clear.
        stored, secret_ct = "", cipher.encrypt(secret, crypto_store.user_aad("totp_secret", username))
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, salt, totp_secret, totp_secret_ct, "
        "role, created_at) VALUES (?,?,?,?,?,?,?)",
        (username, pw_hash, salt, stored, secret_ct, role, timeutil.now_iso()),
    )
    return cur.lastrowid


def totp_secret_for(conn, user):
    """Recover a user's TOTP secret, decrypting when stored encrypted."""
    if user["totp_secret_ct"]:
        cipher = cipher_for(conn)
        if cipher is None:
            raise crypto_store.EncryptionError(
                "this user's TOTP secret is encrypted but no data key is available")
        return cipher.decrypt(user["totp_secret_ct"],
                              crypto_store.user_aad("totp_secret", user["username"]))
    return user["totp_secret"]


def get_user_by_username(conn, username):
    return conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()


def get_user_by_id(conn, user_id):
    return conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def get_username(conn, user_id):
    row = get_user_by_id(conn, user_id)
    return row["username"] if row else "unknown"


# ---------------------------------------------------------------------------
# TOTP replay prevention
# ---------------------------------------------------------------------------

def consume_totp(conn, user, code, purpose):
    """Verify a TOTP code and atomically mark that code as spent.

    Returns True only if the code is valid *and* has not already been used
    for this purpose. RFC 6238 calls for single-use codes; without this a
    captured code stays usable for its whole time step, so an approver
    could rubber-stamp several requests with one code.
    """
    counter = crypto_utils.match_totp_counter(totp_secret_for(conn, user), code)
    if counter is None:
        return False
    # INSERT OR IGNORE against the (user, counter, purpose) primary key makes
    # the claim atomic: a second attempt inserts nothing and is rejected.
    cur = conn.execute(
        "INSERT OR IGNORE INTO used_totp (user_id, counter, purpose, used_at) VALUES (?,?,?,?)",
        (user["id"], counter, purpose, timeutil.now_iso()),
    )
    return cur.rowcount == 1


# ---------------------------------------------------------------------------
# Sessions (login is two-step: password -> pending session -> TOTP -> full session)
# ---------------------------------------------------------------------------

def _create_session(conn, user_id, kind, lifetime_seconds):
    token = crypto_utils.new_token()
    token_hash = crypto_utils.hash_token(token)
    csrf_token = crypto_utils.new_token(16)
    now_dt = timeutil.now()
    expires = timeutil.to_canonical(now_dt + timedelta(seconds=lifetime_seconds))
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, kind, created_at, expires_at) "
        "VALUES (?,?,?,?,?,?)",
        (token_hash, user_id, csrf_token, kind, timeutil.to_canonical(now_dt), expires),
    )
    return token


def create_pending_session(conn, user_id):
    return _create_session(conn, user_id, "pending", config.PENDING_LOGIN_LIFETIME_SECONDS)


def create_full_session(conn, user_id):
    purge_expired_sessions(conn)
    return _create_session(conn, user_id, "full", config.SESSION_LIFETIME_SECONDS)


def purge_expired_sessions(conn):
    """Drop sessions past their expiry so the table does not grow forever."""
    conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (timeutil.now_iso(),))


def get_session(conn, token, kind=None):
    if not token:
        return None
    token_hash = crypto_utils.hash_token(token)
    row = conn.execute("SELECT * FROM sessions WHERE token_hash=?", (token_hash,)).fetchone()
    if not row:
        return None
    if row["expires_at"] <= timeutil.now_iso():
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
        return None
    if kind and row["kind"] != kind:
        return None
    return row


def delete_session(conn, token):
    if not token:
        return
    conn.execute("DELETE FROM sessions WHERE token_hash=?", (crypto_utils.hash_token(token),))


# ---------------------------------------------------------------------------
# LPR events (protected event store)
# ---------------------------------------------------------------------------

def cipher_for(conn):
    """The field cipher for this database, or None when stored in the clear.

    Used for operational secrets (TOTP, source signing secrets) in every mode,
    and for observation fields only under v1. Under v2, observations are
    sealed per record and this cipher cannot open them.

    Cached on the connection: deriving subkeys per row would be wasteful, and
    the key-check must not be re-run on every query.
    """
    if not conn._cipher_loaded:
        conn._cipher = crypto_store.open_cipher(conn, conn.db_path or "")
        conn._cipher_loaded = True
    return conn._cipher


def sealer_for(conn):
    """The record sealer for this database, or None outside v3.

    Deliberately built from the public key alone: the write path must not be
    able to open what it has written.
    """
    if not conn._sealer_loaded:
        conn._sealer = None
        if crypto_store.encryption_mode(conn) == crypto_store.MODE_V3:
            from . import disclosure, sealing
            public_hex = disclosure.public_key_for(conn, conn.db_path or "")
            if public_hex is None:
                raise crypto_store.EncryptionError(
                    "this database seals observations but no disclosure public key is available")
            conn._sealer = sealing.RecordSealer(public_hex)
        conn._sealer_loaded = True
    return conn._sealer


def scope_token(conn, plate):
    """The blind index for a plate.

    In remote mode this application has no index key, so it asks the
    disclosure service. Holding the key locally would let a compromised
    application enumerate the low-entropy plate space offline against the
    stored indexes -- recovering plate identities without decrypting anything.
    """
    from . import disclosure
    if disclosure.is_remote():
        if not conn._index_client:
            conn._index_client = disclosure.service_for(conn, conn.db_path or "")
        return conn._index_client.blind_index(plate)
    return cipher_for(conn).blind_index(plate)


def insert_event(conn, plate, captured_at, camera_id, confidence, location, source_id,
                 source_ref=None, adapter=None):
    """Store an observation, encrypting the protected fields when enabled.

    `source_id` is the vendor's own label for the feed -- a claim carried in
    the payload. `source_ref` is the registered source that actually proved
    its identity with a credential. Only the latter is trustworthy, and it is
    what provenance and audit attribution use.
    """
    captured_at = timeutil.parse(captured_at)
    sealer = sealer_for(conn)
    if sealer is not None:
        # v3: seal to the disclosure public key. Nothing on this path can read
        # the result back, and the envelope is bound to this sighting.
        index = scope_token(conn, plate)
        env = sealer.seal({"plate": plate, "location": location},
                          captured_at, camera_id, index)
        cur = conn.execute(
            "INSERT INTO lpr_events (plate, captured_at, camera_id, confidence, location, "
            "source_id, source_ref, adapter, plate_index, record_ct, wrapped_key, "
            "ephemeral_pub, record_uid, seal_version, recipient_key_id, ingested_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("", captured_at, camera_id, confidence, None, source_id, source_ref, adapter,
             index, env["record_ct"], env["wrapped_key"], env["ephemeral_pub"],
             env["record_uid"], env["seal_version"], env["recipient_key_id"],
             timeutil.now_iso()))
        return cur.lastrowid

    cipher = cipher_for(conn)
    if cipher is None:
        stored_plate, plate_index, plate_ct = plate, None, None
        stored_location, location_ct = location, None
    else:
        # The legacy plate column keeps its NOT NULL constraint, so an
        # encrypted row stores an empty string there and carries the real
        # value in plate_ct. Empty means "look in the ciphertext column".
        stored_plate, stored_location = "", None
        plate_index = cipher.blind_index(plate)
        plate_ct = cipher.encrypt(plate, crypto_store.event_aad("plate", captured_at, camera_id))
        location_ct = cipher.encrypt(
            location, crypto_store.event_aad("location", captured_at, camera_id))

    cur = conn.execute(
        "INSERT INTO lpr_events (plate, captured_at, camera_id, confidence, location, "
        "source_id, source_ref, adapter, plate_index, plate_ct, location_ct, ingested_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (stored_plate, captured_at, camera_id, confidence, stored_location, source_id,
         source_ref, adapter, plate_index, plate_ct, location_ct, timeutil.now_iso()),
    )
    return cur.lastrowid


def _reveal_event(cipher, row):
    """Return an observation as a plain dict, decrypting if necessary."""
    event = dict(row)
    if cipher is not None and row["plate_ct"]:
        event["plate"] = cipher.decrypt(
            row["plate_ct"], crypto_store.event_aad("plate", row["captured_at"], row["camera_id"]))
        event["location"] = cipher.decrypt(
            row["location_ct"],
            crypto_store.event_aad("location", row["captured_at"], row["camera_id"]))
    return event


def search_events(conn, plate, start, end):
    """Exact-plate lookup inside a time window.

    The match runs against the keyed blind index, so the query never handles
    plaintext. Under v2 the rows come back still sealed: this function has no
    way to open them, and disclosure goes through the disclosure service.
    Under v1 the caller's cipher reveals them as before.
    """
    cipher = cipher_for(conn)
    if cipher is None:
        rows = conn.execute(
            "SELECT * FROM lpr_events WHERE plate=? AND captured_at>=? AND captured_at<=? "
            "ORDER BY captured_at ASC", (plate, start, end)).fetchall()
        return [dict(r) for r in rows]

    rows = conn.execute(
        "SELECT * FROM lpr_events WHERE plate_index=? AND captured_at>=? AND captured_at<=? "
        "ORDER BY captured_at ASC", (scope_token(conn, plate), start, end)).fetchall()
    if crypto_store.encryption_mode(conn) == crypto_store.MODE_V3:
        return [dict(r) for r in rows]          # still sealed, deliberately
    return [_reveal_event(cipher, r) for r in rows]


def count_events(conn):
    return conn.execute("SELECT COUNT(*) c FROM lpr_events").fetchone()["c"]


# ---------------------------------------------------------------------------
# Authorizations (warrant / legal-authority requests)
# ---------------------------------------------------------------------------

def parse_datetime_local_utc(value):
    """Interpret an HTML datetime-local value ("YYYY-MM-DDTHH:MM") as UTC."""
    return timeutil.parse(value)


def create_authorization(conn, case_number, legal_authority, purpose, target_plate,
                          window_start, window_end, requested_by):
    cur = conn.execute(
        "INSERT INTO authorizations "
        "(case_number, legal_authority, purpose, target_plate, window_start, window_end, "
        " requested_by, requested_at, status) "
        "VALUES (?,?,?,?,?,?,?,?, 'pending')",
        (case_number, legal_authority, purpose, target_plate.strip().upper(),
         window_start, window_end, requested_by, timeutil.now_iso()),
    )
    return cur.lastrowid


def get_authorization(conn, auth_id):
    return conn.execute("SELECT * FROM authorizations WHERE id=?", (auth_id,)).fetchone()


_AUTH_WITH_NAMES = """
SELECT a.*, u.username AS requester_username, ap.username AS approver_username
FROM authorizations a
JOIN users u ON u.id = a.requested_by
LEFT JOIN users ap ON ap.id = a.approved_by
"""


def list_authorizations(conn, user):
    """List authorizations, resolving usernames in the same query.

    Scoped to need-to-know. A requester sees only their own. An approver sees
    what is pending review plus what they personally decided -- enough to do
    the job and to be accountable for it, without handing every approver a
    browsable history of every plate the agency has ever investigated. Only
    the auditor, whose function is oversight, sees everything.
    """
    if user["role"] == "requester":
        return conn.execute(
            _AUTH_WITH_NAMES + " WHERE a.requested_by=? ORDER BY a.requested_at DESC",
            (user["id"],),
        ).fetchall()
    if user["role"] == "approver":
        return conn.execute(
            _AUTH_WITH_NAMES + " WHERE a.status='pending' OR a.approved_by=? "
            "ORDER BY a.requested_at DESC", (user["id"],),
        ).fetchall()
    return conn.execute(_AUTH_WITH_NAMES + " ORDER BY a.requested_at DESC").fetchall()


def get_authorization_with_names(conn, auth_id):
    return conn.execute(_AUTH_WITH_NAMES + " WHERE a.id=?", (auth_id,)).fetchone()


def list_active_authorizations_for_user(conn, user_id):
    return conn.execute(
        "SELECT * FROM authorizations WHERE requested_by=? AND status='approved' "
        "AND approval_expires_at > ? ORDER BY approved_at DESC",
        (user_id, timeutil.now_iso()),
    ).fetchall()


def approve_authorization(conn, auth_id, approver_id, signing_key=None):
    """Approve a pending request, refusing self-approval.

    The status check and the write are one conditional UPDATE so that two
    approvers acting at the same instant cannot both succeed, and so the
    self-approval prohibition cannot be raced past.

    When a signing key is supplied the approver also signs the exact scope
    approved, and that signature is stored alongside the status. The
    signature is produced before the write, so an approval is never recorded
    without the evidence that backs it.
    """
    from . import approvals

    auth_row = get_authorization(conn, auth_id)
    if auth_row is None:
        return False, "not_found"

    now_dt = timeutil.now()
    approved_at = timeutil.to_canonical(now_dt)
    expires = timeutil.to_canonical(now_dt + timedelta(seconds=config.APPROVAL_VALIDITY_SECONDS))

    signature = None
    if signing_key is not None:
        approver = get_user_by_id(conn, approver_id)
        requester = get_user_by_id(conn, auth_row["requested_by"])
        if approver is None or requester is None:
            return False, "not_found"
        from . import sealing as _sealing
        statement = approvals.build_statement(
            auth_row, requester["username"], approver["username"], approved_at, expires,
            approver_key_id=_sealing.key_id(approver["signing_pub"]) if approver["signing_pub"] else None)
        signature = approvals.sign_statement(signing_key, statement)

    cur = conn.execute(
        "UPDATE authorizations SET status='approved', approved_by=?, approved_at=?, "
        "approval_expires_at=?, approval_signature=? "
        "WHERE id=? AND status='pending' AND requested_by<>?",
        (approver_id, approved_at, expires, signature, auth_id, approver_id),
    )
    if cur.rowcount == 1:
        return True, None
    return False, _why_review_failed(conn, auth_id, approver_id, "self_approval_forbidden")


def set_signing_key(conn, user_id, public_hex, wrapped, salt):
    conn.execute(
        "UPDATE users SET signing_pub=?, signing_key_ct=?, signing_key_salt=? WHERE id=?",
        (public_hex, wrapped, salt, user_id))


def deny_authorization(conn, auth_id, approver_id, reason):
    cur = conn.execute(
        "UPDATE authorizations SET status='denied', approved_by=?, approved_at=?, denial_reason=? "
        "WHERE id=? AND status='pending' AND requested_by<>?",
        (approver_id, timeutil.now_iso(), reason, auth_id, approver_id),
    )
    if cur.rowcount == 1:
        return True, None
    return False, _why_review_failed(conn, auth_id, approver_id, "self_review_forbidden")


def _why_review_failed(conn, auth_id, approver_id, self_reason):
    """Explain why a guarded review UPDATE matched no row."""
    row = get_authorization(conn, auth_id)
    if row is None:
        return "not_found"
    if row["requested_by"] == approver_id:
        return self_reason
    return "not_pending"


def record_disclosure(conn, auth_id):
    """Count one use of an authorization.

    Done as a single guarded UPDATE so concurrent searches cannot both slip
    past the cap by reading the same count.
    """
    conn.execute(
        "UPDATE authorizations SET disclosure_count = disclosure_count + 1 WHERE id=?",
        (auth_id,))
    row = conn.execute(
        "SELECT disclosure_count FROM authorizations WHERE id=?", (auth_id,)).fetchone()
    return row["disclosure_count"] if row else 0


def count_pending_authorizations(conn):
    return conn.execute("SELECT COUNT(*) c FROM authorizations WHERE status='pending'").fetchone()["c"]


def count_active_authorizations(conn):
    return conn.execute(
        "SELECT COUNT(*) c FROM authorizations WHERE status='approved' AND approval_expires_at > ?",
        (timeutil.now_iso(),),
    ).fetchone()["c"]


def effective_status(auth_row):
    if auth_row["status"] == "approved" and auth_row["approval_expires_at"] <= timeutil.now_iso():
        return "expired"
    return auth_row["status"]


# ---------------------------------------------------------------------------
# API keys (sensor / edge-device ingest authentication)
# ---------------------------------------------------------------------------

def has_api_key(conn):
    return conn.execute("SELECT 1 FROM api_keys LIMIT 1").fetchone() is not None


def create_api_key(conn, key, label):
    conn.execute(
        "INSERT INTO api_keys (key_hash, label, created_at) VALUES (?,?,?)",
        (crypto_utils.hash_token(key), label, timeutil.now_iso()),
    )


def verify_api_key(conn, key):
    if not key:
        return False
    return conn.execute(
        "SELECT 1 FROM api_keys WHERE key_hash=?", (crypto_utils.hash_token(key),)
    ).fetchone() is not None


# ---------------------------------------------------------------------------
# Brute-force resistance
# ---------------------------------------------------------------------------

def login_lock_remaining(conn, username):
    """Seconds this account is locked for, or 0.

    Without this, PBKDF2's cost is the only thing slowing an attacker down,
    which bounds the guess rate but never stops it.
    """
    row = conn.execute(
        "SELECT locked_until FROM login_failures WHERE username=?", (username,)).fetchone()
    if not row or not row["locked_until"]:
        return 0
    now = timeutil.now()
    locked_until = timeutil.parse_dt(row["locked_until"])
    return max(0, int((locked_until - now).total_seconds()))


def record_login_failure(conn, username):
    """Count a failed sign-in, locking the account once the threshold is hit.

    Returns (failures, locked_seconds).
    """
    now = timeutil.now()
    row = conn.execute(
        "SELECT failures FROM login_failures WHERE username=?", (username,)).fetchone()
    failures = (row["failures"] if row else 0) + 1
    locked_until = None
    if config.MAX_FAILED_LOGINS > 0 and failures >= config.MAX_FAILED_LOGINS:
        locked_until = timeutil.to_canonical(
            now + timedelta(seconds=config.LOCKOUT_SECONDS))
    conn.execute(
        "INSERT INTO login_failures (username, failures, locked_until, last_failure_at) "
        "VALUES (?,?,?,?) ON CONFLICT(username) DO UPDATE SET "
        "failures=excluded.failures, locked_until=excluded.locked_until, "
        "last_failure_at=excluded.last_failure_at",
        (username, failures, locked_until, timeutil.to_canonical(now)))
    return failures, (config.LOCKOUT_SECONDS if locked_until else 0)


def clear_login_failures(conn, username):
    conn.execute("DELETE FROM login_failures WHERE username=?", (username,))


def count_audit_entries(conn):
    return conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"]


# ---------------------------------------------------------------------------
# Sensor sources: registered feeds and their credentials
# ---------------------------------------------------------------------------

def create_source(conn, source_key, display_name, adapter="justikey", operator=None,
                  auth_mode="bearer"):
    cur = conn.execute(
        "INSERT INTO sources (source_key, display_name, adapter, operator, auth_mode, "
        "status, created_at) VALUES (?,?,?,?,?, 'active', ?)",
        (source_key, display_name, adapter, operator, auth_mode, timeutil.now_iso()),
    )
    return cur.lastrowid


def get_source(conn, source_id):
    return conn.execute("SELECT * FROM sources WHERE id=?", (source_id,)).fetchone()


def get_source_by_key(conn, source_key):
    return conn.execute("SELECT * FROM sources WHERE source_key=?", (source_key,)).fetchone()


def list_sources(conn):
    return conn.execute(
        "SELECT s.*, "
        "(SELECT COUNT(*) FROM source_credentials c "
        "  WHERE c.source_id = s.id AND c.revoked_at IS NULL) AS active_credentials, "
        "(SELECT COUNT(*) FROM lpr_events e WHERE e.source_ref = s.id) AS observation_count "
        "FROM sources s ORDER BY s.created_at ASC"
    ).fetchall()


def issue_source_credential(conn, source_id, label="default"):
    """Mint a new ingest credential. Returns the raw value, shown once.

    A bearer source stores only the hash: the server never needs the secret
    back. A signing source must recompute an HMAC, so its secret is stored
    encrypted instead -- which is why encryption at rest is a prerequisite
    for signing mode.
    """
    key = crypto_utils.new_token(24)
    source = get_source(conn, source_id)
    secret_ct = None
    if source is not None and source["auth_mode"] == "hmac":
        cipher = cipher_for(conn)
        if cipher is None:
            raise crypto_store.EncryptionError(
                "signing sources require encryption at rest, so the shared secret "
                "is not stored in the clear")
        secret_ct = cipher.encrypt(key, crypto_store.source_aad(source["source_key"]))
    conn.execute(
        "INSERT INTO source_credentials (key_hash, source_id, label, secret_ct, created_at) "
        "VALUES (?,?,?,?,?)",
        (crypto_utils.hash_token(key), source_id, label, secret_ct, timeutil.now_iso()),
    )
    return key


# --- Signed ingest -----------------------------------------------------------

def signing_secrets_for(conn, source):
    """Every live signing secret for a source, so rotation overlaps cleanly."""
    cipher = cipher_for(conn)
    if cipher is None:
        return []
    rows = conn.execute(
        "SELECT secret_ct FROM source_credentials WHERE source_id=? AND revoked_at IS NULL "
        "AND secret_ct IS NOT NULL", (source["id"],)).fetchall()
    aad = crypto_store.source_aad(source["source_key"])
    return [cipher.decrypt(r["secret_ct"], aad) for r in rows]


def signature_base(timestamp, nonce, body):
    """Bytes a sender signs: request time, nonce, and a digest of the body.

    Covering the body means a captured request cannot be edited in flight;
    covering the nonce and timestamp means it cannot be replayed.
    """
    digest = hashlib.sha256(body or b"").hexdigest()
    return f"{timestamp}\n{nonce}\n{digest}".encode("utf-8")


def compute_signature(secret, timestamp, nonce, body):
    return hmac.new(secret.encode("utf-8"),
                    signature_base(timestamp, nonce, body), hashlib.sha256).hexdigest()


def claim_ingest_nonce(conn, source_id, nonce):
    """Spend a nonce once. False means it was already used -- a replay."""
    cur = conn.execute(
        "INSERT OR IGNORE INTO ingest_nonces (source_id, nonce, seen_at) VALUES (?,?,?)",
        (source_id, nonce, timeutil.now_iso()))
    return cur.rowcount == 1


def purge_ingest_nonces(conn):
    """Forget nonces older than the freshness window; they can no longer be
    replayed anyway, because their timestamps are already too old."""
    cutoff = timeutil.to_canonical(
        timeutil.now() - timedelta(seconds=config.INGEST_SIGNATURE_WINDOW_SECONDS * 2))
    conn.execute("DELETE FROM ingest_nonces WHERE seen_at < ?", (cutoff,))


def authenticate_signed_source(conn, key_id, timestamp, nonce, signature, body):
    """Verify a signed ingest request. Returns (source, reason)."""
    if not all([key_id, timestamp, nonce, signature]):
        return None, "missing signature headers"
    source = get_source_by_key(conn, key_id)
    if source is None or source["status"] != "active":
        return None, "unknown or inactive source"
    if source["auth_mode"] != "hmac":
        # Refuse to let a signing source be downgraded to bearer.
        return None, "source is not configured for signed requests"

    try:
        skew = abs((timeutil.now() - timeutil.parse_dt(timestamp)).total_seconds())
    except ValueError:
        return None, "malformed timestamp"
    if skew > config.INGEST_SIGNATURE_WINDOW_SECONDS:
        return None, "timestamp outside the accepted window"

    expected = [compute_signature(s, timestamp, nonce, body)
                for s in signing_secrets_for(conn, source)]
    if not any(hmac.compare_digest(e, signature) for e in expected):
        return None, "signature mismatch"

    # Signature checked before the nonce is spent, so an unauthenticated
    # caller cannot burn a legitimate sender's nonces.
    if not claim_ingest_nonce(conn, source["id"], nonce):
        return None, "nonce already used (replay)"
    purge_ingest_nonces(conn)
    return source, None


def authenticate_source(conn, key):
    """Resolve an ingest credential to the source that owns it.

    Returns the source row, or None when the key is unknown, the credential
    has been revoked, or the source itself is no longer active. Revoking one
    credential or one source leaves every other feed untouched -- the reason
    identity is per-source rather than one shared key.

    Signing sources are refused here, not merely at the HTTP layer. Presenting
    a signing secret as a bearer token would strip the replay and integrity
    protection the source was configured for, and a downgrade must fail in the
    primitive rather than depend on every caller remembering to re-check.
    """
    if not key:
        return None
    row = conn.execute(
        "SELECT s.* FROM source_credentials c JOIN sources s ON s.id = c.source_id "
        "WHERE c.key_hash = ? AND c.revoked_at IS NULL AND s.status = 'active' "
        "AND s.auth_mode = 'bearer'",
        (crypto_utils.hash_token(key),),
    ).fetchone()
    return row


def revoke_signing_key(conn, user_id):
    """Retire an approver's signing key; approvals under it stop verifying."""
    conn.execute("UPDATE users SET signing_key_revoked_at=? WHERE id=?",
                 (timeutil.now_iso(), user_id))


def revoke_source(conn, source_id, status="revoked"):
    conn.execute(
        "UPDATE sources SET status=?, revoked_at=? WHERE id=?",
        (status, timeutil.now_iso() if status == "revoked" else None, source_id),
    )


def reactivate_source(conn, source_id):
    conn.execute(
        "UPDATE sources SET status='active', revoked_at=NULL WHERE id=?", (source_id,))


def revoke_source_credentials(conn, source_id):
    """Revoke every outstanding key for a source, e.g. to rotate them."""
    cur = conn.execute(
        "UPDATE source_credentials SET revoked_at=? WHERE source_id=? AND revoked_at IS NULL",
        (timeutil.now_iso(), source_id),
    )
    return cur.rowcount


def count_sources(conn, status="active"):
    return conn.execute(
        "SELECT COUNT(*) c FROM sources WHERE status=?", (status,)).fetchone()["c"]
