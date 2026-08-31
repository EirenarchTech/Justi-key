"""Data-access layer: users, sessions, LPR events, and authorizations."""
from datetime import timedelta

from . import config, crypto_utils, timeutil


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def create_user(conn, username, password, role, totp_secret=None):
    pw_hash, salt = crypto_utils.hash_password(password)
    secret = totp_secret or crypto_utils.generate_totp_secret()
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, salt, totp_secret, role, created_at) "
        "VALUES (?,?,?,?,?,?)",
        (username, pw_hash, salt, secret, role, timeutil.now_iso()),
    )
    return cur.lastrowid


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
    counter = crypto_utils.match_totp_counter(user["totp_secret"], code)
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

def insert_event(conn, plate, captured_at, camera_id, confidence, location, source_id):
    cur = conn.execute(
        "INSERT INTO lpr_events (plate, captured_at, camera_id, confidence, location, source_id, ingested_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (plate, timeutil.parse(captured_at), camera_id, confidence, location, source_id,
         timeutil.now_iso()),
    )
    return cur.lastrowid


def search_events(conn, plate, start, end):
    return conn.execute(
        "SELECT * FROM lpr_events WHERE plate=? AND captured_at>=? AND captured_at<=? "
        "ORDER BY captured_at ASC",
        (plate, start, end),
    ).fetchall()


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

    Requesters see only their own; approvers and auditors see all.
    """
    if user["role"] == "requester":
        return conn.execute(
            _AUTH_WITH_NAMES + " WHERE a.requested_by=? ORDER BY a.requested_at DESC",
            (user["id"],),
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


def approve_authorization(conn, auth_id, approver_id):
    """Approve a pending request, refusing self-approval.

    The status check and the write are one conditional UPDATE so that two
    approvers acting at the same instant cannot both succeed, and so the
    self-approval prohibition cannot be raced past.
    """
    now_dt = timeutil.now()
    expires = timeutil.to_canonical(now_dt + timedelta(seconds=config.APPROVAL_VALIDITY_SECONDS))
    cur = conn.execute(
        "UPDATE authorizations SET status='approved', approved_by=?, approved_at=?, "
        "approval_expires_at=? WHERE id=? AND status='pending' AND requested_by<>?",
        (approver_id, timeutil.to_canonical(now_dt), expires, auth_id, approver_id),
    )
    if cur.rowcount == 1:
        return True, None
    return False, _why_review_failed(conn, auth_id, approver_id, "self_approval_forbidden")


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


def count_audit_entries(conn):
    return conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"]
