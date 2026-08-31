"""Data-access layer: users, sessions, LPR events, and authorizations."""
from datetime import datetime, timedelta, timezone

from . import audit, config, crypto_utils


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def create_user(conn, username, password, role, totp_secret=None):
    pw_hash, salt = crypto_utils.hash_password(password)
    secret = totp_secret or crypto_utils.generate_totp_secret()
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, salt, totp_secret, role, created_at) "
        "VALUES (?,?,?,?,?,?)",
        (username, pw_hash, salt, secret, role, audit.now_iso()),
    )
    conn.commit()
    return cur.lastrowid


def get_user_by_username(conn, username):
    return conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()


def get_user_by_id(conn, user_id):
    return conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def get_username(conn, user_id):
    row = get_user_by_id(conn, user_id)
    return row["username"] if row else "unknown"


# ---------------------------------------------------------------------------
# Sessions (login is two-step: password -> pending session -> TOTP -> full session)
# ---------------------------------------------------------------------------

def _create_session(conn, user_id, kind, lifetime_seconds):
    token = crypto_utils.new_token()
    token_hash = crypto_utils.hash_token(token)
    csrf_token = crypto_utils.new_token(16)
    now = audit.now_iso()
    expires = (datetime.now(timezone.utc) + timedelta(seconds=lifetime_seconds)).isoformat()
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, kind, created_at, expires_at) "
        "VALUES (?,?,?,?,?,?)",
        (token_hash, user_id, csrf_token, kind, now, expires),
    )
    conn.commit()
    return token


def create_pending_session(conn, user_id):
    return _create_session(conn, user_id, "pending", config.PENDING_LOGIN_LIFETIME_SECONDS)


def create_full_session(conn, user_id):
    return _create_session(conn, user_id, "full", config.SESSION_LIFETIME_SECONDS)


def get_session(conn, token, kind=None):
    if not token:
        return None
    token_hash = crypto_utils.hash_token(token)
    row = conn.execute("SELECT * FROM sessions WHERE token_hash=?", (token_hash,)).fetchone()
    if not row:
        return None
    if row["expires_at"] < audit.now_iso():
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
        conn.commit()
        return None
    if kind and row["kind"] != kind:
        return None
    return row


def delete_session(conn, token):
    if not token:
        return
    conn.execute("DELETE FROM sessions WHERE token_hash=?", (crypto_utils.hash_token(token),))
    conn.commit()


# ---------------------------------------------------------------------------
# LPR events (protected event store)
# ---------------------------------------------------------------------------

def insert_event(conn, plate, captured_at, camera_id, confidence, location, source_id):
    cur = conn.execute(
        "INSERT INTO lpr_events (plate, captured_at, camera_id, confidence, location, source_id, ingested_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (plate, captured_at, camera_id, confidence, location, source_id, audit.now_iso()),
    )
    conn.commit()
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
    """Interpret an HTML datetime-local value ("YYYY-MM-DDTHH:MM[:SS]") as UTC."""
    dt = datetime.fromisoformat(value)
    dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def create_authorization(conn, case_number, legal_authority, purpose, target_plate,
                          window_start, window_end, requested_by):
    cur = conn.execute(
        "INSERT INTO authorizations "
        "(case_number, legal_authority, purpose, target_plate, window_start, window_end, "
        " requested_by, requested_at, status) "
        "VALUES (?,?,?,?,?,?,?,?, 'pending')",
        (case_number, legal_authority, purpose, target_plate.strip().upper(),
         window_start, window_end, requested_by, audit.now_iso()),
    )
    conn.commit()
    return cur.lastrowid


def get_authorization(conn, auth_id):
    return conn.execute("SELECT * FROM authorizations WHERE id=?", (auth_id,)).fetchone()


def list_authorizations(conn, user):
    if user["role"] == "requester":
        return conn.execute(
            "SELECT * FROM authorizations WHERE requested_by=? ORDER BY requested_at DESC",
            (user["id"],),
        ).fetchall()
    return conn.execute("SELECT * FROM authorizations ORDER BY requested_at DESC").fetchall()


def list_active_authorizations_for_user(conn, user_id):
    now = audit.now_iso()
    return conn.execute(
        "SELECT * FROM authorizations WHERE requested_by=? AND status='approved' "
        "AND approval_expires_at > ? ORDER BY approved_at DESC",
        (user_id, now),
    ).fetchall()


def approve_authorization(conn, auth_id, approver_id):
    auth_row = get_authorization(conn, auth_id)
    if auth_row is None:
        return False, "not_found"
    if auth_row["status"] != "pending":
        return False, "not_pending"
    if auth_row["requested_by"] == approver_id:
        return False, "self_approval_forbidden"
    now_dt = datetime.now(timezone.utc)
    expires = (now_dt + timedelta(seconds=config.APPROVAL_VALIDITY_SECONDS)).isoformat()
    conn.execute(
        "UPDATE authorizations SET status='approved', approved_by=?, approved_at=?, "
        "approval_expires_at=? WHERE id=?",
        (approver_id, now_dt.isoformat(), expires, auth_id),
    )
    conn.commit()
    return True, None


def deny_authorization(conn, auth_id, approver_id, reason):
    auth_row = get_authorization(conn, auth_id)
    if auth_row is None:
        return False, "not_found"
    if auth_row["status"] != "pending":
        return False, "not_pending"
    if auth_row["requested_by"] == approver_id:
        return False, "self_review_forbidden"
    conn.execute(
        "UPDATE authorizations SET status='denied', approved_by=?, approved_at=?, denial_reason=? "
        "WHERE id=?",
        (approver_id, audit.now_iso(), reason, auth_id),
    )
    conn.commit()
    return True, None


def count_pending_authorizations(conn):
    return conn.execute("SELECT COUNT(*) c FROM authorizations WHERE status='pending'").fetchone()["c"]


def count_active_authorizations(conn):
    now = audit.now_iso()
    return conn.execute(
        "SELECT COUNT(*) c FROM authorizations WHERE status='approved' AND approval_expires_at > ?",
        (now,),
    ).fetchone()["c"]


def effective_status(auth_row):
    if auth_row["status"] == "approved" and auth_row["approval_expires_at"] < audit.now_iso():
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
        (crypto_utils.hash_token(key), label, audit.now_iso()),
    )
    conn.commit()


def verify_api_key(conn, key):
    if not key:
        return False
    return conn.execute(
        "SELECT 1 FROM api_keys WHERE key_hash=?", (crypto_utils.hash_token(key),)
    ).fetchone() is not None


def count_audit_entries(conn):
    return conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"]
