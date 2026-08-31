"""SQLite schema and connection helpers.

Uses only the Python standard library (sqlite3).

Connections are opened in autocommit mode so that code needing atomicity
can request it explicitly with BEGIN IMMEDIATE (see audit.append_event),
rather than relying on sqlite3's implicit transaction handling. The
server is threaded, so a busy timeout is set to make concurrent writers
wait for the write lock instead of failing outright.
"""
import sqlite3

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    totp_secret TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('requester', 'approver', 'auditor')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    csrf_token TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'full',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- Records a TOTP code that has already been spent, so the same code cannot
-- be replayed within the same security context. Scoped by purpose so that
-- each approval requires its own fresh code (an approver cannot rubber-stamp
-- several requests with one code) without forcing a user to wait out a full
-- time step between signing in and acting.
CREATE TABLE IF NOT EXISTS used_totp (
    user_id INTEGER NOT NULL REFERENCES users(id),
    counter INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    used_at TEXT NOT NULL,
    PRIMARY KEY (user_id, counter, purpose)
);

CREATE TABLE IF NOT EXISTS lpr_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plate TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    camera_id TEXT NOT NULL,
    confidence REAL NOT NULL,
    location TEXT,
    source_id TEXT,
    ingested_at TEXT NOT NULL
);
-- Authorized search always filters on plate AND a captured_at range, so a
-- composite index serves the whole predicate and returns rows already
-- ordered. It also covers plate-only lookups, so no separate plate index
-- is needed.
CREATE INDEX IF NOT EXISTS idx_events_plate_time ON lpr_events(plate, captured_at);
DROP INDEX IF EXISTS idx_events_plate;
DROP INDEX IF EXISTS idx_events_captured_at;

CREATE TABLE IF NOT EXISTS authorizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number TEXT NOT NULL,
    legal_authority TEXT NOT NULL,
    purpose TEXT NOT NULL,
    target_plate TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    requested_by INTEGER NOT NULL REFERENCES users(id),
    requested_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    approved_by INTEGER REFERENCES users(id),
    approved_at TEXT,
    approval_expires_at TEXT,
    denial_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_requested_by ON authorizations(requested_by);
CREATE INDEX IF NOT EXISTS idx_auth_status ON authorizations(status);

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

CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def get_connection(db_path=None):
    conn = sqlite3.connect(db_path or config.DB_PATH, timeout=config.SQLITE_BUSY_TIMEOUT_SECONDS)
    conn.row_factory = sqlite3.Row
    # Autocommit: transactions are opened explicitly where atomicity matters.
    conn.isolation_level = None
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = %d" % int(config.SQLITE_BUSY_TIMEOUT_SECONDS * 1000))
    # WAL lets readers proceed while a writer holds the lock. Ignored for
    # in-memory databases, which tests use.
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def init_db(db_path=None):
    conn = get_connection(db_path)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()
