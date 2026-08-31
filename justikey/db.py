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
    -- The feed name the payload claimed: a hint for troubleshooting, never
    -- an identity.
    source_id TEXT,
    -- The registered source that actually authenticated, and the payload
    -- format it arrived in. These are the trustworthy provenance fields.
    source_ref INTEGER REFERENCES sources(id),
    adapter TEXT,
    ingested_at TEXT NOT NULL
);
-- The index on source_ref is created by migrate(), not here: on an existing
-- database this script runs before the column has been added, and indexing a
-- column that does not yet exist would abort the whole upgrade.
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

-- A registered sensor feed: one camera, one edge device, or one upstream
-- ALPR system. Every observation is attributed to the source proven by the
-- credential it authenticated with, never to a name the payload claims.
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_key TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    adapter TEXT NOT NULL DEFAULT 'justikey',
    operator TEXT,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active', 'suspended', 'revoked')),
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

-- Credentials are separate from identity so a key can be rotated, or one of
-- several issued keys revoked, without disturbing the source's history or
-- the provenance already recorded against it.
CREATE TABLE IF NOT EXISTS source_credentials (
    key_hash TEXT PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    label TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_source_credentials_source ON source_credentials(source_id);
"""

# Columns added to lpr_events after the original schema shipped. Applied by
# init_db so existing databases pick them up.
EVENT_COLUMNS = (
    # The authenticated source: which registered feed proved its identity.
    ("source_ref", "INTEGER REFERENCES sources(id)"),
    # Which payload format this observation arrived in.
    ("adapter", "TEXT"),
)


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


def migrate(conn):
    """Apply additive schema changes to an existing database."""
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(lpr_events)")}
    for column, decl in EVENT_COLUMNS:
        if column not in existing:
            conn.execute(f"ALTER TABLE lpr_events ADD COLUMN {column} {decl}")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_source_ref ON lpr_events(source_ref)")

    # Keys issued before per-source identity existed still work, but are now
    # attributed to an explicit legacy source rather than to whatever name a
    # payload claimed. Their raw values were never stored, so the hashes move
    # across as-is.
    orphans = conn.execute(
        "SELECT key_hash, label, created_at FROM api_keys WHERE key_hash NOT IN "
        "(SELECT key_hash FROM source_credentials)"
    ).fetchall()
    if orphans:
        from . import timeutil
        now = timeutil.now_iso()
        row = conn.execute("SELECT id FROM sources WHERE source_key=?", ("legacy-api-key",)).fetchone()
        if row is None:
            cur = conn.execute(
                "INSERT INTO sources (source_key, display_name, adapter, operator, status, created_at) "
                "VALUES (?,?,?,?,?,?)",
                ("legacy-api-key", "Legacy shared ingest key", "justikey",
                 "pre-migration", "active", now))
            source_id = cur.lastrowid
        else:
            source_id = row["id"]
        for orphan in orphans:
            conn.execute(
                "INSERT INTO source_credentials (key_hash, source_id, label, created_at) "
                "VALUES (?,?,?,?)",
                (orphan["key_hash"], source_id, orphan["label"], orphan["created_at"]))


def init_db(db_path=None):
    conn = get_connection(db_path)
    try:
        conn.executescript(SCHEMA)
        migrate(conn)
    finally:
        conn.close()
