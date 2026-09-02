"""SQLite schema and connection helpers.

Uses only the Python standard library (sqlite3).

Connections are opened in autocommit mode so that code needing atomicity
can request it explicitly with BEGIN IMMEDIATE (see audit.append_event),
rather than relying on sqlite3's implicit transaction handling. The
server is threaded, so a busy timeout is set to make concurrent writers
wait for the write lock instead of failing outright.
"""
import sqlite3
import sys

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    totp_secret TEXT NOT NULL,
    totp_secret_ct TEXT,
    -- Approver signing key. The private half is wrapped under a key derived
    -- from the approver's password, so the server can only use it while that
    -- approver is actively supplying it.
    signing_pub TEXT,
    signing_key_ct TEXT,
    signing_key_salt TEXT,
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
    -- Encrypted-at-rest columns. plate_index is a keyed HMAC enabling exact
    -- lookup without holding plaintext; plate_ct/location_ct hold the
    -- AES-256-GCM ciphertext. When encryption is on, plate and location are
    -- NULL and these carry the data.
    plate_index TEXT,
    plate_ct TEXT,
    location_ct TEXT,
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
    denial_reason TEXT,
    disclosure_count INTEGER NOT NULL DEFAULT 0,
    -- Ed25519 signature by the approver over the exact scope approved. An
    -- edit to any signed field after approval invalidates it.
    approval_signature TEXT
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
    -- 'bearer' sends the credential on every request; 'hmac' signs each
    -- request instead, so the secret never transits and a captured request
    -- cannot be replayed or modified.
    auth_mode TEXT NOT NULL DEFAULT 'bearer' CHECK(auth_mode IN ('bearer', 'hmac')),
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
    -- Signing sources need the secret itself to recompute an HMAC, so it is
    -- stored encrypted rather than hashed. Bearer sources leave this NULL.
    secret_ct TEXT,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_source_credentials_source ON source_credentials(source_id);

-- Nonces already spent by a signing source. A replayed request reuses its
-- nonce and is refused. Bounded by the signature freshness window, so old
-- rows are purged rather than accumulating forever.
CREATE TABLE IF NOT EXISTS ingest_nonces (
    source_id INTEGER NOT NULL REFERENCES sources(id),
    nonce TEXT NOT NULL,
    seen_at TEXT NOT NULL,
    PRIMARY KEY (source_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_ingest_nonces_seen ON ingest_nonces(seen_at);

-- Per-database settings: encryption mode and the key-check canary.
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Failed sign-in attempts, for lockout. Cleared on a successful sign-in.
CREATE TABLE IF NOT EXISTS login_failures (
    username TEXT PRIMARY KEY,
    failures INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    last_failure_at TEXT NOT NULL
);
"""

# Columns added to lpr_events after the original schema shipped. Applied by
# init_db so existing databases pick them up.
EVENT_COLUMNS = (
    # The authenticated source: which registered feed proved its identity.
    ("source_ref", "INTEGER REFERENCES sources(id)"),
    # Which payload format this observation arrived in.
    ("adapter", "TEXT"),
    # Encryption-at-rest columns (see crypto_store).
    ("plate_index", "TEXT"),
    ("plate_ct", "TEXT"),
    ("location_ct", "TEXT"),
)

AUTHORIZATION_COLUMNS = (
    # How many disclosures this authorization has already produced, so a
    # single approval cannot be replayed indefinitely inside its window.
    ("disclosure_count", "INTEGER NOT NULL DEFAULT 0"),
    ("approval_signature", "TEXT"),
)

USER_COLUMNS = (
    ("totp_secret_ct", "TEXT"),
    ("signing_pub", "TEXT"),
    ("signing_key_ct", "TEXT"),
    ("signing_key_salt", "TEXT"),
)

SOURCE_COLUMNS = (
    ("auth_mode", "TEXT NOT NULL DEFAULT 'bearer'"),
)

CREDENTIAL_COLUMNS = (
    # Signing sources need the secret itself, not just its hash, so it is
    # stored encrypted rather than hashed.
    ("secret_ct", "TEXT"),
)


class Connection(sqlite3.Connection):
    """sqlite3.Connection that can carry per-database state.

    The base class is a C type with no instance dict, so the field cipher and
    the database path -- both needed wherever protected columns are read or
    written -- have nowhere to live without subclassing.
    """
    db_path = None
    _cipher = None
    _cipher_loaded = False


def get_connection(db_path=None):
    path = db_path or config.DB_PATH
    conn = sqlite3.connect(path, timeout=config.SQLITE_BUSY_TIMEOUT_SECONDS,
                           factory=Connection)
    conn.db_path = path
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
    for table, columns in (("lpr_events", EVENT_COLUMNS),
                           ("authorizations", AUTHORIZATION_COLUMNS),
                           ("users", USER_COLUMNS),
                           ("sources", SOURCE_COLUMNS),
                           ("source_credentials", CREDENTIAL_COLUMNS)):
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        for column, decl in columns:
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_source_ref ON lpr_events(source_ref)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_plate_index ON lpr_events(plate_index, captured_at)")

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
        _enable_encryption_if_appropriate(conn)
    finally:
        conn.close()


def _enable_encryption_if_appropriate(conn):
    """Turn on encryption at rest for a database that can safely adopt it.

    Only a database with no existing plaintext observations is switched
    automatically. One that already holds plaintext needs a deliberate,
    audited migration (scripts/encrypt_store.py) rather than silently ending
    up half encrypted, which would be worse than either state.
    """
    from . import crypto_store
    if not config.ENCRYPT_AT_REST or not crypto_store.CRYPTOGRAPHY_AVAILABLE:
        return
    if conn.db_path in (None, "", ":memory:"):
        return
    if crypto_store.encryption_mode(conn) != crypto_store.MODE_NONE:
        return
    plaintext_rows = conn.execute(
        "SELECT COUNT(*) c FROM lpr_events WHERE plate <> ''").fetchone()["c"]
    if plaintext_rows:
        print(f"[justikey] {plaintext_rows} unencrypted observation(s) present; "
              f"run scripts/encrypt_store.py to migrate before encryption is enabled.",
              file=sys.stderr)
        return
    crypto_store.enable_encryption(conn, conn.db_path)
