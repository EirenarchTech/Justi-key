"""Central configuration for the JustiKey prototype.

All settings are read from environment variables so the demo can be
reconfigured without editing code, with safe local-development defaults.
"""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("JUSTIKEY_DB", os.path.join(BASE_DIR, "justikey.db"))

# Session and authorization lifetimes.
SESSION_LIFETIME_SECONDS = int(os.environ.get("JUSTIKEY_SESSION_LIFETIME", 8 * 3600))
PENDING_LOGIN_LIFETIME_SECONDS = int(os.environ.get("JUSTIKEY_PENDING_LIFETIME", 5 * 60))
APPROVAL_VALIDITY_SECONDS = int(os.environ.get("JUSTIKEY_APPROVAL_VALIDITY", 30 * 60))

# Password hashing.
PBKDF2_ITERATIONS = int(os.environ.get("JUSTIKEY_PBKDF2_ITERATIONS", 200_000))

# How long a writer waits for SQLite's write lock before giving up. The
# server is threaded, so concurrent ingest requests do contend.
SQLITE_BUSY_TIMEOUT_SECONDS = float(os.environ.get("JUSTIKEY_SQLITE_TIMEOUT", 10.0))

# Largest request body accepted, for form posts and sensor observations alike.
MAX_BODY_BYTES = int(os.environ.get("JUSTIKEY_MAX_BODY_BYTES", 64 * 1024))

# Most observations one ingest request may carry. Edge devices reconnecting
# after an outage flush buffered reads in batches.
MAX_BATCH_OBSERVATIONS = int(os.environ.get("JUSTIKEY_MAX_BATCH", 500))

# Only set JUSTIKEY_COOKIE_SECURE=1 when serving over HTTPS (production).
COOKIE_SECURE = os.environ.get("JUSTIKEY_COOKIE_SECURE", "0") == "1"

# Genesis hash for the audit hash chain (seq 0, no prior entry).
GENESIS_HASH = "0" * 64

# --- Audit anchoring -------------------------------------------------------
# A hash chain cannot detect truncation of its own tail: deleting the most
# recent entries leaves a shorter but perfectly valid chain. Anchoring
# publishes signed checkpoints of the chain head to storage the database
# cannot reach, so a missing tail becomes provable.
#
# Leave these unset to derive the anchor log and key from the database path
# (justikey.db -> justikey.anchors.jsonl, justikey.anchor-key). Setting them
# explicitly is how a real deployment puts the anchor log on separate
# storage and the key in a secrets manager.
ANCHOR_PATH = os.environ.get("JUSTIKEY_ANCHOR_PATH") or None
ANCHOR_KEY_FILE = os.environ.get("JUSTIKEY_ANCHOR_KEY_FILE") or None
# Hex-encoded key supplied directly, so the signing key never has to touch
# this host's disk. Takes precedence over the key file.
ANCHOR_KEY_HEX = os.environ.get("JUSTIKEY_ANCHOR_KEY") or None

# Write a checkpoint every N audit entries. 0 disables automatic anchoring
# (anchors can still be created on demand from the CLI or the audit page).
ANCHOR_INTERVAL_ENTRIES = int(os.environ.get("JUSTIKEY_ANCHOR_INTERVAL", 25))

# Optional independent witness. Anchors are also POSTed here, to a service
# outside this application's trust domain -- the control that actually makes
# tail truncation undeniable. See scripts/witness_server.py.
WITNESS_URL = os.environ.get("JUSTIKEY_WITNESS_URL") or None
WITNESS_TIMEOUT_SECONDS = float(os.environ.get("JUSTIKEY_WITNESS_TIMEOUT", 5.0))

INGEST_API_KEY_HEADER = "X-API-Key"

SESSION_COOKIE_NAME = "jk_session"
PENDING_COOKIE_NAME = "jk_pending"
