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

# Only set JUSTIKEY_COOKIE_SECURE=1 when serving over HTTPS (production).
COOKIE_SECURE = os.environ.get("JUSTIKEY_COOKIE_SECURE", "0") == "1"

# Genesis hash for the audit hash chain (seq 0, no prior entry).
GENESIS_HASH = "0" * 64

INGEST_API_KEY_HEADER = "X-API-Key"

SESSION_COOKIE_NAME = "jk_session"
PENDING_COOKIE_NAME = "jk_pending"
