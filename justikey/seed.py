"""Deterministic demonstration accounts.

Creates one requester, one approver, and one auditor so the entire
two-person authorization workflow can be exercised locally without any
external identity provider. A production deployment would replace these
with enterprise identity management and hardware-backed MFA.
"""
from . import crypto_utils, db, models

DEMO_USERS = [
    ("officer1", "Requester#2026!", "requester"),
    ("supervisor1", "Approver#2026!", "approver"),
    ("auditor1", "Auditor#2026!", "auditor"),
]


def seed(db_path=None):
    db.init_db(db_path)
    conn = db.get_connection(db_path)
    try:
        created = []
        for username, password, role in DEMO_USERS:
            if models.get_user_by_username(conn, username):
                continue
            secret = crypto_utils.generate_totp_secret()
            models.create_user(conn, username, password, role, totp_secret=secret)
            created.append((username, password, role, secret))

        api_key = None
        if not models.has_api_key(conn):
            api_key = crypto_utils.new_token(24)
            models.create_api_key(conn, api_key, "default-sensor-key")

        return created, api_key
    finally:
        conn.close()
