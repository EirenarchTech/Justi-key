"""Deterministic demonstration accounts.

Creates one requester, one approver, and one auditor so the entire
two-person authorization workflow can be exercised locally without any
external identity provider. A production deployment would replace these
with enterprise identity management and hardware-backed MFA.
"""
from . import crypto_utils, db, models

DEMO_SOURCE_KEY = "demo-simulator"

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
        if models.get_source_by_key(conn, DEMO_SOURCE_KEY) is None:
            source_id = models.create_source(
                conn, DEMO_SOURCE_KEY, "Demo simulator feed",
                adapter="justikey", operator="local-demo")
            api_key = models.issue_source_credential(conn, source_id, "initial")

        return created, api_key
    finally:
        conn.close()
