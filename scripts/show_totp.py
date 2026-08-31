#!/usr/bin/env python3
"""Print the current TOTP code for a demo account.

This is a development convenience for the prototype's deterministic demo
accounts, standing in for a real authenticator app. It reads the TOTP
secret directly from the local database, so it only works where the
database file is reachable.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import crypto_utils, db, models  # noqa: E402


def main():
    if len(sys.argv) != 2:
        print("usage: show_totp.py <username>")
        sys.exit(1)
    conn = db.get_connection()
    try:
        user = models.get_user_by_username(conn, sys.argv[1])
        if not user:
            print(f"no such user: {sys.argv[1]}")
            sys.exit(1)
        secret = models.totp_secret_for(conn, user)
    finally:
        conn.close()
    print(crypto_utils.totp_now(secret))


if __name__ == "__main__":
    main()
