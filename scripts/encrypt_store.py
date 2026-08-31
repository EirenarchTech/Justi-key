#!/usr/bin/env python3
"""Encrypt an existing plaintext database in place.

A database created before encryption existed holds plate and location values
in the clear. init_db deliberately will not switch such a database over on
its own: a half-encrypted store is worse than either state, because callers
cannot tell which rows are protected.

This migration is explicit, transactional, and audited. It rewrites every
observation and TOTP secret into ciphertext, records the key-check canary,
and only then marks the database encrypted. If it fails partway, the
transaction rolls back and the database is left exactly as it was.

    python3 scripts/encrypt_store.py --db justikey.db            # dry run
    python3 scripts/encrypt_store.py --db justikey.db --apply

BACK UP FIRST, and make sure the key is one you will still have tomorrow.
Losing it means losing every protected record: that is the point of
encryption, and it cuts both ways.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import audit, config, crypto_store, db, timeutil  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Encrypt a JustiKey database at rest")
    parser.add_argument("--db", default=config.DB_PATH)
    parser.add_argument("--apply", action="store_true", help="perform the migration")
    parser.add_argument("--actor", default=os.environ.get("USER", "operator"))
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"Database not found: {args.db}")
        sys.exit(2)
    if not crypto_store.CRYPTOGRAPHY_AVAILABLE:
        print("The 'cryptography' package is required: pip install cryptography")
        sys.exit(2)

    db.init_db(args.db)
    conn = db.get_connection(args.db)
    try:
        if crypto_store.encryption_mode(conn) == crypto_store.MODE_V1:
            print("This database is already encrypted.")
            return

        events = conn.execute(
            "SELECT COUNT(*) c FROM lpr_events WHERE plate <> ''").fetchone()["c"]
        users = conn.execute(
            "SELECT COUNT(*) c FROM users WHERE totp_secret <> ''").fetchone()["c"]
        print(f"To encrypt: {events} observation(s), {users} TOTP secret(s)")
        if not args.apply:
            print("\nDry run. Back up the database, then re-run with --apply.")
            return

        root = crypto_store.load_root_key(crypto_store.key_file_for(args.db), create=True)
        cipher = crypto_store.FieldCipher(root)

        conn.execute("BEGIN IMMEDIATE")
        try:
            for row in conn.execute(
                    "SELECT id, plate, location, captured_at, camera_id FROM lpr_events "
                    "WHERE plate <> ''").fetchall():
                conn.execute(
                    "UPDATE lpr_events SET plate='', location=NULL, plate_index=?, "
                    "plate_ct=?, location_ct=? WHERE id=?",
                    (cipher.blind_index(row["plate"]),
                     cipher.encrypt(row["plate"], crypto_store.event_aad(
                         "plate", row["captured_at"], row["camera_id"])),
                     cipher.encrypt(row["location"], crypto_store.event_aad(
                         "location", row["captured_at"], row["camera_id"])),
                     row["id"]))

            for row in conn.execute(
                    "SELECT id, username, totp_secret FROM users "
                    "WHERE totp_secret <> ''").fetchall():
                conn.execute(
                    "UPDATE users SET totp_secret='', totp_secret_ct=? WHERE id=?",
                    (cipher.encrypt(row["totp_secret"],
                                    crypto_store.user_aad("totp_secret", row["username"])),
                     row["id"]))

            crypto_store.set_meta(conn, "encryption_mode", crypto_store.MODE_V1)
            crypto_store.set_meta(conn, "key_check", cipher.canary())
            crypto_store.set_meta(conn, "encrypted_at", timeutil.now_iso())
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

        audit.append_event(conn, "store_encrypted", args.actor, {
            "observations": events, "totp_secrets": users, "mode": crypto_store.MODE_V1})
        print(f"Encrypted {events} observation(s) and {users} TOTP secret(s).")
        print(f"Key file: {crypto_store.key_file_for(args.db)}")
        print("Move that key off this host (JUSTIKEY_DATA_KEY from a secrets manager); "
              "a key stored beside the database only protects against a stolen file.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
