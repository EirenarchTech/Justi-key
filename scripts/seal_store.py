#!/usr/bin/env python3
"""Migrate a v1 database to per-record sealing (capability model, stage 2).

Under v1 the application holds one symmetric key that opens every
observation. This rewrites each record under its own key, wrapped to a
disclosure public key, after which the application can write observations but
not read them: opening goes through the disclosure service, which requires an
approver's signature.

    python3 scripts/seal_store.py --db justikey.db            # dry run
    python3 scripts/seal_store.py --db justikey.db --apply

The migration needs the v1 data key (to read the records one last time) and
produces a disclosure keypair. BACK UP FIRST. Once sealed, losing the
disclosure private key loses the archive -- that is what the guarantee costs,
and it cuts both ways.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import (audit, config, crypto_store, db, disclosure,  # noqa: E402
                      sealing, timeutil)


def main():
    parser = argparse.ArgumentParser(description="Seal a JustiKey database per record")
    parser.add_argument("--db", default=config.DB_PATH)
    parser.add_argument("--apply", action="store_true", help="perform the migration")
    parser.add_argument("--actor", default=os.environ.get("USER", "operator"))
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"Database not found: {args.db}")
        sys.exit(2)
    if not sealing.SEALING_AVAILABLE:
        print("The 'cryptography' package is required: pip install cryptography")
        sys.exit(2)

    conn = db.get_connection(args.db)
    try:
        mode = crypto_store.encryption_mode(conn)
        if mode == crypto_store.MODE_V2:
            print("This database already seals records per record.")
            return
        if mode != crypto_store.MODE_V1:
            print("This database is not encrypted yet. Run scripts/encrypt_store.py first.")
            sys.exit(2)

        cipher = crypto_store.open_cipher(conn, args.db)
        if cipher is None:
            print("The v1 data key is required to read records before resealing them.")
            sys.exit(2)

        total = conn.execute(
            "SELECT COUNT(*) c FROM lpr_events WHERE plate_ct IS NOT NULL").fetchone()["c"]
        print(f"To seal: {total} observation(s)")
        if not args.apply:
            print("\nDry run. Back up the database, then re-run with --apply.")
            return

        private_hex = disclosure.load_private_key(args.db, create=True)
        public_hex = sealing.public_from_private(private_hex)
        sealer = sealing.RecordSealer(public_hex)

        conn.execute("BEGIN IMMEDIATE")
        try:
            rows = conn.execute(
                "SELECT id, plate_ct, location_ct, captured_at, camera_id FROM lpr_events "
                "WHERE plate_ct IS NOT NULL").fetchall()
            for row in rows:
                plate = cipher.decrypt(
                    row["plate_ct"], crypto_store.event_aad(
                        "plate", row["captured_at"], row["camera_id"]))
                location = cipher.decrypt(
                    row["location_ct"], crypto_store.event_aad(
                        "location", row["captured_at"], row["camera_id"]))
                record_ct, wrapped, ephemeral = sealer.seal(
                    {"plate": plate, "location": location},
                    crypto_store.record_aad(row["captured_at"], row["camera_id"]))
                conn.execute(
                    "UPDATE lpr_events SET record_ct=?, wrapped_key=?, ephemeral_pub=?, "
                    "plate_ct=NULL, location_ct=NULL WHERE id=?",
                    (record_ct, wrapped, ephemeral, row["id"]))

            crypto_store.set_meta(conn, "encryption_mode", crypto_store.MODE_V2)
            crypto_store.set_meta(conn, "disclosure_public_key", public_hex)
            crypto_store.set_meta(conn, "sealed_at", timeutil.now_iso())
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

        audit.append_event(conn, "store_sealed", args.actor, {
            "observations": len(rows), "mode": crypto_store.MODE_V2,
            "disclosure_public_key": public_hex})
        print(f"Sealed {len(rows)} observation(s) under per-record keys.")
        print(f"  disclosure public key : {public_hex}")
        print(f"  disclosure private key: {disclosure.key_file_for(args.db)}")
        print("\nMove the private key off this host (JUSTIKEY_DISCLOSURE_KEY, or a")
        print("separate disclosure service). While it sits here, the application can")
        print("still open records and the split is structural rather than enforced.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
