#!/usr/bin/env python3
"""Independent command-line verifier for the JustiKey audit ledger.

Deliberately does not import the justikey package's own audit module —
it re-implements the hash-chain check directly against the SQLite file
so it can act as an independent integrity check, not merely a call back
into the same code that wrote the ledger.
"""
import argparse
import hashlib
import os
import sqlite3
import sys

GENESIS_HASH = "0" * 64


def _entry_hash(seq, timestamp, event_type, actor, details_json, prev_hash):
    payload = "|".join([str(seq), timestamp, event_type, actor, details_json, prev_hash])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT seq, timestamp, event_type, actor, details, prev_hash, hash "
            "FROM audit_log ORDER BY seq ASC"
        ).fetchall()
    finally:
        conn.close()

    expected_prev = GENESIS_HASH
    expected_seq = 1
    for row in rows:
        # A gap means an entry was removed, even if the surviving links
        # still hash correctly among themselves.
        if row["seq"] != expected_seq:
            return False, row["seq"], f"sequence gap: expected seq={expected_seq}, found seq={row['seq']}"
        if row["prev_hash"] != expected_prev:
            return False, row["seq"], "prev_hash does not match the previous entry's hash"
        recomputed = _entry_hash(
            row["seq"], row["timestamp"], row["event_type"], row["actor"], row["details"], row["prev_hash"]
        )
        if recomputed != row["hash"]:
            return False, row["seq"], "stored hash does not match recomputed hash (possible tampering)"
        expected_prev = row["hash"]
        expected_seq += 1
    return True, len(rows), None


def main():
    parser = argparse.ArgumentParser(description="Verify the JustiKey audit ledger hash chain")
    parser.add_argument(
        "db_path", nargs="?", default=os.environ.get("JUSTIKEY_DB", "justikey.db"),
        help="Path to the JustiKey SQLite database (default: justikey.db)",
    )
    args = parser.parse_args()

    if not os.path.exists(args.db_path):
        print(f"Database not found: {args.db_path}")
        sys.exit(2)

    ok, info, reason = verify(args.db_path)
    if ok:
        print(f"OK: audit chain verified, {info} entries, no tampering detected.")
        sys.exit(0)
    else:
        print(f"FAILED: audit chain integrity check failed at entry seq={info}: {reason}")
        sys.exit(1)


if __name__ == "__main__":
    main()
