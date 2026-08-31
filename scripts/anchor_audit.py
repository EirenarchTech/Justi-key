#!/usr/bin/env python3
"""Publish a checkpoint of the audit ledger head.

Anchors are normally written automatically every JUSTIKEY_ANCHOR_INTERVAL
entries. Use this to force one -- before a backup, at the end of a shift, or
from cron so that quiet periods still get witnessed.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import anchor, config, db  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Anchor the JustiKey audit ledger head")
    parser.add_argument("--db", default=config.DB_PATH, help="path to the JustiKey database")
    parser.add_argument("--witness", default=config.WITNESS_URL,
                        help="URL of an independent witness to also notify")
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"Database not found: {args.db}")
        sys.exit(2)

    conn = db.get_connection(args.db)
    try:
        store = anchor.AnchorStore.for_connection(conn)
        if store is None:
            print("Anchoring is unavailable for this database.")
            sys.exit(2)
        record = anchor.create_anchor(conn, store, witness_url=args.witness)
        if record is None:
            seq, _, _ = anchor.chain_head(conn)
            if seq == 0:
                print("Audit ledger is empty; nothing to anchor.")
            else:
                print(f"Head (seq={seq}) is already anchored; nothing to do.")
            sys.exit(0)
        print(f"Anchored audit seq={record['audit_seq']} "
              f"(anchor #{record['anchor_seq']}) -> {store.path}")
        print(f"  head hash : {record['audit_hash']}")
        print(f"  anchor    : {record['hash']}")
        if args.witness:
            print(f"  witness   : submitted to {args.witness}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
