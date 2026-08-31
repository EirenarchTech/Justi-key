#!/usr/bin/env python3
"""Delete observations past their retention period.

Indefinite retention of location history is itself the harm JustiKey exists
to limit. Every control here narrows *who* may look and *when*; none of them
shrink what is available to look at. A record that no longer exists cannot
be disclosed by a future compromise, a future policy change, or a future
subpoena, so deletion is the only control that gets stronger with time.

Deletion is audited: the ledger records how many observations were removed
and the cutoff applied, so a purge is itself reviewable. It never deletes
audit entries -- the record of access outlives the data it describes.

    python3 scripts/enforce_retention.py --db justikey.db          # dry run
    python3 scripts/enforce_retention.py --db justikey.db --apply
    python3 scripts/enforce_retention.py --db justikey.db --days 30 --apply

Run it from cron. A retention policy nobody executes is not a policy.
"""
import argparse
import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import audit, config, db, timeutil  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Apply the JustiKey retention policy")
    parser.add_argument("--db", default=config.DB_PATH)
    parser.add_argument("--days", type=int, default=config.RETENTION_DAYS,
                        help="retain observations captured within this many days")
    parser.add_argument("--apply", action="store_true",
                        help="actually delete; without this it only reports")
    parser.add_argument("--actor", default=os.environ.get("USER", "retention-job"))
    args = parser.parse_args()

    if args.days <= 0:
        print("Retention is disabled (days <= 0); nothing to do.")
        return
    if not os.path.exists(args.db):
        print(f"Database not found: {args.db}")
        sys.exit(2)

    cutoff = timeutil.to_canonical(timeutil.now() - timedelta(days=args.days))
    conn = db.get_connection(args.db)
    try:
        expired = conn.execute(
            "SELECT COUNT(*) c FROM lpr_events WHERE captured_at < ?", (cutoff,)).fetchone()["c"]
        total = conn.execute("SELECT COUNT(*) c FROM lpr_events").fetchone()["c"]
        print(f"Retention: {args.days} days (cutoff {cutoff[:19]}Z)")
        print(f"  observations held   : {total}")
        print(f"  past retention      : {expired}")

        if not expired:
            print("  nothing to delete.")
            return
        if not args.apply:
            print("\n  Dry run. Re-run with --apply to delete them.")
            return

        conn.execute("DELETE FROM lpr_events WHERE captured_at < ?", (cutoff,))
        remaining = conn.execute("SELECT COUNT(*) c FROM lpr_events").fetchone()["c"]
        # Audited so a purge is reviewable, and so an unexplained drop in the
        # event count has a corresponding entry to account for it.
        audit.append_event(conn, "retention_purge", args.actor, {
            "retention_days": args.days, "cutoff": cutoff,
            "deleted": expired, "remaining": remaining,
        })
        print(f"  deleted             : {expired}")
        print(f"  remaining           : {remaining}")
        print("  recorded in the audit ledger.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
