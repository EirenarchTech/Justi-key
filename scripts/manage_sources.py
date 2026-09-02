#!/usr/bin/env python3
"""Register and manage sensor feeds.

Every camera, edge device, or upstream ALPR system that sends observations
to JustiKey is a registered source with its own credential. That is what
makes a single vendor revocable without interrupting anyone else, and what
lets an observation's provenance be trusted.

    manage_sources.py list
    manage_sources.py register gate-north "North gate camera" --adapter justikey
    manage_sources.py issue-key gate-north --label replacement
    manage_sources.py rotate gate-north
    manage_sources.py suspend gate-north
    manage_sources.py revoke gate-north
    manage_sources.py reactivate gate-north
    manage_sources.py adapters
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import adapters, audit, config, db, models, timeutil  # noqa: E402


def _resolve(conn, source_key):
    source = models.get_source_by_key(conn, source_key)
    if source is None:
        print(f"No such source: {source_key}")
        sys.exit(2)
    return source


def cmd_list(conn, args):
    rows = models.list_sources(conn)
    if not rows:
        print("No sources registered.")
        return
    print(f"{'KEY':<20} {'STATUS':<10} {'AUTH':<7} {'ADAPTER':<19} {'KEYS':>4} {'EVENTS':>7}  NAME")
    for r in rows:
        print(f"{r['source_key']:<20} {r['status']:<10} {r['auth_mode']:<7} {r['adapter']:<19} "
              f"{r['active_credentials']:>4} {r['observation_count']:>7}  {r['display_name']}")


def cmd_adapters(conn, args):
    print("Available payload adapters:")
    for name in adapters.available():
        doc = (adapters._REGISTRY[name].__doc__ or "").strip().splitlines()
        print(f"  {name:<20} {doc[0] if doc else ''}")


def cmd_register(conn, args):
    if models.get_source_by_key(conn, args.source_key):
        print(f"Source already exists: {args.source_key}")
        sys.exit(2)
    if args.adapter not in adapters.available():
        print(f"Unknown adapter {args.adapter!r}. Available: {', '.join(adapters.available())}")
        sys.exit(2)
    source_id = models.create_source(conn, args.source_key, args.display_name,
                                     adapter=args.adapter, operator=args.operator,
                                     auth_mode=args.auth_mode)
    key = models.issue_source_credential(conn, source_id, "initial")
    audit.append_event(conn, "source_registered", args.actor, {
        "source_key": args.source_key, "adapter": args.adapter,
        "operator": args.operator, "auth_mode": args.auth_mode})
    print(f"Registered source '{args.source_key}' "
          f"(adapter: {args.adapter}, auth: {args.auth_mode})")
    print(f"  {'signing secret' if args.auth_mode == 'hmac' else 'ingest key'}: {key}")
    print("  Shown once. Store it in the sender's configuration now.")
    if args.auth_mode == "hmac":
        print("  This source signs each request; the secret never goes on the wire, "
              "and captured requests cannot be replayed.")


def cmd_issue_key(conn, args):
    source = _resolve(conn, args.source_key)
    key = models.issue_source_credential(conn, source["id"], args.label)
    audit.append_event(conn, "source_credential_issued", args.actor, {
        "source_key": args.source_key, "label": args.label})
    print(f"Issued a new key for '{args.source_key}' (label: {args.label})")
    print(f"  ingest key: {key}")
    print("  Existing keys remain valid; use 'rotate' to retire them.")


def cmd_rotate(conn, args):
    """Issue a replacement key, then retire the old ones.

    Deliberately two steps in one command: the new key is minted and printed
    before the old ones are revoked, so an operator always has the
    replacement in hand at the moment the feed stops accepting the old.
    """
    source = _resolve(conn, args.source_key)
    # Capture exactly which credentials existed before minting the
    # replacement, so the new key cannot be caught by its own rotation.
    previous = [r["key_hash"] for r in conn.execute(
        "SELECT key_hash FROM source_credentials WHERE source_id=? AND revoked_at IS NULL",
        (source["id"],))]
    key = models.issue_source_credential(conn, source["id"], args.label)
    retired = 0
    if previous:
        now = timeutil.now_iso()
        placeholders = ",".join("?" * len(previous))
        retired = conn.execute(
            f"UPDATE source_credentials SET revoked_at=? WHERE key_hash IN ({placeholders})",
            [now, *previous],
        ).rowcount
    audit.append_event(conn, "source_credentials_rotated", args.actor, {
        "source_key": args.source_key, "retired": retired})
    print(f"Rotated credentials for '{args.source_key}': {retired} key(s) retired")
    print(f"  new ingest key: {key}")


def cmd_suspend(conn, args):
    source = _resolve(conn, args.source_key)
    models.revoke_source(conn, source["id"], status="suspended")
    audit.append_event(conn, "source_suspended", args.actor, {"source_key": args.source_key})
    print(f"Suspended '{args.source_key}'. Its observations are refused until reactivated; "
          f"records already collected are unaffected.")


def cmd_revoke(conn, args):
    source = _resolve(conn, args.source_key)
    models.revoke_source(conn, source["id"], status="revoked")
    count = models.revoke_source_credentials(conn, source["id"])
    audit.append_event(conn, "source_revoked", args.actor, {
        "source_key": args.source_key, "credentials_revoked": count})
    print(f"Revoked '{args.source_key}' and {count} credential(s). Every other feed is unaffected.")
    print("Observations already collected are retained; revocation stops new ones.")


def cmd_reactivate(conn, args):
    source = _resolve(conn, args.source_key)
    models.reactivate_source(conn, source["id"])
    audit.append_event(conn, "source_reactivated", args.actor, {"source_key": args.source_key})
    active = conn.execute(
        "SELECT COUNT(*) c FROM source_credentials WHERE source_id=? AND revoked_at IS NULL",
        (source["id"],)).fetchone()["c"]
    print(f"Reactivated '{args.source_key}' ({active} active credential(s)).")
    if not active:
        print("  It has no usable key; run 'issue-key' before it can send.")


def main():
    parser = argparse.ArgumentParser(description="Manage JustiKey sensor sources")
    parser.add_argument("--db", default=config.DB_PATH)
    parser.add_argument("--actor", default=os.environ.get("USER", "operator"),
                        help="name recorded in the audit ledger for this action")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list registered sources").set_defaults(fn=cmd_list)
    sub.add_parser("adapters", help="list available payload adapters").set_defaults(fn=cmd_adapters)

    p = sub.add_parser("register", help="register a new source and issue its first key")
    p.add_argument("source_key")
    p.add_argument("display_name")
    p.add_argument("--adapter", default="justikey")
    p.add_argument("--operator", help="owning agency or vendor")
    p.add_argument("--auth-mode", choices=("bearer", "hmac"), default="bearer",
                   dest="auth_mode",
                   help="bearer sends the key each request; hmac signs instead "
                        "(recommended: adds replay protection)")
    p.set_defaults(fn=cmd_register)

    for name, fn, helptext in (
        ("issue-key", cmd_issue_key, "issue an additional key for a source"),
        ("rotate", cmd_rotate, "issue a new key and retire the previous ones"),
        ("suspend", cmd_suspend, "temporarily stop accepting a source's observations"),
        ("revoke", cmd_revoke, "permanently revoke a source and its credentials"),
        ("reactivate", cmd_reactivate, "return a suspended or revoked source to service"),
    ):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("source_key")
        if name in ("issue-key", "rotate"):
            p.add_argument("--label", default="rotated")
        p.set_defaults(fn=fn)

    args = parser.parse_args()
    if not os.path.exists(args.db):
        print(f"Database not found: {args.db}")
        sys.exit(2)
    db.init_db(args.db)
    conn = db.get_connection(args.db)
    try:
        args.fn(conn, args)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
