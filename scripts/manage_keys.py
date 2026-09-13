#!/usr/bin/env python3
"""Signing keys and hardware authenticators.

Stage 4 of docs/capability-model.md.

Two jobs. First, enrolling a WebAuthn authenticator for a person, so their
private key stops existing on this host at all. Second, exporting the
registries the disclosure service reads -- which until now had to be
hand-written, and a hand-written registry of public keys is a file where one
wrong paste quietly enrols an attacker's key.

    python3 scripts/manage_keys.py list --db justikey.db
    python3 scripts/manage_keys.py enrol --db justikey.db --user officer1 \\
        --credential-id <base64url> --public-key <base64url COSE> --label "YubiKey 5"
    python3 scripts/manage_keys.py revoke --db justikey.db --credential-id <base64url>
    python3 scripts/manage_keys.py export --db justikey.db \\
        --approvers approvers.json --requesters requesters.json

WHERE THE ENROLMENT VALUES COME FROM

`--credential-id` and `--public-key` are what a WebAuthn registration
ceremony returns: `credential.rawId` and the COSE public key from the
attestation object, both base64url. This tool does not run that ceremony --
it needs a browser and an authenticator, and JustiKey's web interface does
not yet implement the registration page. Verification of the assertions those
credentials later produce is fully implemented and tested
(justikey/webauthn.py), so a deployment that has the enrolment values by any
means can use hardware today.

EXPORT IS A ONE-WAY COPY

The service holds its own registry precisely so that a compromised
application cannot change who it trusts. Exporting writes a file; moving that
file to the service's host is a deliberate human act, and should be, because
that is the moment someone decides which keys count.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import (audit, config, custody, db, models,  # noqa: E402
                      registry, webauthn)

ROLES = ("requester", "approver")


def registry_for(conn, role):
    """Exactly what the disclosure service should hold for this role."""
    rows = conn.execute(
        "SELECT id, username, signing_pub, signing_key_revoked_at FROM users "
        "WHERE role=? AND signing_pub IS NOT NULL ORDER BY username", (role,)).fetchall()
    registry = {}
    for row in rows:
        entry = {"public_key": row["signing_pub"],
                 "revoked": bool(row["signing_key_revoked_at"])}
        hardware = conn.execute(
            "SELECT credential_id, public_key, sign_count, rp_id, origin "
            "FROM webauthn_credentials WHERE user_id=? AND revoked_at IS NULL "
            "ORDER BY created_at ASC LIMIT 1", (row["id"],)).fetchone()
        if hardware is not None:
            entry["webauthn"] = dict(hardware)
        registry[row["username"]] = entry
    return registry


def cmd_list(args, conn):
    for role in ROLES:
        rows = conn.execute(
            "SELECT id, username, signing_pub, signing_key_revoked_at FROM users "
            "WHERE role=? ORDER BY username", (role,)).fetchall()
        print(f"\n{role}s")
        if not rows:
            print("  (none)")
            continue
        for row in rows:
            if not row["signing_pub"]:
                print(f"  {row['username']:<16} no signing key")
                continue
            state = "REVOKED" if row["signing_key_revoked_at"] else "active"
            credentials = models.webauthn_credentials_for(conn, row["id"])
            custody_label = "hardware" if credentials else "software (password-wrapped)"
            print(f"  {row['username']:<16} {state:<8} {custody_label}")
            for credential in credentials:
                print(f"      {credential['label']} "
                      f"[{credential['credential_id'][:16]}...] "
                      f"sign_count={credential['sign_count']} "
                      f"rp={credential['rp_id'] or '(unset)'}")


def cmd_enrol(args, conn):
    user = models.get_user_by_username(conn, args.user)
    if user is None:
        raise SystemExit(f"no such user: {args.user}")
    if user["role"] not in ROLES:
        raise SystemExit(f"{args.user} is a {user['role']}, which does not sign anything")

    # Validate the key here rather than discovering it is unusable at the one
    # moment it matters, which would be a disclosure being refused.
    try:
        cose = webauthn.decode_cose_key(webauthn.b64url_decode(args.public_key))
    except webauthn.WebAuthnError as exc:
        raise SystemExit(f"that public key is not usable: {exc}")

    rp_id = args.rp_id or config.WEBAUTHN_RP_ID
    origin = args.origin or config.WEBAUTHN_ORIGIN
    if not rp_id or not origin:
        raise SystemExit(
            "an rp id and origin are required (--rp-id/--origin or "
            "JUSTIKEY_WEBAUTHN_RP_ID/JUSTIKEY_WEBAUTHN_ORIGIN): without them an "
            "assertion for another site could not be told apart from one for this one")

    models.enrol_webauthn_credential(
        conn, user["id"], args.credential_id, args.public_key, args.label,
        rp_id=rp_id, origin=origin, sign_count=args.sign_count)
    audit.append_event(conn, "webauthn_credential_enrolled", args.actor, {
        "user": args.user, "label": args.label, "rp_id": rp_id,
        "algorithm": cose["algorithm"],
        "credential_id": args.credential_id[:16] + "..."})

    print(f"Enrolled {args.label} for {args.user}.")
    print(f"  algorithm : {'ES256' if cose['algorithm'] == webauthn.ALG_ES256 else 'Ed25519'}")
    print(f"  rp / origin: {rp_id} / {origin}")
    print("\nFrom now on this account's software signature is refused: enrolling")
    print("hardware raises the bar rather than adding an alternative to it. Export")
    print("the registry and move it to the disclosure service to take effect there.")


def cmd_revoke(args, conn):
    row = conn.execute("SELECT * FROM webauthn_credentials WHERE credential_id=?",
                       (args.credential_id,)).fetchone()
    if row is None:
        raise SystemExit("no such credential")
    if row["revoked_at"]:
        print("Already revoked.")
        return
    models.revoke_webauthn_credential(conn, args.credential_id)
    audit.append_event(conn, "webauthn_credential_revoked", args.actor, {
        "label": row["label"], "credential_id": args.credential_id[:16] + "..."})
    user = models.get_user_by_id(conn, row["user_id"])
    print(f"Revoked {row['label']} for {user['username'] if user else 'unknown'}.")
    print("They fall back to their password-wrapped software key. Re-export the")
    print("registry, or the service will keep demanding an authenticator they no")
    print("longer have.")


def cmd_export(args, conn):
    if not args.approvers and not args.requesters:
        raise SystemExit("nothing to export: pass --approvers and/or --requesters")
    for path, role in ((args.approvers, "approver"), (args.requesters, "requester")):
        if not path:
            continue
        principals = registry_for(conn, role)

        # Version moves forward only when the contents actually change.
        # Bumping on every export would train the service's operators to
        # expect version changes, which is exactly when a swapped registry
        # stops standing out.
        previous_version, previous = 0, None
        if os.path.exists(path):
            with open(path, "r") as fh:
                previous_version, previous = registry.unwrap(json.load(fh))
        changed = previous is None or registry.digest(previous) != registry.digest(principals)
        version = previous_version + 1 if changed else previous_version

        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(registry.wrap(principals, version), fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        hardware = sum(1 for entry in principals.values() if entry.get("webauthn"))
        revoked = sum(1 for entry in principals.values() if entry["revoked"])
        print(f"{path}: v{version} ({'changed' if changed else 'unchanged'}), "
              f"{len(principals)} {role}(s), {hardware} on hardware, {revoked} revoked")
    audit.append_event(conn, "key_registry_exported", args.actor, {
        "approvers": bool(args.approvers), "requesters": bool(args.requesters)})
    print("\nMove these to the disclosure service's host and restart it with")
    print("--approvers / --requesters. The service reads them there and never asks")
    print("this application, which is what stops a compromised application from")
    print("choosing whose keys count.")
    print("\nThe version is what stops an older copy being restored later: the")
    print("service records it and refuses to start on anything lower.")


COMMANDS = {"list": cmd_list, "enrol": cmd_enrol, "revoke": cmd_revoke, "export": cmd_export}


def main():
    parser = argparse.ArgumentParser(description="JustiKey signing keys and authenticators")
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("--db", default=config.DB_PATH)
    parser.add_argument("--actor", default=os.environ.get("USER", "operator"))
    parser.add_argument("--user", help="username to enrol an authenticator for")
    parser.add_argument("--credential-id", help="base64url credential id from registration")
    parser.add_argument("--public-key", help="base64url COSE public key from registration")
    parser.add_argument("--label", default="security key", help="how to name this device")
    parser.add_argument("--rp-id", help="WebAuthn relying-party id")
    parser.add_argument("--origin", help="WebAuthn origin, e.g. https://justikey.example")
    parser.add_argument("--sign-count", type=int, default=0)
    parser.add_argument("--approvers", help="write the approver registry here")
    parser.add_argument("--requesters", help="write the requester registry here")
    args = parser.parse_args()

    if args.command == "enrol" and not all([args.user, args.credential_id, args.public_key]):
        parser.error("enrol needs --user, --credential-id and --public-key")
    if args.command == "revoke" and not args.credential_id:
        parser.error("revoke needs --credential-id")
    if not os.path.exists(args.db):
        raise SystemExit(f"Database not found: {args.db}")

    conn = db.get_connection(args.db)
    try:
        COMMANDS[args.command](args, conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
