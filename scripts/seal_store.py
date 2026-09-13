#!/usr/bin/env python3
"""The v1 -> v3 migration ceremony.

Migrating a JustiKey store is not a command, it is a ceremony, because its
last step destroys a key that currently opens every record. Get the order
wrong and you either keep a key that defeats the whole point, or destroy one
that was still the only way to read the archive. So the steps are separate,
each one is checkable, and each one writes what it did:

    plan               what is here, what would change, what would be destroyed
    migrate            reseal every observation per record, then verify
    verify             re-check a migrated store against its manifest
    rekey-credentials  move TOTP and sensor secrets off the legacy key
    destroy-legacy-key prove the legacy key opens nothing, then destroy it

Run them in that order, reading the output each time. Back up the database
and both keys before starting. `migrate` is transactional and rolls back, but
a backup is what makes the decision to go ahead reversible.

WHY `destroy-legacy-key` IS A SEPARATE STEP, AND WHY IT NEEDS `rekey-credentials`

Under v1 one root key protects three different things: observations, users'
TOTP secrets, and sensors' HMAC signing secrets. Sealing the observations
moves only the first out of its reach. Destroying the key at that point would
lock every user out of their second factor and break every signed sensor
feed -- so the ceremony re-keys the credential material under a fresh key
first, and then checks that nothing anywhere still decrypts under the legacy
one. Only a key proven to open nothing is safe to destroy.

THE MANIFEST

Each step appends to a JSON manifest: counts before and after, a digest over
every sealed record, the disclosure key id, what the sample verification
actually proved, and key fingerprints. The manifest is a convenience, not the
evidence: its digest is written into the hash-chained audit ledger at every
step, so an altered manifest is detectable against a chain that is itself
externally anchored.

    python3 scripts/seal_store.py plan --db justikey.db
    python3 scripts/seal_store.py migrate --db justikey.db --approver supervisor1
    python3 scripts/seal_store.py rekey-credentials --db justikey.db
    python3 scripts/seal_store.py destroy-legacy-key --db justikey.db \\
        --confirm "destroy the legacy key for justikey.db"
"""
import argparse
import getpass
import hashlib
import json
import os
import secrets
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import (approvals, audit, config, crypto_store, db,  # noqa: E402
                      disclosure, models, sealing, timeutil)

MANIFEST_VERSION = 1
DEFAULT_SAMPLE = 5


class CeremonyError(RuntimeError):
    """A step refused to proceed. Nothing was changed."""


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def manifest_path_for(db_path, explicit=None):
    if explicit:
        return explicit
    base = db_path[:-3] if db_path.endswith(".db") else db_path
    return base + ".ceremony.json"


def load_manifest(path):
    if not os.path.exists(path):
        return None
    with open(path, "r") as fh:
        return json.load(fh)


def manifest_digest(manifest):
    """A digest over everything except the digest field itself."""
    body = {k: v for k, v in manifest.items() if k != "digest"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def write_manifest(path, manifest):
    manifest["digest"] = manifest_digest(manifest)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    return manifest["digest"]


def record_step(conn, path, manifest, stage, actor, detail):
    """Append one stage to the manifest and anchor its digest in the ledger."""
    manifest.setdefault("stages", []).append(
        dict(detail, stage=stage, at=timeutil.now_iso(), operator=actor))
    digest = write_manifest(path, manifest)
    audit.append_event(conn, f"ceremony_{stage.replace('-', '_')}", actor,
                       dict(detail, ceremony_id=manifest["ceremony_id"],
                            manifest=os.path.basename(path), manifest_digest=digest))
    return digest


# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------

def census(conn):
    """What is actually in this store, by protection format."""
    row = conn.execute("""
        SELECT COUNT(*) total,
               SUM(CASE WHEN plate_ct IS NOT NULL THEN 1 ELSE 0 END) v1,
               SUM(CASE WHEN record_ct IS NOT NULL THEN 1 ELSE 0 END) sealed,
               SUM(CASE WHEN plate_ct IS NULL AND record_ct IS NULL THEN 1 ELSE 0 END) plain
        FROM lpr_events""").fetchone()
    return {"total": row["total"], "v1": row["v1"] or 0,
            "sealed": row["sealed"] or 0, "plaintext": row["plain"] or 0}


def credential_census(conn):
    return {
        "totp_secrets": conn.execute(
            "SELECT COUNT(*) c FROM users WHERE totp_secret_ct IS NOT NULL").fetchone()["c"],
        "source_secrets": conn.execute(
            "SELECT COUNT(*) c FROM source_credentials "
            "WHERE secret_ct IS NOT NULL").fetchone()["c"],
    }


def store_digest(conn):
    """A digest over every sealed record's stored envelope.

    Ciphertext only: this is a fingerprint of the migrated store that anyone
    can recompute later to show nothing was substituted, and it reveals
    nothing about the plates inside.
    """
    digest = hashlib.sha256()
    count = 0
    for row in conn.execute(
            "SELECT id, record_uid, seal_version, recipient_key_id, plate_index, "
            "captured_at, camera_id, record_ct, wrapped_key, ephemeral_pub "
            "FROM lpr_events WHERE record_ct IS NOT NULL ORDER BY id"):
        digest.update(json.dumps([row[k] for k in row.keys()],
                                 separators=(",", ":")).encode("utf-8"))
        count += 1
    return digest.hexdigest(), count


def key_fingerprint(material):
    """Identify a key without disclosing it."""
    if material is None:
        return None
    if isinstance(material, str):
        material = material.encode("utf-8")
    return hashlib.sha256(b"justikey:key-fingerprint:v1" + material).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Sample verification: does the disclosure path actually work now?
# ---------------------------------------------------------------------------

class CeremonyApprover:
    """An ephemeral approver, used only to exercise the disclosure path.

    The point of the sample check is to prove that a migrated record can still
    be found and opened -- the scope lookup, the envelope binding, the key
    wrap. Those are what a migration can break. Whether a real supervisor
    would have approved is not in question here, so in local mode the ceremony
    signs with a throwaway key and enrols it with a service built for this
    check alone. Pass --approver to use a genuine enrolled approver instead,
    which is what a remote service requires.
    """

    def __init__(self, username="ceremony-verifier"):
        self.username = username
        public_hex, wrapped, salt = approvals.generate_signing_key("ceremony")
        self.public_hex = public_hex
        self._key = approvals.unwrap_signing_key(
            {"signing_pub": public_hex, "signing_key_ct": wrapped,
             "signing_key_salt": salt}, "ceremony")

    def sign(self, statement):
        return approvals.sign_statement(self._key, statement)


def ceremony_statement(plate, window_start, window_end, requester, approver,
                       approver_key_id, sequence):
    """A signed scope covering exactly one sampled record."""
    now = timeutil.now_iso()
    row = {"id": -sequence, "case_number": "CEREMONY-VERIFY",
           "legal_authority": "migration ceremony", "purpose": "post-migration verification",
           "target_plate": plate, "window_start": window_start, "window_end": window_end}
    return approvals.build_statement(
        row, requester, approver, now,
        timeutil.to_canonical(timeutil.now() + timedelta(minutes=10)),
        approver_key_id=approver_key_id)


def verify_sample_full(conn, db_path, samples, approver):
    """Open sampled records the way a real request would, and compare.

    `samples` is [(row_id, plate)] captured while the plaintext was still
    readable. Each one goes out through search_events -- which recomputes the
    blind index -- and then through the disclosure service, which re-derives
    scope for itself. A migration that wrote an index the search path cannot
    reproduce would make records permanently unfindable while every row still
    looked correct; this is the check that catches it.
    """
    service = disclosure.service_for(conn, db_path)
    if service is None:
        raise CeremonyError("the store is not in v3 mode, so there is nothing to open")

    if isinstance(service, disclosure.DisclosureService) and isinstance(approver,
                                                                       CeremonyApprover):
        # Enrol the throwaway key for this check only. The real registry is
        # untouched; nothing persists.
        service.approvers = dict(service.approvers)
        service.approvers[approver.username] = {"public_key": approver.public_hex,
                                                "revoked": False}
    results = []
    for sequence, (row_id, plate) in enumerate(samples, start=1):
        row = conn.execute("SELECT captured_at FROM lpr_events WHERE id=?",
                           (row_id,)).fetchone()
        window_start, window_end = row["captured_at"], row["captured_at"]
        statement = ceremony_statement(
            plate, window_start, window_end, "ceremony-requester", approver.username,
            sealing.key_id(approver.public_hex), sequence)
        signature = approver.sign(statement)

        candidates = [dict(r) for r in models.search_events(
            conn, plate, window_start, window_end)]
        found = [c for c in candidates if c["id"] == row_id]
        if not found:
            results.append({"id": row_id, "ok": False,
                            "reason": "the record is no longer findable by its own plate"})
            continue
        try:
            opened = service.disclose(found, statement, signature, "ceremony-requester")
        except (disclosure.DisclosureError, sealing.SealingError) as exc:
            results.append({"id": row_id, "ok": False, "reason": str(exc)})
            continue
        if not opened or opened[0]["plate"] != plate:
            results.append({"id": row_id, "ok": False,
                            "reason": "the opened record did not match what was sealed"})
            continue
        results.append({"id": row_id, "ok": True})
    return results


def verify_sample_structural(conn, db_path, row_ids):
    """Re-open sampled records later, without knowing what they should say.

    Once the plaintext is gone there is nothing to compare against, so this
    proves the weaker but still useful property: the envelope opens under the
    disclosure key, its binding holds, and the plate inside still hashes to
    the blind index stored in the row. Needs the disclosure private key, so it
    runs where that key lives.
    """
    private_hex = disclosure.load_private_key(db_path)
    if private_hex is None:
        return None, "the disclosure private key is not available on this host"
    opener = sealing.RecordOpener(private_hex)
    try:
        index_key = crypto_store.resolve_index_key(db_path)
    except crypto_store.EncryptionError as exc:
        return None, str(exc)

    import hmac
    results = []
    for row_id in row_ids:
        row = conn.execute(
            "SELECT * FROM lpr_events WHERE id=?", (row_id,)).fetchone()
        if row is None or row["record_ct"] is None:
            results.append({"id": row_id, "ok": False, "reason": "record is missing or unsealed"})
            continue
        try:
            fields = opener.open(dict(row), row["captured_at"], row["camera_id"],
                                 row["plate_index"])
        except sealing.SealingError as exc:
            results.append({"id": row_id, "ok": False, "reason": str(exc)})
            continue
        recomputed = hmac.new(index_key, fields["plate"].strip().upper().encode("utf-8"),
                              hashlib.sha256).hexdigest()
        if recomputed != row["plate_index"]:
            results.append({"id": row_id, "ok": False,
                            "reason": "the plate inside does not match the stored index"})
            continue
        results.append({"id": row_id, "ok": True})
    return results, None


def summarize(results):
    ok = sum(1 for r in results if r["ok"])
    return ok, [r for r in results if not r["ok"]]


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

def resolve_approver(conn, username):
    """A genuine enrolled approver, present and unlocking their own key."""
    user = models.get_user_by_username(conn, username)
    if user is None:
        raise CeremonyError(f"no such user: {username}")
    if not user["signing_pub"]:
        raise CeremonyError(f"{username} has no signing key enrolled")
    if user["signing_key_revoked_at"]:
        raise CeremonyError(f"{username}'s signing key has been revoked")
    password = os.environ.get("JUSTIKEY_CEREMONY_PASSWORD")
    if not password:
        password = getpass.getpass(f"Password for {username}: ")
    try:
        key = approvals.unwrap_signing_key(user, password)
    except Exception as exc:
        raise CeremonyError(f"could not unlock {username}'s signing key: {exc}") from exc

    class EnrolledApprover:
        def __init__(self):
            self.username = username
            self.public_hex = user["signing_pub"]

        def sign(self, statement):
            return approvals.sign_statement(key, statement)

    return EnrolledApprover()


def cmd_plan(args, conn):
    mode = crypto_store.encryption_mode(conn)
    counts = census(conn)
    creds = credential_census(conn)
    legacy_file = crypto_store.key_file_for(args.db)

    print(f"Database        : {args.db}")
    print(f"Storage format  : {mode}")
    print(f"Observations    : {counts['total']} "
          f"({counts['v1']} v1, {counts['sealed']} sealed, {counts['plaintext']} plaintext)")
    print(f"Credentials     : {creds['totp_secrets']} TOTP secret(s), "
          f"{creds['source_secrets']} sensor secret(s) under the legacy key")
    print(f"Legacy key file : {legacy_file if os.path.exists(legacy_file) else '(not on disk)'}")
    print(f"Disclosure mode : {'remote - ' + config.DISCLOSURE_URL if disclosure.is_remote() else 'local'}")
    print()

    if mode == crypto_store.MODE_V3:
        print("Already migrated. Remaining steps, if not yet done:")
        print("  rekey-credentials   move TOTP and sensor secrets off the legacy key")
        print("  destroy-legacy-key  once it is proven to open nothing")
        return
    if mode != crypto_store.MODE_V1:
        print("This store is not v1. Run scripts/encrypt_store.py first.")
        return

    print("migrate would:")
    print(f"  reseal {counts['v1']} observation(s) under per-record keys (v1 -> v3)")
    print("  recompute every blind index, since the index key changes with the format")
    print(f"  open {args.sample} of them back through the disclosure path and compare")
    print("  write a manifest and anchor its digest in the audit ledger")
    print()
    print("It would NOT touch TOTP or sensor secrets, which stay under the legacy")
    print("key until rekey-credentials. Destroying that key before then would lock")
    print("every user out of their second factor.")


def cmd_migrate(args, conn):
    if crypto_store.encryption_mode(conn) != crypto_store.MODE_V1:
        raise CeremonyError(
            f"expected a v1 store, found {crypto_store.encryption_mode(conn)!r}")
    if not sealing.SEALING_AVAILABLE:
        raise CeremonyError("the 'cryptography' package is required: pip install cryptography")

    cipher = crypto_store.open_cipher(conn, args.db)
    if cipher is None:
        raise CeremonyError("the v1 data key is required to read records one last time")

    before = census(conn)
    if before["plaintext"]:
        raise CeremonyError(
            f"{before['plaintext']} observation(s) are still plaintext; run "
            f"scripts/encrypt_store.py first so the store is in one known state")

    public_hex = disclosure.public_key_for(conn, args.db, create=True)
    if not public_hex:
        raise CeremonyError("no disclosure public key is available to seal against")
    sealer = sealing.RecordSealer(public_hex)
    approver = (resolve_approver(conn, args.approver) if args.approver
                else CeremonyApprover())
    if args.approver is None and disclosure.is_remote():
        raise CeremonyError(
            "a remote disclosure service keeps its own approver registry, so the "
            "sample check needs a genuine enrolled approver: pass --approver")

    samples = []
    sample_every = max(1, before["v1"] // max(1, args.sample)) if before["v1"] else 1
    conn.execute("BEGIN IMMEDIATE")
    try:
        rows = conn.execute(
            "SELECT id, plate_ct, location_ct, captured_at, camera_id FROM lpr_events "
            "WHERE plate_ct IS NOT NULL ORDER BY id").fetchall()
        for position, row in enumerate(rows):
            plate = cipher.decrypt(row["plate_ct"], crypto_store.event_aad(
                "plate", row["captured_at"], row["camera_id"]))
            location = cipher.decrypt(row["location_ct"], crypto_store.event_aad(
                "location", row["captured_at"], row["camera_id"]))
            # The index key belongs to the new format, so every index is
            # rebuilt. Reusing the v1 index would leave rows that the search
            # path can never match again.
            index = models.scope_token(conn, plate)
            env = sealer.seal({"plate": plate, "location": location},
                              row["captured_at"], row["camera_id"], index)
            conn.execute(
                "UPDATE lpr_events SET plate='', location=NULL, plate_ct=NULL, "
                "location_ct=NULL, plate_index=?, record_ct=?, wrapped_key=?, "
                "ephemeral_pub=?, record_uid=?, seal_version=?, recipient_key_id=? "
                "WHERE id=?",
                (index, env["record_ct"], env["wrapped_key"], env["ephemeral_pub"],
                 env["record_uid"], env["seal_version"], env["recipient_key_id"],
                 row["id"]))
            if position % sample_every == 0 and len(samples) < args.sample:
                samples.append((row["id"], plate))

        crypto_store.set_meta(conn, "encryption_mode", crypto_store.MODE_V3)
        crypto_store.set_meta(conn, "disclosure_public_key", public_hex)
        crypto_store.set_meta(conn, "sealed_at", timeutil.now_iso())
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    after = census(conn)
    digest, sealed_count = store_digest(conn)
    print(f"Resealed {len(rows)} observation(s).")

    # Verification. Anything that fails here means the store is migrated but
    # not usable, which is exactly what the backup is for -- and is why the
    # legacy key is still intact at this point.
    problems = []
    if after["v1"]:
        problems.append(f"{after['v1']} record(s) are still in v1 format")
    if after["total"] != before["total"]:
        problems.append(f"record count changed: {before['total']} -> {after['total']}")
    if after["sealed"] != before["total"]:
        problems.append(f"only {after['sealed']} of {before['total']} record(s) are sealed")

    results = verify_sample_full(conn, args.db, samples, approver)
    verified, failures = summarize(results)
    if failures:
        problems.append(f"{len(failures)} sampled record(s) failed to open: "
                        f"{failures[0]['reason']}")

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "ceremony_id": secrets.token_hex(8),
        "database": os.path.abspath(args.db),
        "from_mode": crypto_store.MODE_V1,
        "to_mode": crypto_store.MODE_V3,
        "disclosure_public_key": public_hex,
        "disclosure_key_id": sealing.key_id(public_hex),
        "seal_version": sealing.FORMAT_VERSION,
        "legacy_key_fingerprint": key_fingerprint(crypto_store.load_root_key(
            crypto_store.key_file_for(args.db))),
        "stages": [],
    }
    record_step(conn, args.manifest, manifest, "migrate", args.actor, {
        "observations_before": before, "observations_after": after,
        "resealed": len(rows), "store_digest": digest, "sealed_records": sealed_count,
        "credentials_still_on_legacy_key": credential_census(conn),
        "sample_size": len(samples), "sample_ids": [i for i, _ in samples],
        "sample_verified": verified, "sample_level": "full",
        "approver": approver.username,
        "approver_kind": "enrolled" if args.approver else "ephemeral-ceremony-key",
        "problems": problems,
    })

    print(f"  disclosure key id : {sealing.key_id(public_hex)}")
    print(f"  store digest      : {digest}")
    print(f"  sample verified   : {verified}/{len(samples)} opened through the "
          f"disclosure path and matched")
    print(f"  manifest          : {args.manifest}")
    if problems:
        print("\nPROBLEMS -- do not proceed, and restore from backup:")
        for problem in problems:
            print(f"  - {problem}")
        raise CeremonyError("migration completed but verification failed")
    print("\nNext: rekey-credentials, then destroy-legacy-key.")


def cmd_verify(args, conn):
    manifest = load_manifest(args.manifest)
    if manifest is None:
        raise CeremonyError(f"no manifest at {args.manifest}")
    if manifest.get("digest") != manifest_digest(manifest):
        raise CeremonyError("the manifest's own digest does not match its contents")

    migrate_stage = next((s for s in manifest["stages"] if s["stage"] == "migrate"), None)
    if migrate_stage is None:
        raise CeremonyError("this manifest records no migrate step")

    digest, sealed = store_digest(conn)
    counts = census(conn)
    problems = []
    if crypto_store.encryption_mode(conn) != crypto_store.MODE_V3:
        problems.append(f"store is in {crypto_store.encryption_mode(conn)!r} mode, not v3")
    if counts["v1"]:
        problems.append(f"{counts['v1']} record(s) are still in v1 format")
    if digest != migrate_stage["store_digest"]:
        problems.append("the sealed store has changed since the migration "
                        f"({sealed} record(s) now, {migrate_stage['sealed_records']} then)")

    results, why = verify_sample_structural(conn, args.db, migrate_stage["sample_ids"])
    if results is None:
        # Not a failure. Once the disclosure key has moved out of the
        # application -- which is the point of the migration -- this host
        # cannot open a record, so the deep check belongs on the host that can.
        level, verified, sample_line = "not-checked-here", None, f"not checked here ({why})"
    else:
        verified, failures = summarize(results)
        level = "structural"
        sample_line = f"{verified}/{len(results)} re-opened"
        if failures:
            problems.append(f"{len(failures)} sampled record(s) failed to re-open: "
                            f"{failures[0]['reason']}")

    print(f"Ceremony     : {manifest['ceremony_id']}")
    print(f"Mode         : {crypto_store.encryption_mode(conn)}")
    print(f"Observations : {counts['total']} ({counts['sealed']} sealed, {counts['v1']} v1)")
    matches = digest == migrate_stage["store_digest"]
    print(f"Store digest : {digest} {'(matches the migration)' if matches else '(CHANGED)'}")
    print(f"Sample       : {sample_line}")

    record_step(conn, args.manifest, manifest, "verify", args.actor, {
        "store_digest": digest, "sealed_records": sealed, "observations": counts,
        "sample_verified": verified, "sample_level": level, "problems": problems})

    if problems:
        print("\nPROBLEMS:")
        for problem in problems:
            print(f"  - {problem}")
        raise CeremonyError("verification failed")
    print("\nVerified.")


def cmd_rekey_credentials(args, conn):
    """Move TOTP and sensor secrets off the legacy key, onto a fresh one."""
    if crypto_store.encryption_mode(conn) != crypto_store.MODE_V3:
        raise CeremonyError("migrate the observations first")
    manifest = load_manifest(args.manifest)
    if manifest is None:
        raise CeremonyError(f"no manifest at {args.manifest}; run migrate first")

    legacy_file = crypto_store.key_file_for(args.db)
    old_root = crypto_store.load_root_key(legacy_file)
    old_cipher = crypto_store.FieldCipher(old_root)
    stored_canary = crypto_store.get_meta(conn, "key_check")
    if stored_canary:
        old_cipher.verify_canary(stored_canary)

    new_root = secrets.token_bytes(crypto_store.KEY_BYTES)
    new_cipher = crypto_store.FieldCipher(new_root)
    before = credential_census(conn)

    # Under v1 one root key derives BOTH the field-encryption key and the
    # blind-index key. Where that is still true, rotating the root silently
    # rotates the index key -- and every stored plate_index then refers to a
    # key nothing computes any more. Worse, the index is bound into each
    # envelope's AAD, so repairing it would mean resealing every record, which
    # requires opening them, which under v3 this process cannot do. The store
    # would be intact, verified, and permanently unsearchable.
    #
    # The test is whether this application derives the index key the *store*
    # uses. resolve_index_key answers exactly that: it returns a key in local
    # mode and refuses in remote mode, where the key belongs to the disclosure
    # service and no root rotation here can touch it.
    try:
        crypto_store.resolve_index_key(args.db)
    except crypto_store.EncryptionError:
        pass                                    # remote: the index key is not ours to rotate
    else:
        raise CeremonyError(
            "rotating the data key here would also rotate the blind-index key, "
            "orphaning every stored index and making the archive unsearchable. "
            "That coupling is what stage 3 removes: stand up the disclosure "
            "service (JUSTIKEY_DISCLOSURE_URL) so the index key lives with it "
            "and not with the application, then re-run this step. In local mode "
            "the ceremony stops here by design.")

    # Stage the new key before committing. A crash after the commit but before
    # the key exists would leave credential material no one can read.
    staged = legacy_file + ".new"
    fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(new_root.hex())
        fh.flush()
        os.fsync(fh.fileno())

    conn.execute("BEGIN IMMEDIATE")
    try:
        for row in conn.execute(
                "SELECT id, username, totp_secret_ct FROM users "
                "WHERE totp_secret_ct IS NOT NULL").fetchall():
            aad = crypto_store.user_aad("totp_secret", row["username"])
            secret = old_cipher.decrypt(row["totp_secret_ct"], aad)
            conn.execute("UPDATE users SET totp_secret_ct=? WHERE id=?",
                         (new_cipher.encrypt(secret, aad), row["id"]))

        for row in conn.execute(
                "SELECT c.key_hash, c.secret_ct, s.source_key FROM source_credentials c "
                "JOIN sources s ON s.id = c.source_id "
                "WHERE c.secret_ct IS NOT NULL").fetchall():
            aad = crypto_store.source_aad(row["source_key"])
            secret = old_cipher.decrypt(row["secret_ct"], aad)
            conn.execute("UPDATE source_credentials SET secret_ct=? WHERE key_hash=?",
                         (new_cipher.encrypt(secret, aad), row["key_hash"]))

        crypto_store.set_meta(conn, "key_check", new_cipher.canary())
        crypto_store.set_meta(conn, "rekeyed_at", timeutil.now_iso())
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        os.unlink(staged)
        raise

    # The database now speaks the new key, so it becomes the live one and the
    # legacy key is set aside for destruction rather than deleted here.
    retired = legacy_file + ".legacy"
    os.replace(legacy_file, retired)
    os.replace(staged, legacy_file)

    record_step(conn, args.manifest, manifest, "rekey-credentials", args.actor, {
        "totp_secrets": before["totp_secrets"],
        "source_secrets": before["source_secrets"],
        "legacy_key_fingerprint": key_fingerprint(old_root),
        "new_key_fingerprint": key_fingerprint(new_root),
        "retired_key_file": os.path.basename(retired)})

    print(f"Re-keyed {before['totp_secrets']} TOTP secret(s) and "
          f"{before['source_secrets']} sensor secret(s).")
    print(f"  live key    : {legacy_file}")
    print(f"  retired key : {retired}")
    print("\nThe retired key now opens nothing in this database. destroy-legacy-key")
    print("checks that for itself before removing it.")
    if config.DATA_KEY_HEX:
        print("\nNOTE: JUSTIKEY_DATA_KEY is set in this environment and overrides the")
        print("key file. Update it to the new key before restarting the application,")
        print("or it will keep presenting the retired one and fail the canary check.")


def cmd_destroy(args, conn):
    manifest = load_manifest(args.manifest)
    if manifest is None:
        raise CeremonyError(f"no manifest at {args.manifest}")
    if manifest.get("digest") != manifest_digest(manifest):
        raise CeremonyError("the manifest's own digest does not match its contents")

    stages = {s["stage"]: s for s in manifest["stages"]}
    migrate_stage, rekey_stage = stages.get("migrate"), stages.get("rekey-credentials")
    if migrate_stage is None:
        raise CeremonyError("this manifest records no migrate step")
    if migrate_stage.get("problems"):
        raise CeremonyError("the migration recorded problems; resolve them first")
    if rekey_stage is None:
        raise CeremonyError(
            "credentials have not been re-keyed. Destroying the legacy key now "
            "would lock every user out of their TOTP second factor and break every "
            "signed sensor feed. Run rekey-credentials first.")

    expected = f"destroy the legacy key for {os.path.basename(args.db)}"
    if args.confirm != expected:
        raise CeremonyError(f"to proceed, pass --confirm {expected!r}")

    retired = crypto_store.key_file_for(args.db) + ".legacy"
    if not os.path.exists(retired):
        raise CeremonyError(f"no retired key at {retired}; nothing to destroy")
    with open(retired, "r") as fh:
        retired_hex = fh.read().strip()
    retired_root = bytes.fromhex(retired_hex)
    if key_fingerprint(retired_root) != rekey_stage["legacy_key_fingerprint"]:
        raise CeremonyError(
            "the retired key file is not the key the ceremony re-keyed away from")

    # Prove it opens nothing that is left. A key still able to read live data
    # is not a legacy key, whatever the manifest says.
    holdouts = []
    counts = census(conn)
    if counts["v1"]:
        holdouts.append(f"{counts['v1']} observation(s) are still in v1 format")
    retired_cipher = crypto_store.FieldCipher(retired_root)
    for row in conn.execute("SELECT username, totp_secret_ct FROM users "
                            "WHERE totp_secret_ct IS NOT NULL").fetchall():
        try:
            retired_cipher.decrypt(row["totp_secret_ct"],
                                   crypto_store.user_aad("totp_secret", row["username"]))
        except crypto_store.EncryptionError:
            continue
        holdouts.append(f"the retired key still opens {row['username']}'s TOTP secret")
    for row in conn.execute(
            "SELECT c.secret_ct, s.source_key FROM source_credentials c "
            "JOIN sources s ON s.id = c.source_id WHERE c.secret_ct IS NOT NULL").fetchall():
        try:
            retired_cipher.decrypt(row["secret_ct"],
                                   crypto_store.source_aad(row["source_key"]))
        except crypto_store.EncryptionError:
            continue
        holdouts.append(f"the retired key still opens sensor {row['source_key']}'s secret")

    digest, sealed = store_digest(conn)
    if digest != migrate_stage["store_digest"]:
        holdouts.append("the sealed store has changed since the migration was verified")

    # Re-open a sample now. The digest proves the ciphertext is unchanged; this
    # proves it is still openable and still findable by its own index -- which
    # is what actually matters before the last copy of anything is destroyed.
    results, why = verify_sample_structural(conn, args.db, migrate_stage["sample_ids"])
    if results is None:
        recheck = f"skipped ({why})"
    else:
        verified, failures = summarize(results)
        recheck = f"{verified}/{len(results)} re-opened"
        if failures:
            holdouts.append(f"{len(failures)} sampled record(s) no longer open cleanly: "
                            f"{failures[0]['reason']}")

    if holdouts:
        print("Refusing to destroy the legacy key:")
        for holdout in holdouts:
            print(f"  - {holdout}")
        raise CeremonyError("the legacy key still opens live data")

    # Overwrite before unlinking: unlink alone leaves the bytes on disk. On a
    # copy-on-write or log-structured filesystem even this is best-effort,
    # which is why the destruction is recorded rather than merely trusted.
    size = os.path.getsize(retired)
    with open(retired, "r+b") as fh:
        for _ in range(3):
            fh.seek(0)
            fh.write(secrets.token_bytes(size))
            fh.flush()
            os.fsync(fh.fileno())
    os.unlink(retired)

    record_step(conn, args.manifest, manifest, "destroy-legacy-key", args.actor, {
        "destroyed_key_fingerprint": key_fingerprint(retired_root),
        "key_file": os.path.basename(retired), "overwrite_passes": 3,
        "store_digest": digest, "sealed_records": sealed, "sample_recheck": recheck,
        "checks_passed": ["no v1 records remain",
                          "no TOTP secret opens under the retired key",
                          "no sensor secret opens under the retired key",
                          "store digest unchanged since migration"]
                         + ([] if results is None else
                            [f"sampled records still open: {recheck}"]),
        "checks_not_run": [] if results is not None else [f"sample re-open: {why}"]})

    print(f"Destroyed {retired}")
    print(f"  fingerprint : {key_fingerprint(retired_root)}")
    print(f"  recorded in : {args.manifest} and the audit ledger")
    print("\nNothing in this database decrypts under that key any more. Delete any")
    print("backups of it, and the v1 database backups it was the key to.")


# ---------------------------------------------------------------------------

COMMANDS = {"plan": cmd_plan, "migrate": cmd_migrate, "verify": cmd_verify,
            "rekey-credentials": cmd_rekey_credentials,
            "destroy-legacy-key": cmd_destroy}


def main():
    parser = argparse.ArgumentParser(
        description="The v1 -> v3 migration ceremony",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run the steps in order: plan, migrate, rekey-credentials, "
               "destroy-legacy-key. Back up the database and both keys first.")
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("--db", default=config.DB_PATH)
    parser.add_argument("--manifest", help="ceremony manifest (default: <db>.ceremony.json)")
    parser.add_argument("--actor", default=os.environ.get("USER", "operator"))
    parser.add_argument("--sample", type=int, default=DEFAULT_SAMPLE,
                        help="records to open back through the disclosure path")
    parser.add_argument("--approver", help="enrolled approver who signs the sample check")
    parser.add_argument("--confirm", help="exact confirmation phrase for destroy-legacy-key")
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"Database not found: {args.db}")
        sys.exit(2)
    args.manifest = manifest_path_for(args.db, args.manifest)

    conn = db.get_connection(args.db)
    try:
        COMMANDS[args.command](args, conn)
    except CeremonyError as exc:
        print(f"\n{exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
