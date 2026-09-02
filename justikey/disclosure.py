"""The disclosure service: the only thing that can open a sealed observation.

Stage 2 of docs/capability-model.md.

The application seals observations with a public key and cannot open them.
Everything that turns a sealed record back into a plate passes through here,
and this service will not open anything without a valid approver signature
over the exact scope being claimed.

WHY IT RE-CHECKS EVERYTHING

The caller has already run the policy engine. This service checks scope
again anyway -- signature, requester, expiry, target plate, time window --
because a caller that has been compromised is precisely the caller whose
filtering cannot be trusted. The service is the key holder; if it delegated
scope decisions to the code asking for keys, holding the key separately
would buy nothing.

Scope is verified against the blind index rather than by opening records to
look at them. Opening an observation to discover it was out of scope would
disclose it in the act of deciding not to disclose it.

TRUST BOUNDARY, HONESTLY

In `local` mode the private key is loaded into this process, so the split is
structural rather than enforced: it establishes the chokepoint, the wrapping
format, and the independent scope check, but an attacker with code execution
in the application can still reach the key. Stage 3 moves the service to its
own process and host, at which point the boundary becomes real. The interface
here is deliberately the one a remote service would expose, so that move
changes where disclose() runs, not what it does.
"""
import hashlib
import hmac
import sys

from . import approvals, config, crypto_store, sealing, timeutil

MODE_LOCAL = "local"


class DisclosureError(RuntimeError):
    """Disclosure was refused."""


class DisclosureService:
    """Holds the private key. Opens only what an approval actually covers."""

    def __init__(self, opener, index_key):
        self._opener = opener
        self._index_key = index_key
        self.disclosures = 0

    def _blind_index(self, plate):
        normalized = str(plate).strip().upper().encode("utf-8")
        return hmac.new(self._index_key, normalized, hashlib.sha256).hexdigest()

    def disclose(self, rows, statement, signature_hex, approver_public_hex, requester):
        """Open the records an approval covers, and no others.

        `rows` are candidate observations the caller selected; the selection
        is treated as a hint, never as authority.
        """
        if not approver_public_hex:
            raise DisclosureError("the approver has no signing key on record")
        if not approvals.verify_statement(approver_public_hex, statement, signature_hex):
            raise DisclosureError("approval signature does not cover this request")

        if statement.get("requester") != requester:
            raise DisclosureError("this approval belongs to another requester")
        if statement.get("approver") == statement.get("requester"):
            raise DisclosureError("self-approval: requester and approver are the same person")
        expires = statement.get("approval_expires_at")
        if not expires or timeutil.now_iso() > expires:
            raise DisclosureError("approval has expired")

        target_index = self._blind_index(statement["target_plate"])
        window_start = statement["window_start"]
        window_end = statement["window_end"]

        revealed = []
        for row in rows:
            # Scope decided from the index and the timestamp, never by
            # opening the record first.
            if row["plate_index"] != target_index:
                continue
            if not (window_start <= row["captured_at"] <= window_end):
                continue
            fields = self._opener.open(
                row["record_ct"], row["wrapped_key"], row["ephemeral_pub"],
                crypto_store.record_aad(row["captured_at"], row["camera_id"]))
            event = dict(row)
            event["plate"] = fields.get("plate")
            event["location"] = fields.get("location")
            revealed.append(event)

        self.disclosures += 1
        return revealed


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------

def key_file_for(db_path):
    base = db_path[:-3] if db_path.endswith(".db") else db_path
    return base + ".disclosure-key"


def load_private_key(db_path, create=False):
    """Resolve the disclosure private key.

    An explicitly supplied key wins, so the private half can be injected from
    a secrets manager -- or, once stage 3 lands, held only by a separate
    service that this application never sees.
    """
    if config.DISCLOSURE_PRIVATE_KEY:
        return config.DISCLOSURE_PRIVATE_KEY.strip()

    import os
    path = key_file_for(db_path)
    if os.path.exists(path):
        with open(path, "r") as fh:
            return fh.read().strip()
    if not create:
        return None

    private_hex, _ = sealing.generate_keypair()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(path, "r") as fh:
            return fh.read().strip()
    with os.fdopen(fd, "w") as fh:
        fh.write(private_hex)
    print(f"[justikey] generated a disclosure key at {path}. In local mode this "
          f"process can open sealed records, so the split is structural only. "
          f"Stage 3 moves the private key to a separate service; until then, "
          f"treat this file as the crown jewels.", file=sys.stderr)
    return private_hex


def public_key_for(conn, db_path, create=False):
    """The public half the application uses to seal new observations."""
    stored = crypto_store.get_meta(conn, "disclosure_public_key")
    if stored:
        return stored
    private_hex = load_private_key(db_path, create=create)
    if private_hex is None:
        return None
    return sealing.public_from_private(private_hex)


def service_for(conn, db_path):
    """Build the disclosure service for this database, or None.

    Returns None when sealing is not in use, which keeps v1 databases working
    through the legacy path.
    """
    if crypto_store.encryption_mode(conn) != crypto_store.MODE_V2:
        return None
    private_hex = load_private_key(db_path)
    if private_hex is None:
        raise DisclosureError(
            "this database seals observations but no disclosure key is available; "
            "set JUSTIKEY_DISCLOSURE_KEY")
    root = crypto_store.load_root_key(crypto_store.key_file_for(db_path))
    index_key = crypto_store._hkdf(root, crypto_store._IDX_LABEL)
    return DisclosureService(sealing.RecordOpener(private_hex), index_key)
