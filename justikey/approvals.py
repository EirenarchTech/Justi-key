"""Approver-signed authorizations.

Stage 1 of docs/capability-model.md. Approval stops being a boolean the
application sets on a row and becomes a signature the approver personally
produces over the exact scope they agreed to.

WHY A SIGNATURE CHANGES ANYTHING

Today an approved authorization is a status column. Anyone who can write to
the database can flip it, or -- more quietly -- leave the approval alone and
edit what it authorizes: change target_plate on an already-approved row and
the next search returns a different vehicle's history under a real approval,
with a real approver's name on it. Nothing in the system notices.

A signature binds the approval to its scope. The statement covers the case,
the legal authority, the purpose, the target plate, the window, the
requester, and the expiry. Alter any of them afterwards and verification
fails, so the disclosure is refused.

WHERE THE PRIVATE KEY LIVES, AND WHY IT MATTERS

A signing key the server can use whenever it likes proves nothing: a
compromised application would simply sign its own approvals. So the
approver's private key is stored wrapped under a key derived from the
approver's password, which the server only ever sees while that approver is
actively signing in or approving.

The practical consequence: approval now requires the approver's password in
addition to their TOTP code. A compromised server can forge an approval only
during the moment a real approver is entering their password -- it cannot
mint approvals for last month, or for tomorrow, or while nobody is looking.

That is a real improvement over a status column, and it is still not the end
state. The strong form keeps the private key off the server entirely, on a
smartcard or in a WebAuthn authenticator, so the server never handles it at
all. This module is deliberately shaped so that swapping in such a signer
changes only where sign() is called, not what is signed or how it is
verified.
"""
import json

from . import crypto_store, crypto_utils, sealing, timeutil

try:  # pragma: no cover
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    SIGNING_AVAILABLE = True
except ImportError:  # pragma: no cover
    InvalidSignature = Exception
    ed25519 = None
    SIGNING_AVAILABLE = False

STATEMENT_VERSION = 2


class ApprovalKeyError(RuntimeError):
    """A signing key is required but unavailable or unusable."""


# ---------------------------------------------------------------------------
# The signed statement
# ---------------------------------------------------------------------------

def statement_nonce(auth_row, approved_at):
    """Deterministic per-approval nonce.

    Derived rather than random so the statement can be rebuilt from the row
    for verification, while still being unique to this approval and usable by
    the disclosure service for replay rejection.
    """
    import hashlib
    return hashlib.sha256(
        f"{auth_row['id']}|{approved_at}|{auth_row['target_plate']}".encode()).hexdigest()[:32]


def build_statement(auth_row, requester, approver, approved_at, expires_at,
                    approver_key_id=None):
    """The exact scope an approver puts their name to.

    Every field that narrows the authorization is included. Anything omitted
    here could be altered after approval without invalidating the signature,
    so omissions are silent holes rather than mere untidiness.
    """
    return {
        "v": STATEMENT_VERSION,
        "authorization_id": auth_row["id"],
        "approver_key_id": approver_key_id,
        "nonce": statement_nonce(auth_row, approved_at),
        "case_number": auth_row["case_number"],
        "legal_authority": auth_row["legal_authority"],
        "purpose": auth_row["purpose"],
        "target_plate": auth_row["target_plate"],
        "window_start": auth_row["window_start"],
        "window_end": auth_row["window_end"],
        "requester": requester,
        "approver": approver,
        "approved_at": approved_at,
        "approval_expires_at": expires_at,
    }


def canonical(statement):
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------

def _require_signing():
    if not SIGNING_AVAILABLE:
        raise ApprovalKeyError(
            "approver signing requires the 'cryptography' package")


def _wrap_key(password, salt):
    """Derive the key that protects an approver's private key.

    Deliberately a different derivation from the stored password hash, so
    the value that guards the signing key is never the value the database
    already holds for authentication.
    """
    derived, _ = crypto_utils.hash_password(password, salt)
    return bytes.fromhex(derived)[:crypto_store.KEY_BYTES]


def generate_signing_key(password):
    """Create an approver's keypair. Returns (public_hex, wrapped, salt)."""
    _require_signing()
    private = ed25519.Ed25519PrivateKey.generate()
    raw = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    public_hex = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    salt = crypto_utils.new_token(16)
    salt_hex = salt.encode("utf-8").hex()[:32]
    cipher = crypto_store.FieldCipher(_wrap_key(password, salt_hex))
    wrapped = cipher.encrypt(raw.hex(), f"users:signing_key:{public_hex}")
    return public_hex, wrapped, salt_hex


def unwrap_signing_key(user, password):
    """Recover an approver's private key using their password.

    Raises ApprovalKeyError when the password is wrong or no key exists --
    never returns a key derived from the wrong password, because signing with
    it would produce approvals nobody can verify.
    """
    _require_signing()
    if not user["signing_key_ct"] or not user["signing_key_salt"]:
        raise ApprovalKeyError("this approver has no signing key yet")
    cipher = crypto_store.FieldCipher(_wrap_key(password, user["signing_key_salt"]))
    try:
        raw_hex = cipher.decrypt(user["signing_key_ct"],
                                 f"users:signing_key:{user['signing_pub']}")
    except crypto_store.WrongKeyError as exc:
        raise ApprovalKeyError("signing key could not be unwrapped with that password") from exc
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw_hex))


# ---------------------------------------------------------------------------
# Sign and verify
# ---------------------------------------------------------------------------

def sign_statement(private_key, statement):
    return private_key.sign(canonical(statement)).hex()


def verify_statement(public_hex, statement, signature_hex):
    """True only if this exact statement was signed by that approver."""
    if not SIGNING_AVAILABLE or not public_hex or not signature_hex:
        return False
    try:
        public = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        public.verify(bytes.fromhex(signature_hex), canonical(statement))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def verify_authorization(conn, auth_row):
    """Re-derive the signed statement from the row and check it.

    Returns (ok, reason). The statement is rebuilt from the authorization's
    *current* values, so any post-approval edit to scope shows up as a
    signature mismatch rather than passing unnoticed.
    """
    if auth_row["status"] != "approved":
        return False, "not approved"
    if not auth_row["approval_signature"]:
        return False, "approval carries no signature"

    from . import models
    approver = models.get_user_by_id(conn, auth_row["approved_by"])
    requester = models.get_user_by_id(conn, auth_row["requested_by"])
    if approver is None or requester is None:
        return False, "approver or requester no longer exists"
    if not approver["signing_pub"]:
        return False, "approver has no signing key on record"

    if approver["signing_key_revoked_at"]:
        return False, "the approver's signing key has been revoked"
    statement = build_statement(
        auth_row, requester["username"], approver["username"],
        auth_row["approved_at"], auth_row["approval_expires_at"],
        approver_key_id=sealing.key_id(approver["signing_pub"]))
    if not verify_statement(approver["signing_pub"], statement,
                            auth_row["approval_signature"]):
        return False, "approval signature does not match this authorization"
    return True, None


def approval_receipt(conn, auth_row):
    """A portable record of the approval, verifiable outside this system."""
    from . import models
    approver = models.get_user_by_id(conn, auth_row["approved_by"])
    requester = models.get_user_by_id(conn, auth_row["requested_by"])
    statement = build_statement(
        auth_row, requester["username"], approver["username"],
        auth_row["approved_at"], auth_row["approval_expires_at"],
        approver_key_id=sealing.key_id(approver["signing_pub"]))
    return {
        "statement": statement,
        "signature": auth_row["approval_signature"],
        "approver_public_key": approver["signing_pub"],
        "algorithm": "Ed25519",
        "retrieved_at": timeutil.now_iso(),
    }
