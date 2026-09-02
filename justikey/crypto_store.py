"""Encryption at rest for protected observation data.

Everything else in JustiKey governs *access*: who asked, who approved, how
narrow the scope was. None of it helps if someone simply takes the database
file. A stolen backup, a decommissioned disk, or a copied volume yields the
entire location history with no authorization, no approval, and no audit
entry -- defeating every control at once. This module closes that path.

DESIGN

Plate and location values are stored as AES-256-GCM ciphertext. Searching
still has to work, so each plate additionally carries a *blind index*: a
keyed HMAC of the normalized plate. Equality lookups match on the index;
the plaintext is only ever recovered by decrypting, and only for records a
policy check has already authorized.

Two keys, both derived from one root via HKDF with distinct labels, so the
index key can never decrypt and the encryption key can never be used to
build lookup values:

    root -> HKDF("justikey:field-encryption:v1") -> AES-256-GCM key
         -> HKDF("justikey:blind-index:v1")      -> HMAC-SHA256 index key

Each ciphertext is bound to its context with additional authenticated data
(AAD): the table, the column, and the observation's capture time and camera.
Someone with write access to the database therefore cannot move a plate
ciphertext onto a different time or camera to fabricate a sighting -- the
tag check fails.

KEY CUSTODY IS THE WHOLE POINT

A key sitting beside the database protects against a stolen file and nothing
more. Supply it out of band -- JUSTIKEY_DATA_KEY from a secrets manager, or
a KMS/HSM-held key -- so possession of the database alone is not enough to
recover plate history. The generated key file is a development fallback and
says so loudly.

RESIDUAL EXPOSURE, STATED PLAINLY

- The blind index is deterministic, so an attacker holding the database can
  see that two rows concern the same (still unknown) vehicle, and count how
  often it was seen. That is inherent to searchable encryption; removing it
  would mean giving up authorized lookup entirely.
- camera_id and captured_at remain plaintext: they are needed to bind the
  AAD and to operate the system. Combined with the blind index they reveal
  movement patterns of an unidentified vehicle, not its identity.
- A running server necessarily holds the key. This protects data at rest,
  not against a live host compromise.
"""
import base64
import hashlib
import hmac
import os
import secrets
import sys

from . import config

try:  # pragma: no cover - exercised by the availability test
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:  # pragma: no cover
    AESGCM = None
    InvalidTag = Exception
    CRYPTOGRAPHY_AVAILABLE = False

MODE_NONE = "none"
MODE_V1 = "v1"

NONCE_BYTES = 12
KEY_BYTES = 32
_ENC_LABEL = b"justikey:field-encryption:v1"
_IDX_LABEL = b"justikey:blind-index:v1"
_CANARY = b"justikey-key-check-v1"


class EncryptionError(RuntimeError):
    """Encryption is required but cannot be performed correctly."""


class WrongKeyError(EncryptionError):
    """The configured key does not match the one this database was written with."""


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def _hkdf(root, label, length=KEY_BYTES):
    """HKDF-Expand over HMAC-SHA256 (stdlib; extract is unnecessary for a
    uniformly random 32-byte root)."""
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(root, block + label + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


class FieldCipher:
    """Encrypts, decrypts, and indexes individual field values."""

    def __init__(self, root_key):
        if len(root_key) != KEY_BYTES:
            raise EncryptionError(f"data key must be {KEY_BYTES} bytes")
        if not CRYPTOGRAPHY_AVAILABLE:
            raise EncryptionError(
                "encryption at rest requires the 'cryptography' package "
                "(pip install cryptography)")
        self._aead = AESGCM(_hkdf(root_key, _ENC_LABEL))
        self._index_key = _hkdf(root_key, _IDX_LABEL)

    def encrypt(self, plaintext, aad):
        if plaintext is None:
            return None
        nonce = os.urandom(NONCE_BYTES)
        ct = self._aead.encrypt(nonce, str(plaintext).encode("utf-8"), aad.encode("utf-8"))
        return base64.b64encode(nonce + ct).decode("ascii")

    def decrypt(self, ciphertext, aad):
        if ciphertext is None:
            return None
        try:
            raw = base64.b64decode(ciphertext)
            return self._aead.decrypt(
                raw[:NONCE_BYTES], raw[NONCE_BYTES:], aad.encode("utf-8")
            ).decode("utf-8")
        except (InvalidTag, ValueError, TypeError) as exc:
            # A tag failure means the wrong key, or that the stored value was
            # altered or moved between rows. Never return a guess.
            raise WrongKeyError(f"could not decrypt field: {exc!r}") from exc

    def blind_index(self, value):
        """Deterministic searchable token for an exact-match lookup."""
        normalized = str(value).strip().upper().encode("utf-8")
        return hmac.new(self._index_key, normalized, hashlib.sha256).hexdigest()

    def canary(self):
        return self.encrypt(_CANARY.decode("ascii"), "meta:key_check")

    def verify_canary(self, stored):
        if self.decrypt(stored, "meta:key_check") != _CANARY.decode("ascii"):
            raise WrongKeyError("data key does not match this database")


# ---------------------------------------------------------------------------
# AAD construction: bind a ciphertext to the row it belongs to
# ---------------------------------------------------------------------------

def event_aad(column, captured_at, camera_id):
    return f"lpr_events:{column}:{captured_at}:{camera_id or ''}"


def user_aad(column, username):
    return f"users:{column}:{username}"


def source_aad(source_key):
    return f"source_credentials:secret:{source_key}"


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------

def load_root_key(key_file=None, key_hex=None, create=False):
    """Resolve the root data key.

    An explicitly supplied hex key wins, so a deployment can inject it from a
    secrets manager and keep it off this host entirely.
    """
    key_hex = key_hex if key_hex is not None else config.DATA_KEY_HEX
    if key_hex:
        try:
            key = bytes.fromhex(key_hex.strip())
        except ValueError as exc:
            raise EncryptionError(f"JUSTIKEY_DATA_KEY is not valid hex: {exc}") from exc
        if len(key) != KEY_BYTES:
            raise EncryptionError(f"JUSTIKEY_DATA_KEY must be {KEY_BYTES * 2} hex characters")
        return key

    if key_file and os.path.exists(key_file):
        with open(key_file, "r") as fh:
            return bytes.fromhex(fh.read().strip())
    if not create or not key_file:
        raise EncryptionError(
            "encryption is enabled but no data key is available; set JUSTIKEY_DATA_KEY")

    key = secrets.token_bytes(KEY_BYTES)
    try:
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(key_file, "r") as fh:      # lost a race; the winner's key is real
            return bytes.fromhex(fh.read().strip())
    with os.fdopen(fd, "w") as fh:
        fh.write(key.hex())
    print(f"[justikey] generated a data-encryption key at {key_file}. This is a "
          f"DEVELOPMENT fallback: a key stored beside the database protects only "
          f"against a stolen file. In production set JUSTIKEY_DATA_KEY from a "
          f"secrets manager or KMS.", file=sys.stderr)
    return key


def key_file_for(db_path):
    base = db_path[:-3] if db_path.endswith(".db") else db_path
    return base + ".data-key"


# ---------------------------------------------------------------------------
# Per-database state
# ---------------------------------------------------------------------------

def get_meta(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(conn, key, value):
    conn.execute("INSERT INTO meta (key, value) VALUES (?,?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def encryption_mode(conn):
    return get_meta(conn, "encryption_mode", MODE_NONE)


def open_cipher(conn, db_path, create_key=False):
    """Return the FieldCipher for an encrypted database, or None.

    Refuses to proceed when the configured key does not match the one the
    database was written with: continuing would mean writing records that can
    never be read back, or reading garbage as if it were evidence.
    """
    if encryption_mode(conn) != MODE_V1:
        return None
    root = load_root_key(key_file_for(db_path), create=create_key)
    cipher = FieldCipher(root)
    stored = get_meta(conn, "key_check")
    if stored:
        cipher.verify_canary(stored)
    return cipher


def enable_encryption(conn, db_path, create_key=True):
    """Mark a database as encrypted and record the key-check canary."""
    root = load_root_key(key_file_for(db_path), create=create_key)
    cipher = FieldCipher(root)
    set_meta(conn, "encryption_mode", MODE_V1)
    set_meta(conn, "key_check", cipher.canary())
    return cipher
