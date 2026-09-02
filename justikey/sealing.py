"""Per-record sealing: write with a public key, read with a private one.

Stages 2-3 of docs/capability-model.md.

Each observation gets a fresh random record key; its fields are sealed under
that key, and the record key is wrapped to a disclosure *public* key using an
ephemeral X25519 exchange. The application holds only the public half, so it
can keep collecting for ever and still open nothing.

    seal   : public key  -> envelope
    open   : private key -> the fields back

ENVELOPE BINDING

The shared secret from the X25519 exchange is never used as a key directly.
It goes through HKDF with a domain-separation label, and the derived key
wraps the record key with AES-256-GCM.

Everything that identifies a record is authenticated together as AAD:

    format version | recipient key id | record uid | captured_at
                   | camera id | blind index

so an attacker holding the database cannot transplant a ciphertext, a wrapped
key, an index, or a timestamp between records. Any such move changes the AAD
and the tag check fails. The record uid is generated at seal time rather than
taken from the row id, because the row id is not known until after the insert
and a value assigned by the database would be attacker-controlled.

The recipient key id travels in the envelope so disclosure keys can be
rotated without ambiguity about which key a given record was sealed to.
"""
import base64
import hashlib
import json
import os
import secrets

try:  # pragma: no cover - availability is asserted by the caller
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    SEALING_AVAILABLE = True
except ImportError:  # pragma: no cover
    SEALING_AVAILABLE = False

FORMAT_VERSION = "jk-seal-v3"
NONCE_BYTES = 12
WRAP_INFO = b"justikey:record-key-wrap:v3"


class SealingError(RuntimeError):
    """A record could not be sealed or opened."""


def _require():
    if not SEALING_AVAILABLE:
        raise SealingError("record sealing requires the 'cryptography' package")


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _unb64(text):
    return base64.b64decode(text)


def key_id(public_hex):
    """Short, stable identifier for a disclosure public key."""
    return hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:16]


def generate_keypair():
    """Return (private_hex, public_hex) for a new disclosure keypair."""
    _require()
    private = x25519.X25519PrivateKey.generate()
    return (
        private.private_bytes(serialization.Encoding.Raw,
                              serialization.PrivateFormat.Raw,
                              serialization.NoEncryption()).hex(),
        private.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw).hex(),
    )


def public_from_private(private_hex):
    _require()
    private = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def record_aad(recipient_key_id, record_uid, captured_at, camera_id, blind_index):
    """Everything a sealed record is bound to.

    Canonical JSON so the binding is unambiguous, and so a field cannot be
    smuggled across a delimiter.
    """
    return json.dumps({
        "v": FORMAT_VERSION,
        "kid": recipient_key_id,
        "uid": record_uid,
        "captured_at": captured_at,
        "camera_id": camera_id or "",
        "index": blind_index,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _wrap_key_from(shared_secret):
    # The raw X25519 output is never used as a key.
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=WRAP_INFO).derive(shared_secret)


class RecordSealer:
    """Seals observations. Holds only a public key, so it can never open one."""

    def __init__(self, public_hex):
        _require()
        try:
            self._public = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        except (ValueError, TypeError) as exc:
            raise SealingError(f"invalid disclosure public key: {exc}") from exc
        self.public_hex = public_hex
        self.key_id = key_id(public_hex)

    def seal(self, fields, captured_at, camera_id, blind_index):
        """Seal protected fields, bound to the sighting they belong to.

        Returns a dict of the envelope's stored columns.
        """
        record_uid = secrets.token_hex(16)
        aad = record_aad(self.key_id, record_uid, captured_at, camera_id, blind_index)

        record_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(NONCE_BYTES)
        payload = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sealed = nonce + AESGCM(record_key).encrypt(nonce, payload, aad)

        ephemeral = x25519.X25519PrivateKey.generate()
        wrap_key = _wrap_key_from(ephemeral.exchange(self._public))
        wrap_nonce = os.urandom(NONCE_BYTES)
        wrapped = wrap_nonce + AESGCM(wrap_key).encrypt(wrap_nonce, record_key, aad)

        return {
            "record_uid": record_uid,
            "seal_version": FORMAT_VERSION,
            "recipient_key_id": self.key_id,
            "record_ct": _b64(sealed),
            "wrapped_key": _b64(wrapped),
            "ephemeral_pub": _b64(ephemeral.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        }


class RecordOpener:
    """Opens sealed observations. Requires the disclosure private key."""

    def __init__(self, private_hex):
        _require()
        try:
            self._private = x25519.X25519PrivateKey.from_private_bytes(
                bytes.fromhex(private_hex))
        except (ValueError, TypeError) as exc:
            raise SealingError(f"invalid disclosure private key: {exc}") from exc
        self.public_hex = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.key_id = key_id(self.public_hex)

    def open(self, envelope, captured_at, camera_id, blind_index):
        """Recover the protected fields, or refuse.

        A tag failure means the wrong key, or that stored values were altered
        or moved between records. Never returns a guess.
        """
        try:
            if envelope.get("seal_version") != FORMAT_VERSION:
                raise SealingError(f"unsupported seal version {envelope.get('seal_version')!r}")
            recipient = envelope.get("recipient_key_id")
            if recipient != self.key_id:
                raise SealingError(
                    f"record was sealed to key {recipient!r}, not {self.key_id!r}")

            aad = record_aad(recipient, envelope["record_uid"], captured_at,
                             camera_id, blind_index)
            ephemeral = x25519.X25519PublicKey.from_public_bytes(
                _unb64(envelope["ephemeral_pub"]))
            wrap_key = _wrap_key_from(self._private.exchange(ephemeral))

            wrapped = _unb64(envelope["wrapped_key"])
            record_key = AESGCM(wrap_key).decrypt(
                wrapped[:NONCE_BYTES], wrapped[NONCE_BYTES:], aad)

            sealed = _unb64(envelope["record_ct"])
            payload = AESGCM(record_key).decrypt(
                sealed[:NONCE_BYTES], sealed[NONCE_BYTES:], aad)
            return json.loads(payload.decode("utf-8"))
        except SealingError:
            raise
        except Exception as exc:  # noqa: BLE001 - any failure means "do not reveal"
            raise SealingError(f"could not open sealed record: {exc!r}") from exc
