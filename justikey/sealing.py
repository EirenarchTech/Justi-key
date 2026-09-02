"""Per-record sealing: write with a public key, read with a private one.

Stage 2 of docs/capability-model.md.

Under v1 encryption the application held one symmetric key that both sealed
and opened every observation. That protects a stolen database file and
nothing else: the running process could decrypt the entire archive, so the
policy engine was the only thing standing between a compromised application
and every plate ever collected.

Here the two abilities are split. Each observation gets a fresh random record
key; its fields are sealed under that key, and the record key itself is
wrapped to a disclosure *public* key using an ephemeral X25519 exchange. The
application holds only the public half, so it can keep collecting for ever
and still open nothing. Opening requires the private half, which lives behind
the disclosure service.

    seal   : public key  -> (sealed fields, wrapped record key, ephemeral pub)
    open   : private key -> the fields back

Every ciphertext is bound by AAD to the observation's capture time and
camera, so a wrapped key or a sealed blob cannot be moved onto a different
sighting.

What this does NOT give on its own: forward secrecy against later compromise
of the disclosure private key, and no protection for the blind index, which
stays with the application because queries are built from it. See the
capability model document for the residual exposure in full.
"""
import base64
import json
import os

try:  # pragma: no cover - availability is asserted by the caller
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    SEALING_AVAILABLE = True
except ImportError:  # pragma: no cover
    SEALING_AVAILABLE = False

NONCE_BYTES = 12
WRAP_INFO = b"justikey:record-key-wrap:v2"


class SealingError(RuntimeError):
    """A record could not be sealed or opened."""


def _require():
    if not SEALING_AVAILABLE:
        raise SealingError("record sealing requires the 'cryptography' package")


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _unb64(text):
    return base64.b64decode(text)


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


def _wrap_key_from(shared_secret):
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

    def seal(self, fields, aad):
        """Seal a dict of protected fields.

        Returns (sealed_fields, wrapped_key, ephemeral_pub), all base64.
        """
        record_key = AESGCM.generate_key(bit_length=256)
        aad_bytes = aad.encode("utf-8")

        nonce = os.urandom(NONCE_BYTES)
        payload = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sealed = nonce + AESGCM(record_key).encrypt(nonce, payload, aad_bytes)

        ephemeral = x25519.X25519PrivateKey.generate()
        wrap_key = _wrap_key_from(ephemeral.exchange(self._public))
        wrap_nonce = os.urandom(NONCE_BYTES)
        wrapped = wrap_nonce + AESGCM(wrap_key).encrypt(wrap_nonce, record_key, aad_bytes)

        ephemeral_pub = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return _b64(sealed), _b64(wrapped), _b64(ephemeral_pub)


class RecordOpener:
    """Opens sealed observations. Requires the disclosure private key."""

    def __init__(self, private_hex):
        _require()
        try:
            self._private = x25519.X25519PrivateKey.from_private_bytes(
                bytes.fromhex(private_hex))
        except (ValueError, TypeError) as exc:
            raise SealingError(f"invalid disclosure private key: {exc}") from exc

    @property
    def public_hex(self):
        return self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def open(self, sealed_fields, wrapped_key, ephemeral_pub, aad):
        """Recover the protected fields, or refuse.

        A tag failure means the wrong key, or that the stored values were
        altered or moved between rows. Never returns a guess.
        """
        try:
            aad_bytes = aad.encode("utf-8")
            ephemeral = x25519.X25519PublicKey.from_public_bytes(_unb64(ephemeral_pub))
            wrap_key = _wrap_key_from(self._private.exchange(ephemeral))

            wrapped = _unb64(wrapped_key)
            record_key = AESGCM(wrap_key).decrypt(
                wrapped[:NONCE_BYTES], wrapped[NONCE_BYTES:], aad_bytes)

            sealed = _unb64(sealed_fields)
            payload = AESGCM(record_key).decrypt(
                sealed[:NONCE_BYTES], sealed[NONCE_BYTES:], aad_bytes)
            return json.loads(payload.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - any failure means "do not reveal"
            raise SealingError(f"could not open sealed record: {exc!r}") from exc
