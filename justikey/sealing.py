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

from . import kem

try:  # pragma: no cover - availability is asserted by the caller
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import x25519  # noqa: F401
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    SEALING_AVAILABLE = True
except ImportError:  # pragma: no cover
    SEALING_AVAILABLE = False

FORMAT_VERSION = "jk-seal-v4"
LEGACY_VERSION = "jk-seal-v3"
SUPPORTED_VERSIONS = (FORMAT_VERSION, LEGACY_VERSION)
NONCE_BYTES = 12
WRAP_INFO = b"justikey:record-key-wrap:v3"
WRAP_INFO_V4 = b"justikey:record-key-wrap:v4"
KDF_NAME = "HKDF-SHA256"
AEAD_NAME = "AES-256-GCM"


class SealingError(RuntimeError):
    """A record could not be sealed or opened."""


def _require():
    if not SEALING_AVAILABLE:
        raise SealingError("record sealing requires the 'cryptography' package")


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _unb64(text):
    return base64.b64decode(text)


def legacy_key_id(public_hex):
    """The identifier a v3 key already has. Changing it would orphan every
    record sealed to it, so it is preserved exactly."""
    return hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:16]


def key_id(public_hex, kem_name=None):
    """Identifier for a disclosure public key, bound to its suite.

    The suite is hashed in, so the same bytes under two suites are two
    different keys and a record cannot be routed to the wrong one.
    """
    return kem.key_id(kem_name or kem.DEFAULT_KEM, bytes.fromhex(public_hex))


def generate_keypair(kem_name=None):
    """Return (private_hex, public_hex) for a new disclosure keypair.

    Defaults to the current suite, like RecordSealer and RecordOpener. Having
    "make a key" and "make a sealer" default differently is how a deployment
    ends up with a key one primitive cannot use -- the mismatch is silent
    until the first record fails to open.
    """
    _require()
    suite = kem.suite(kem_name or kem.DEFAULT_KEM)
    private, public_raw = suite.generate()
    return suite.private_bytes(private).hex(), public_raw.hex()


def public_from_private(private_hex, kem_name=None):
    _require()
    suite = kem.suite(kem_name or kem.DEFAULT_KEM)
    private = suite.private_from_bytes(bytes.fromhex(private_hex))
    return suite.public_bytes(private.public_key()).hex()


def record_aad(recipient_key_id, record_uid, captured_at, camera_id, blind_index,
               version=None, kem_name=None):
    """Everything a sealed record is bound to.

    Canonical JSON so the binding is unambiguous, and so a field cannot be
    smuggled across a delimiter. From v4 the suite name is bound in too: a
    record must not be reinterpretable under a weaker primitive than the one
    it was sealed with, and an envelope whose `kem` field can be edited
    without breaking the tag would allow exactly that.
    """
    version = version or FORMAT_VERSION
    bound = {
        "v": version,
        "kid": recipient_key_id,
        "uid": record_uid,
        "captured_at": captured_at,
        "camera_id": camera_id or "",
        "index": blind_index,
    }
    if version != LEGACY_VERSION:
        bound["kem"] = kem_name or kem.DEFAULT_KEM
        bound["kdf"] = KDF_NAME
        bound["aead"] = AEAD_NAME
    return json.dumps(bound, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _wrap_key_from(shared_secret):
    # The raw X25519 output is never used as a key.
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=WRAP_INFO).derive(shared_secret)


class RecordSealer:
    """Seals observations. Holds only a public key, so it can never open one."""

    def __init__(self, public_hex, kem_name=None):
        _require()
        # A v3 key is 32 bytes and a v4 P-256 key is 65, so the suite is
        # inferable -- but inferring it would mean a mislabelled key silently
        # selects a primitive. Named explicitly, defaulting to v4's suite.
        #
        # Nothing new is ever written as v3: that version is read-only, kept
        # so records sealed before the migration stay openable.
        self.kem = kem_name or kem.DEFAULT_KEM
        self.version = FORMAT_VERSION
        suite = kem.suite(self.kem)
        try:
            self._public_raw = bytes.fromhex(public_hex or "")
            suite.validate_peer_public(self._public_raw)
        except (ValueError, TypeError, kem.KemError) as exc:
            raise SealingError(f"invalid disclosure public key: {exc}") from exc
        self.public_hex = public_hex
        self.key_id = kem.key_id(self.kem, self._public_raw)

    def seal(self, fields, captured_at, camera_id, blind_index):
        """Seal protected fields, bound to the sighting they belong to.

        Returns a dict of the envelope's stored columns.
        """
        suite = kem.suite(self.kem)
        record_uid = secrets.token_hex(16)
        aad = record_aad(self.key_id, record_uid, captured_at, camera_id, blind_index,
                         version=FORMAT_VERSION, kem_name=self.kem)

        record_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(NONCE_BYTES)
        payload = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sealed = nonce + AESGCM(record_key).encrypt(nonce, payload, aad)

        ephemeral_private, ephemeral_public = suite.generate()
        wrap_key = kem.derive(suite.agree(ephemeral_private, self._public_raw),
                              WRAP_INFO_V4)
        wrap_nonce = os.urandom(NONCE_BYTES)
        wrapped = wrap_nonce + AESGCM(wrap_key).encrypt(wrap_nonce, record_key, aad)

        return {
            "record_uid": record_uid,
            "seal_version": FORMAT_VERSION,
            "seal_kem": self.kem,
            "recipient_key_id": self.key_id,
            "record_ct": _b64(sealed),
            "wrapped_key": _b64(wrapped),
            "ephemeral_pub": _b64(ephemeral_public),
        }


def envelope_suite(envelope):
    """The suite a record was sealed under, from the envelope alone.

    v3 records predate the field and were all X25519. A v4 record must name
    its suite: defaulting one that omits it would let a stripped field select
    the primitive, and the AAD binding exists precisely to stop that.
    """
    version = envelope.get("seal_version")
    if version == LEGACY_VERSION:
        return kem.X25519_ECDH
    if version != FORMAT_VERSION:
        raise SealingError(f"unsupported seal version {version!r}")
    name = envelope.get("seal_kem")
    if not name:
        raise SealingError("a v4 record must name its key-agreement suite")
    return name


def unwrap_record_key(envelope, aad, shared_secret):
    """Turn an agreed secret into the record key. Shared by every opener.

    Kept separate from the agreement itself because stage 5 moves the
    agreement into a custodian: what comes back is a shared secret, and this
    is everything that happens to it afterwards.
    """
    version = envelope.get("seal_version")
    info = WRAP_INFO if version == LEGACY_VERSION else WRAP_INFO_V4
    wrap_key = (_wrap_key_from(shared_secret) if version == LEGACY_VERSION
                else kem.derive(shared_secret, info))
    wrapped = _unb64(envelope["wrapped_key"])
    return AESGCM(wrap_key).decrypt(wrapped[:NONCE_BYTES], wrapped[NONCE_BYTES:], aad)


def open_with_record_key(envelope, aad, record_key):
    sealed = _unb64(envelope["record_ct"])
    payload = AESGCM(record_key).decrypt(sealed[:NONCE_BYTES], sealed[NONCE_BYTES:], aad)
    return json.loads(payload.decode("utf-8"))


def aad_for(envelope, captured_at, camera_id, blind_index):
    version = envelope.get("seal_version")
    return record_aad(envelope.get("recipient_key_id"), envelope["record_uid"],
                      captured_at, camera_id, blind_index, version=version,
                      kem_name=None if version == LEGACY_VERSION else envelope.get("seal_kem"))


class RecordOpener:
    """Opens sealed observations. Requires the disclosure private key.

    Stage 5 replaces this with a custodian that never hands the private key
    to the disclosure service at all; it stays for v3 records, for local
    development, and as the reference the custodian is checked against.
    """

    def __init__(self, private_hex, kem_name=None):
        _require()
        try:
            raw = bytes.fromhex(private_hex)
        except (ValueError, TypeError) as exc:
            raise SealingError(f"invalid disclosure private key: {exc}") from exc
        # v3 private keys are 32 bytes and so are P-256 scalars, so the suite
        # cannot be inferred from the length. Stored key files say which they
        # are (disclosure.decode_key); this default matches the sealer's, so
        # the two halves of a fresh deployment cannot disagree.
        self.kem = kem_name or kem.DEFAULT_KEM
        suite = kem.suite(self.kem)
        try:
            self._private = suite.private_from_bytes(raw)
        except kem.KemError as exc:
            raise SealingError(f"invalid disclosure private key: {exc}") from exc
        self._public_raw = suite.public_bytes(self._private.public_key())
        self.public_hex = self._public_raw.hex()
        # Both identifiers: a v3 record names the legacy id, a v4 record the
        # suite-bound one, and the same opener may be asked for either.
        self.legacy_key_id = legacy_key_id(self.public_hex)
        self.key_id = kem.key_id(self.kem, self._public_raw)

    def accepts(self, recipient_key_id):
        return recipient_key_id in (self.key_id, self.legacy_key_id)

    def open(self, envelope, captured_at, camera_id, blind_index):
        """Recover the protected fields, or refuse.

        A tag failure means the wrong key, or that stored values were altered
        or moved between records. Never returns a guess.
        """
        try:
            name = envelope_suite(envelope)
            if name != self.kem:
                raise SealingError(
                    f"record was sealed under {name!r}; this opener holds a "
                    f"{self.kem!r} key")
            recipient = envelope.get("recipient_key_id")
            if not self.accepts(recipient):
                raise SealingError(
                    f"record was sealed to key {recipient!r}, not {self.key_id!r}")

            aad = aad_for(envelope, captured_at, camera_id, blind_index)
            suite = kem.suite(name)
            shared = suite.agree(self._private, _unb64(envelope["ephemeral_pub"]))
            record_key = unwrap_record_key(envelope, aad, shared)
            return open_with_record_key(envelope, aad, record_key)
        except SealingError:
            raise
        except Exception as exc:  # noqa: BLE001 - any failure means "do not reveal"
            raise SealingError(f"could not open sealed record: {exc!r}") from exc
