"""Key-encapsulation suites, named in the envelope rather than assumed.

Stage 5 of docs/capability-model.md.

Until v4 the wrapping primitive was X25519, written into the format and into
the code with no way to say so. That turned out to be a deployment decision
disguised as an implementation detail: AWS KMS, Google Cloud KMS, Azure
Managed HSM and YubiHSM 2 all refuse X25519 for key agreement, so a
non-exportable key -- the whole point of stage 5 -- was not purchasable on
the current envelope.

So the suite is now a field. `jk-seal-v4` records carry

    "kem": "P256-ECDH-HKDF-SHA256"

and the next primitive after that is a new entry here, not a new format
version. The name is bound into the AAD, so a record cannot be reinterpreted
under a weaker suite than the one it was sealed with.

WHY P-256 WHEN X25519 IS THE BETTER CURVE

It is the better curve, and this is a deliberate trade. X25519 accepts any
32-byte string as a public key and its clamping makes invalid-point attacks a
non-issue; P-256 requires the verifier to check that a caller-supplied point
is actually on the curve, and gets that wrong in a great many published CVEs.

The property being bought is that the private key does not exist in the
disclosure service's memory, and that property is only available at P-256.
The misuse-resistance given up is recoverable with an explicit validation
step -- `validate_peer_public` below -- which the stage 5 attack suite
requires to exist regardless.

ON P-256 POINT VALIDATION, PRECISELY

NIST P-256 has cofactor 1, so the curve group order equals the prime subgroup
order and every point on the curve except the identity has full order n.
There is therefore no small-subgroup attack to defend against, and no
cofactor multiplication to perform: on-curve plus not-the-identity is
complete validation. What must be rejected is a point that is not on the
curve at all, which is what an invalid-curve attack supplies in order to
learn the private key one residue at a time.

`from_encoded_point` performs the on-curve check and rejects the identity
encoding, and raises rather than returning a degraded key. It is wrapped here
so the refusal is explicit and testable rather than incidental.
"""
import hashlib

try:  # pragma: no cover
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, x25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    KEM_AVAILABLE = True
except ImportError:  # pragma: no cover
    ec = x25519 = hashes = serialization = HKDF = None
    KEM_AVAILABLE = False

P256_ECDH = "P256-ECDH-HKDF-SHA256"
X25519_ECDH = "X25519-HKDF-SHA256"
DEFAULT_KEM = P256_ECDH


class KemError(RuntimeError):
    """A suite was unknown, or a key or point was not acceptable."""


def _require():
    if not KEM_AVAILABLE:
        raise KemError("key agreement requires the 'cryptography' package")


# ---------------------------------------------------------------------------
# P-256
# ---------------------------------------------------------------------------

class P256Suite:
    name = P256_ECDH
    # Uncompressed SEC1: 0x04 || X(32) || Y(32).
    public_bytes_length = 65

    @staticmethod
    def generate():
        _require()
        private = ec.generate_private_key(ec.SECP256R1())
        return private, P256Suite.public_bytes(private.public_key())

    @staticmethod
    def public_bytes(public):
        return public.public_bytes(serialization.Encoding.X962,
                                   serialization.PublicFormat.UncompressedPoint)

    @staticmethod
    def private_from_bytes(raw):
        _require()
        try:
            return ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())
        except (ValueError, TypeError) as exc:
            raise KemError(f"not a usable P-256 private key: {exc}") from exc

    @staticmethod
    def private_bytes(private):
        return private.private_numbers().private_value.to_bytes(32, "big")

    @staticmethod
    def validate_peer_public(raw):
        """Accept a peer point only if it is genuinely on P-256.

        The attack this refuses is the invalid-curve attack: a point on some
        other curve sharing the same field, chosen so that the shared secret
        leaks the private key a residue at a time. Cofactor is 1, so no
        subgroup check is needed beyond on-curve and not-identity.
        """
        _require()
        if not isinstance(raw, (bytes, bytearray)):
            raise KemError("a peer public key must be bytes")
        if len(raw) != P256Suite.public_bytes_length or raw[0] != 0x04:
            raise KemError(
                f"peer public key is not an uncompressed SEC1 P-256 point "
                f"({len(raw)} bytes, leading {raw[:1].hex() or 'nothing'})")
        try:
            return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(raw))
        except ValueError as exc:
            raise KemError(f"peer public key is not a point on P-256: {exc}") from exc

    @staticmethod
    def agree(private, peer_raw):
        peer = P256Suite.validate_peer_public(peer_raw)
        return private.exchange(ec.ECDH(), peer)


# ---------------------------------------------------------------------------
# X25519, kept so v3 records stay openable and the format stays agile
# ---------------------------------------------------------------------------

class X25519Suite:
    name = X25519_ECDH
    public_bytes_length = 32

    @staticmethod
    def generate():
        _require()
        private = x25519.X25519PrivateKey.generate()
        return private, X25519Suite.public_bytes(private.public_key())

    @staticmethod
    def public_bytes(public):
        return public.public_bytes(serialization.Encoding.Raw,
                                   serialization.PublicFormat.Raw)

    @staticmethod
    def private_from_bytes(raw):
        _require()
        try:
            return x25519.X25519PrivateKey.from_private_bytes(bytes(raw))
        except (ValueError, TypeError) as exc:
            raise KemError(f"not a usable X25519 private key: {exc}") from exc

    @staticmethod
    def private_bytes(private):
        return private.private_bytes(serialization.Encoding.Raw,
                                     serialization.PrivateFormat.Raw,
                                     serialization.NoEncryption())

    @staticmethod
    def validate_peer_public(raw):
        _require()
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
            raise KemError("peer public key is not a 32-byte X25519 key")
        try:
            return x25519.X25519PublicKey.from_public_bytes(bytes(raw))
        except (ValueError, TypeError) as exc:
            raise KemError(f"not a usable X25519 public key: {exc}") from exc

    @staticmethod
    def agree(private, peer_raw):
        return private.exchange(X25519Suite.validate_peer_public(peer_raw))


SUITES = {P256_ECDH: P256Suite, X25519_ECDH: X25519Suite}


def suite(name):
    try:
        return SUITES[name]
    except KeyError:
        raise KemError(
            f"unsupported key-agreement suite {name!r}; this build offers "
            f"{', '.join(sorted(SUITES))}") from None


def key_id(suite_name, public_raw):
    """Identifier for a recipient key, bound to its suite.

    The suite is hashed in, so the same bytes under two suites are two
    different keys and cannot be confused for one another.
    """
    return hashlib.sha256(
        b"justikey:recipient-key:v4|" + suite_name.encode("ascii") + b"|" + public_raw
    ).hexdigest()[:16]


def derive(shared_secret, info, length=32):
    """The raw agreement output is never used as a key."""
    _require()
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None,
                info=info).derive(shared_secret)
