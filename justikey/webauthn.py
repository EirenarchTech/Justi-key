"""WebAuthn assertion verification: keys the server never holds.

Stage 4 of docs/capability-model.md, the half that moves private keys off
this host entirely.

WHAT THIS BUYS THAT A PASSWORD-WRAPPED KEY DOES NOT

Every signing key in stages 1-3 is a file the server can read given a
password. That bounds the damage -- a compromised application can only sign
while someone is actually typing -- but the key still passes through this
process's memory, so an attacker who is already inside gets it at that
moment.

A WebAuthn authenticator never exports its private key. The server sends a
challenge and receives a signature; the key stays in the token. A compromised
application can obtain a signature over a challenge it chose, while the
person is present and touching the device, and nothing more. It cannot keep
the key, cannot sign afterwards, and cannot sign for a different challenge
than the one the person approved.

That is the whole of the improvement, and it is worth stating narrowly: the
window shrinks from "whenever the password is typed, plus whatever the
attacker kept" to "exactly the operations a present human physically
confirmed".

WHAT IS VERIFIED

    signature over  authenticatorData || SHA-256(clientDataJSON)

and, separately:

    clientDataJSON  type is the expected ceremony, challenge matches the one
                    we issued, origin is ours
    authData        rpIdHash matches our RP ID, user-present flag set,
                    user-verified flag set when we require it
    signCount       strictly increases, which is how a cloned authenticator
                    shows up

Each of those is a distinct attack, so each is a distinct check with its own
refusal. COSE keys are decoded here rather than through a CBOR library,
because the subset WebAuthn actually uses for ES256 and Ed25519 is small and
a dependency that parses attacker-supplied CBOR is a poor trade.
"""
import base64
import hashlib
import json
import struct

try:  # pragma: no cover
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
    WEBAUTHN_AVAILABLE = True
except ImportError:  # pragma: no cover
    InvalidSignature = Exception
    ec = ed25519 = hashes = utils = None
    WEBAUTHN_AVAILABLE = False

# COSE algorithm identifiers (IANA COSE Algorithms registry).
ALG_ES256 = -7
ALG_EDDSA = -8
SUPPORTED_ALGORITHMS = (ALG_ES256, ALG_EDDSA)

# authenticatorData flag bits (WebAuthn Level 2, 6.1).
FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04

# rpIdHash(32) + flags(1) + signCount(4)
AUTH_DATA_MINIMUM = 37


class WebAuthnError(RuntimeError):
    """An assertion was not acceptable. Never a partial acceptance."""


# ---------------------------------------------------------------------------
# base64url, without the padding the spec omits
# ---------------------------------------------------------------------------

def b64url_decode(value):
    if isinstance(value, str):
        value = value.encode("ascii")
    padding = b"=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError) as exc:
        raise WebAuthnError(f"malformed base64url value: {exc}") from exc


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# COSE_Key decoding
# ---------------------------------------------------------------------------

def _cbor_item(data, offset):
    """Decode one CBOR item. Returns (value, next_offset).

    Deliberately partial: WebAuthn COSE keys use small maps of small integers
    and short byte strings, so this covers unsigned and negative integers,
    byte and text strings, arrays and maps, and refuses everything else
    rather than guessing.
    """
    if offset >= len(data):
        raise WebAuthnError("truncated COSE key")
    initial = data[offset]
    major, info = initial >> 5, initial & 0x1F
    offset += 1

    if info < 24:
        value = info
    elif info == 24:
        value, offset = data[offset], offset + 1
    elif info == 25:
        value, offset = struct.unpack_from(">H", data, offset)[0], offset + 2
    elif info == 26:
        value, offset = struct.unpack_from(">I", data, offset)[0], offset + 4
    elif info == 27:
        value, offset = struct.unpack_from(">Q", data, offset)[0], offset + 8
    else:
        raise WebAuthnError(f"unsupported CBOR additional information {info}")

    if major == 0:                                   # unsigned integer
        return value, offset
    if major == 1:                                   # negative integer
        return -1 - value, offset
    if major in (2, 3):                              # byte string / text string
        end = offset + value
        if end > len(data):
            raise WebAuthnError("truncated CBOR string")
        chunk = data[offset:end]
        return (chunk if major == 2 else chunk.decode("utf-8")), end
    if major == 4:                                   # array
        items = []
        for _ in range(value):
            item, offset = _cbor_item(data, offset)
            items.append(item)
        return items, offset
    if major == 5:                                   # map
        result = {}
        for _ in range(value):
            key, offset = _cbor_item(data, offset)
            item, offset = _cbor_item(data, offset)
            result[key] = item
        return result, offset
    raise WebAuthnError(f"unsupported CBOR major type {major}")


def decode_cose_key(raw):
    """Parse a COSE_Key into the fields we need, refusing anything else."""
    key, consumed = _cbor_item(raw, 0)
    if not isinstance(key, dict):
        raise WebAuthnError("COSE key is not a map")
    # Trailing bytes mean the blob is not what it claims to be. In attestation
    # objects the key is followed by extensions; callers pass the key alone.
    if consumed != len(raw):
        raise WebAuthnError("trailing bytes after the COSE key")

    algorithm = key.get(3)
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise WebAuthnError(f"unsupported COSE algorithm {algorithm!r}")

    key_type = key.get(1)
    if algorithm == ALG_ES256:
        if key_type != 2 or key.get(-1) != 1:        # EC2 over P-256
            raise WebAuthnError("ES256 key is not an EC2 P-256 key")
        x, y = key.get(-2), key.get(-3)
        if not isinstance(x, bytes) or not isinstance(y, bytes):
            raise WebAuthnError("ES256 key is missing its coordinates")
        if len(x) != 32 or len(y) != 32:
            raise WebAuthnError("ES256 coordinates are not 32 bytes")
        return {"algorithm": algorithm, "x": x, "y": y}

    if key_type != 1 or key.get(-1) != 6:            # OKP over Ed25519
        raise WebAuthnError("EdDSA key is not an OKP Ed25519 key")
    point = key.get(-2)
    if not isinstance(point, bytes) or len(point) != 32:
        raise WebAuthnError("Ed25519 key is not 32 bytes")
    return {"algorithm": algorithm, "x": point}


def _public_key(cose):
    if cose["algorithm"] == ALG_ES256:
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(cose["x"], "big"), int.from_bytes(cose["y"], "big"),
            ec.SECP256R1())
        return numbers.public_key()
    return ed25519.Ed25519PublicKey.from_public_bytes(cose["x"])


# ---------------------------------------------------------------------------
# authenticatorData
# ---------------------------------------------------------------------------

def parse_authenticator_data(raw):
    if len(raw) < AUTH_DATA_MINIMUM:
        raise WebAuthnError("authenticator data is too short")
    flags = raw[32]
    return {
        "rp_id_hash": raw[:32],
        "flags": flags,
        "user_present": bool(flags & FLAG_USER_PRESENT),
        "user_verified": bool(flags & FLAG_USER_VERIFIED),
        "sign_count": struct.unpack_from(">I", raw, 33)[0],
    }


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def _verify_signature(cose, signature, message):
    public = _public_key(cose)
    try:
        if cose["algorithm"] == ALG_ES256:
            public.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:
            public.verify(signature, message)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise WebAuthnError("assertion signature does not verify") from exc


def verify_assertion(credential, assertion, challenge, rp_id, origin,
                     require_user_verification=True, ceremony="webauthn.get"):
    """Check one assertion. Returns the new sign count, or raises.

    `credential` is what enrolment stored: {"credential_id", "public_key"
    (base64url COSE), "sign_count"}. `assertion` is what the browser returned:
    {"credential_id", "authenticator_data", "client_data_json", "signature"},
    all base64url. `challenge` is the exact bytes we issued.

    Nothing here is taken on trust from the caller: the public key comes from
    our own enrolment record, and the challenge from whatever we are actually
    authorizing -- never from the assertion itself.

    REPLAY PROTECTION IS NOT THIS FUNCTION'S JOB. The returned sign count must
    be persisted against the credential, but a caller who forgets leaves the
    counter check comparing against a stale value and every assertion
    replayable. So do not build replay protection on it: make the challenge
    single-use instead -- a digest over a statement carrying a nonce the
    trusted side spends once -- and treat a counter that fails to advance as
    what the spec says it is, a cloned-authenticator signal.
    """
    if not WEBAUTHN_AVAILABLE:
        raise WebAuthnError("WebAuthn verification requires the 'cryptography' package")
    for field in ("credential_id", "authenticator_data", "client_data_json", "signature"):
        if not assertion.get(field):
            raise WebAuthnError(f"assertion is missing {field}")

    if assertion["credential_id"] != credential["credential_id"]:
        raise WebAuthnError("assertion came from a different credential than the enrolled one")

    client_data_raw = b64url_decode(assertion["client_data_json"])
    try:
        client_data = json.loads(client_data_raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise WebAuthnError(f"malformed clientDataJSON: {exc}") from exc

    if client_data.get("type") != ceremony:
        raise WebAuthnError(
            f"assertion is for ceremony {client_data.get('type')!r}, not {ceremony!r}")
    # Constant-time on the challenge: it is the binding between this signature
    # and the specific thing being authorized.
    presented = b64url_decode(client_data.get("challenge", ""))
    if not _equal(presented, challenge):
        raise WebAuthnError("assertion answers a different challenge")
    if client_data.get("origin") != origin:
        raise WebAuthnError(
            f"assertion was produced for origin {client_data.get('origin')!r}, not {origin!r}")

    auth_data_raw = b64url_decode(assertion["authenticator_data"])
    auth_data = parse_authenticator_data(auth_data_raw)
    if not _equal(auth_data["rp_id_hash"], hashlib.sha256(rp_id.encode("utf-8")).digest()):
        raise WebAuthnError("assertion is for a different relying party")
    if not auth_data["user_present"]:
        raise WebAuthnError("the authenticator did not report a present user")
    if require_user_verification and not auth_data["user_verified"]:
        raise WebAuthnError(
            "this operation requires user verification (PIN or biometric), and the "
            "authenticator reported only presence")

    # A counter that fails to advance is the documented signal for a cloned
    # authenticator -- not the replay defence, which belongs to the single-use
    # challenge (see the note above). Authenticators that do not implement a
    # counter report 0 forever, which is allowed and is not evidence of
    # cloning.
    stored = credential.get("sign_count") or 0
    if auth_data["sign_count"] != 0 or stored != 0:
        if auth_data["sign_count"] <= stored:
            raise WebAuthnError(
                f"signature counter went backwards ({auth_data['sign_count']} after "
                f"{stored}); this authenticator may have been cloned")

    cose = decode_cose_key(b64url_decode(credential["public_key"]))
    _verify_signature(cose, b64url_decode(assertion["signature"]),
                      auth_data_raw + hashlib.sha256(client_data_raw).digest())
    return auth_data["sign_count"]


def _equal(left, right):
    import hmac
    return hmac.compare_digest(left, right)


def challenge_for(message):
    """The challenge that binds an assertion to a specific authorization.

    WebAuthn signs a challenge, not a document, so the challenge has to *be*
    the document: the digest of the exact canonical statement being
    authorized. An assertion is then usable for that statement and no other.
    """
    return hashlib.sha256(message).digest()
