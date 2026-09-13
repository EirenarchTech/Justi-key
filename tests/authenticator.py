"""A synthetic WebAuthn authenticator, for testing verification without hardware.

Produces byte-exact assertions: real COSE keys, real authenticatorData, real
signatures over authData || SHA-256(clientDataJSON). If verification accepts
what this produces and refuses what it deliberately corrupts, the verifier is
checking the things it claims to check.
"""
import hashlib
import json
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402

from justikey import webauthn  # noqa: E402


def _cbor_uint(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 256:
        return bytes([(major << 5) | 24, value])
    if value < 65536:
        return bytes([(major << 5) | 25]) + struct.pack(">H", value)
    return bytes([(major << 5) | 26]) + struct.pack(">I", value)


def _cbor(value):
    if isinstance(value, bool):
        raise TypeError("booleans are not used in COSE keys here")
    if isinstance(value, int):
        return _cbor_uint(0, value) if value >= 0 else _cbor_uint(1, -1 - value)
    if isinstance(value, bytes):
        return _cbor_uint(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _cbor_uint(3, len(raw)) + raw
    if isinstance(value, list):
        return _cbor_uint(4, len(value)) + b"".join(_cbor(v) for v in value)
    if isinstance(value, dict):
        return _cbor_uint(5, len(value)) + b"".join(
            _cbor(k) + _cbor(v) for k, v in value.items())
    raise TypeError(f"cannot encode {type(value)}")


class Authenticator:
    """One enrolled credential in one imaginary security key."""

    def __init__(self, algorithm=webauthn.ALG_ES256, rp_id="localhost",
                 origin="https://localhost", credential_id=None, sign_count=1):
        self.algorithm = algorithm
        self.rp_id = rp_id
        self.origin = origin
        self.sign_count = sign_count
        self.credential_id = credential_id or webauthn.b64url_encode(os.urandom(16))
        if algorithm == webauthn.ALG_ES256:
            self._private = ec.generate_private_key(ec.SECP256R1())
            numbers = self._private.public_key().public_numbers()
            cose = {1: 2, 3: webauthn.ALG_ES256, -1: 1,
                    -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")}
        else:
            self._private = ed25519.Ed25519PrivateKey.generate()
            raw = self._private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            cose = {1: 1, 3: webauthn.ALG_EDDSA, -1: 6, -2: raw}
        self.public_key = webauthn.b64url_encode(_cbor(cose))

    def credential(self, sign_count=None):
        """The enrolment record a relying party would store."""
        return {"credential_id": self.credential_id, "public_key": self.public_key,
                "sign_count": self.sign_count - 1 if sign_count is None else sign_count}

    def _sign(self, message):
        if self.algorithm == webauthn.ALG_ES256:
            return self._private.sign(message, ec.ECDSA(hashes.SHA256()))
        return self._private.sign(message)

    def assert_challenge(self, challenge, user_present=True, user_verified=True,
                         ceremony="webauthn.get", origin=None, rp_id=None,
                         sign_count=None, tamper_signature=False):
        client_data = {
            "type": ceremony,
            "challenge": webauthn.b64url_encode(challenge),
            "origin": self.origin if origin is None else origin,
            "crossOrigin": False,
        }
        client_data_raw = json.dumps(client_data, separators=(",", ":")).encode("utf-8")

        flags = 0
        if user_present:
            flags |= webauthn.FLAG_USER_PRESENT
        if user_verified:
            flags |= webauthn.FLAG_USER_VERIFIED
        count = self.sign_count if sign_count is None else sign_count
        auth_data = (hashlib.sha256((self.rp_id if rp_id is None else rp_id).encode()).digest()
                     + bytes([flags]) + struct.pack(">I", count))
        self.sign_count = max(self.sign_count, count) + 1

        signature = self._sign(auth_data + hashlib.sha256(client_data_raw).digest())
        if tamper_signature:
            signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])
        return {
            "credential_id": self.credential_id,
            "authenticator_data": webauthn.b64url_encode(auth_data),
            "client_data_json": webauthn.b64url_encode(client_data_raw),
            "signature": webauthn.b64url_encode(signature),
        }
