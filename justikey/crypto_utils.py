"""Password hashing, TOTP (RFC 6238), and token helpers.

Implemented entirely with the Python standard library: hashlib, hmac,
secrets, base64, and struct. No third-party cryptography dependency.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time

from . import config


# ---------------------------------------------------------------------------
# Password hashing (PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), config.PBKDF2_ITERATIONS
    )
    return dk.hex(), salt


def verify_password(password, salt, expected_hash):
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), config.PBKDF2_ITERATIONS
    )
    return hmac.compare_digest(dk.hex(), expected_hash)


# ---------------------------------------------------------------------------
# TOTP (RFC 6238) over HMAC-SHA1, 30-second step, 6 digits
# ---------------------------------------------------------------------------

def generate_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def _hotp(secret_b32, counter, digits=6):
    # Normalize base32 padding in case a secret was hand-entered without it.
    secret_b32 = secret_b32.strip().upper()
    padding = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32 + padding)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code_int).zfill(digits)


def totp_now(secret_b32, step=30, digits=6, t=None):
    t = t if t is not None else time.time()
    return _hotp(secret_b32, int(t // step), digits)


def match_totp_counter(secret_b32, code, step=30, digits=6, window=1, t=None):
    """Return the time-step counter a code matches, or None.

    Callers that must prevent replay need to know *which* step was used so
    they can record it as spent; verify_totp is the plain boolean form.
    """
    if not code:
        return None
    code = code.strip()
    if not code.isdigit():
        return None
    t = t if t is not None else time.time()
    counter = int(t // step)
    for w in range(-window, window + 1):
        if hmac.compare_digest(_hotp(secret_b32, counter + w, digits), code.zfill(digits)):
            return counter + w
    return None


def verify_totp(secret_b32, code, step=30, digits=6, window=1, t=None):
    return match_totp_counter(secret_b32, code, step, digits, window, t) is not None


# ---------------------------------------------------------------------------
# Random tokens (sessions, API keys)
# ---------------------------------------------------------------------------

def new_token(nbytes=32):
    return secrets.token_urlsafe(nbytes)


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
