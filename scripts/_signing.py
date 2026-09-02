"""Request signing for sensor senders.

A signing source never puts its secret on the wire. Each request carries a
timestamp, a fresh nonce, and an HMAC over both plus a digest of the body, so
a captured request can be neither modified nor replayed.
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timezone


def signed_headers(key_id, secret, body):
    timestamp = "%04d-%02d-%02dT%02d:%02d:%02d.%06d+00:00" % (
        *datetime.now(timezone.utc).timetuple()[:6], datetime.now(timezone.utc).microsecond)
    nonce = secrets.token_urlsafe(16)
    base = f"{timestamp}\n{nonce}\n{hashlib.sha256(body or b'').hexdigest()}".encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    return {
        "X-JustiKey-Key-Id": key_id,
        "X-JustiKey-Timestamp": timestamp,
        "X-JustiKey-Nonce": nonce,
        "X-JustiKey-Signature": signature,
    }
