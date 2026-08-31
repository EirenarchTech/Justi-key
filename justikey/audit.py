"""Tamper-evident, hash-chained audit ledger.

Every sensitive action is appended as a row whose hash incorporates the
hash of the previous row (SHA-256), so altering or deleting an earlier
entry breaks the chain for every entry after it. See
scripts/verify_audit.py for an independent, standalone verifier that
recomputes the chain directly against the SQLite file.
"""
import hashlib
import json
from datetime import datetime, timezone

from . import config


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _entry_hash(seq, timestamp, event_type, actor, details_json, prev_hash):
    payload = "|".join([str(seq), timestamp, event_type, actor, details_json, prev_hash])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_event(conn, event_type, actor, details=None):
    details = details or {}
    row = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    prev_seq = row["seq"] if row else 0
    prev_hash = row["hash"] if row else config.GENESIS_HASH
    seq = prev_seq + 1
    timestamp = now_iso()
    details_json = json.dumps(details, sort_keys=True, separators=(",", ":"))
    entry_hash = _entry_hash(seq, timestamp, event_type, actor, details_json, prev_hash)
    conn.execute(
        "INSERT INTO audit_log (seq, timestamp, event_type, actor, details, prev_hash, hash) "
        "VALUES (?,?,?,?,?,?,?)",
        (seq, timestamp, event_type, actor, details_json, prev_hash, entry_hash),
    )
    conn.commit()
    return seq, entry_hash


def verify_chain(conn):
    """Recompute the hash chain and confirm it is unbroken.

    Returns (ok: bool, entries_checked_or_failing_seq: int, reason: str|None).
    """
    rows = conn.execute(
        "SELECT seq, timestamp, event_type, actor, details, prev_hash, hash "
        "FROM audit_log ORDER BY seq ASC"
    ).fetchall()
    expected_prev = config.GENESIS_HASH
    for row in rows:
        if row["prev_hash"] != expected_prev:
            return False, row["seq"], "prev_hash does not match the previous entry's hash"
        recomputed = _entry_hash(
            row["seq"], row["timestamp"], row["event_type"], row["actor"], row["details"], row["prev_hash"]
        )
        if recomputed != row["hash"]:
            return False, row["seq"], "stored hash does not match recomputed hash (possible tampering)"
        expected_prev = row["hash"]
    return True, len(rows), None
