"""Tamper-evident, hash-chained audit ledger.

Every sensitive action is appended as a row whose hash incorporates the
hash of the previous row (SHA-256), so altering or deleting an earlier
entry breaks the chain for every entry after it. See
scripts/verify_audit.py for an independent, standalone verifier that
recomputes the chain directly against the SQLite file.
"""
import hashlib
import json

from . import config, timeutil

# Re-exported so existing callers keep working; canonical UTC formatting
# lives in timeutil.
now_iso = timeutil.now_iso


def _entry_hash(seq, timestamp, event_type, actor, details_json, prev_hash):
    payload = "|".join([str(seq), timestamp, event_type, actor, details_json, prev_hash])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_event(conn, event_type, actor, details=None):
    """Append one entry to the ledger, atomically.

    Reading the chain head and writing the next link must be a single
    atomic step. The server is threaded, so without BEGIN IMMEDIATE two
    concurrent appends read the same head, compute the same sequence
    number, and one of them loses the UNIQUE race and is discarded -- the
    surviving chain still verifies, so the loss is silent, which is
    exactly the failure a tamper-evident ledger must not have.
    """
    details_json = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev_seq = row["seq"] if row else 0
        prev_hash = row["hash"] if row else config.GENESIS_HASH
        seq = prev_seq + 1
        timestamp = timeutil.now_iso()
        entry_hash = _entry_hash(seq, timestamp, event_type, actor, details_json, prev_hash)
        conn.execute(
            "INSERT INTO audit_log (seq, timestamp, event_type, actor, details, prev_hash, hash) "
            "VALUES (?,?,?,?,?,?,?)",
            (seq, timestamp, event_type, actor, details_json, prev_hash, entry_hash),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
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
    expected_seq = 1
    for row in rows:
        # A gap in the sequence means an entry is missing, even if every
        # surviving link still hashes correctly.
        if row["seq"] != expected_seq:
            return False, row["seq"], f"sequence gap: expected seq={expected_seq}, found seq={row['seq']}"
        if row["prev_hash"] != expected_prev:
            return False, row["seq"], "prev_hash does not match the previous entry's hash"
        recomputed = _entry_hash(
            row["seq"], row["timestamp"], row["event_type"], row["actor"], row["details"], row["prev_hash"]
        )
        if recomputed != row["hash"]:
            return False, row["seq"], "stored hash does not match recomputed hash (possible tampering)"
        expected_prev = row["hash"]
        expected_seq += 1
    return True, len(rows), None
