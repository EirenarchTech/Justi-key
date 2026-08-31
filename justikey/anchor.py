"""External anchoring for the audit ledger tail.

A hash chain proves that no entry was *modified*, but it cannot prove that
no entry was *removed from the end*. Deleting the most recent N entries
leaves a shorter chain that still verifies perfectly, so the one thing an
attacker most wants to erase -- the record of what they just did -- is the
one thing the chain alone cannot protect.

Anchoring closes that gap by periodically publishing a signed checkpoint of
the chain head (its sequence number and hash) to storage the database
cannot reach. Verification then compares the ledger against the highest
checkpoint: if the ledger is shorter than something already witnessed, the
missing entries are proven missing rather than merely absent.

Each anchor carries two independent values:

  hash  SHA-256 over the checkpoint's fields. Key-free, so any party can
        verify that anchors link together and match the ledger.
  mac   HMAC-SHA256 under the anchor key. Proves the checkpoint was issued
        by this system and not forged by whoever rewrote the ledger.

Two destinations are supported, and they are not equally strong:

  the local anchor log   an append-only JSONL file beside the database.
                         Raises the bar (an attacker must now also rewrite
                         the log and hold the signing key) but offers no
                         protection against someone who controls the host.
  an external witness    an independent service, ideally run by a different
                         team on different infrastructure, that keeps its
                         own copy. This is the control that actually works
                         against a host-level adversary, because the
                         attacker cannot reach the witness's records.

Production should additionally use asymmetric signatures, so verifiers need
only a public key, and anchor to WORM storage or a transparency log.
"""
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading

from . import config, timeutil

GENESIS_ANCHOR_HASH = "0" * 64

# Serializes checkpoint creation within a process, so concurrent audit
# writes cannot interleave and produce a broken anchor chain.
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Checkpoint construction
# ---------------------------------------------------------------------------

def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def payload_hash(payload):
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def payload_mac(key, payload):
    return hmac.new(key, _canonical(payload).encode("utf-8"), hashlib.sha256).hexdigest()


def build_anchor(key, anchor_seq, audit_seq, audit_hash, entry_count, prev_anchor_hash):
    payload = {
        "anchor_seq": anchor_seq,
        "audit_seq": audit_seq,
        "audit_hash": audit_hash,
        "entry_count": entry_count,
        "created_at": timeutil.now_iso(),
        "prev_anchor_hash": prev_anchor_hash,
    }
    record = dict(payload)
    record["hash"] = payload_hash(payload)
    record["mac"] = payload_mac(key, payload)
    return record


def anchor_payload(record):
    """Strip the derived fields, recovering the signed payload."""
    return {k: v for k, v in record.items() if k not in ("hash", "mac")}


# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------

def load_key(key_file, key_hex=None, create=True):
    """Resolve the anchor signing key.

    An explicitly supplied hex key wins, so a deployment can inject the key
    from a secrets manager and keep it off this host's disk entirely. The
    generated key file is a development fallback: an attacker who can
    rewrite the ledger can usually also read a key sitting beside it, which
    is precisely why the external witness matters.
    """
    if key_hex:
        return bytes.fromhex(key_hex)

    def read_existing():
        with open(key_file, "r") as fh:
            return bytes.fromhex(fh.read().strip())

    if key_file and os.path.exists(key_file):
        return read_existing()
    if not create:
        raise FileNotFoundError(f"anchor key not found: {key_file}")

    key = secrets.token_bytes(32)
    try:
        # O_EXCL so concurrent first-time callers cannot each write a key and
        # leave anchors signed under one that was immediately overwritten.
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Lost the race; the winner's key is the real one.
        return read_existing()
    with os.fdopen(fd, "w") as fh:
        fh.write(key.hex())
    print(f"[justikey] generated audit anchor key at {key_file} (development default; "
          f"use JUSTIKEY_ANCHOR_KEY or a secrets manager in production)", file=sys.stderr)
    return key


# ---------------------------------------------------------------------------
# Anchor log
# ---------------------------------------------------------------------------

class AnchorStore:
    """Append-only JSONL log of checkpoints, kept outside the database."""

    def __init__(self, path, key):
        self.path = path
        self.key = key

    @classmethod
    def for_connection(cls, conn, create_key=True):
        """Build the store belonging to a connection's database file.

        Returns None for an in-memory database, which has no durable file to
        anchor beside; anchoring is then simply inactive.
        """
        path = config.ANCHOR_PATH
        key_file = config.ANCHOR_KEY_FILE
        if path is None or key_file is None:
            db_path = database_path(conn)
            if not db_path:
                return None
            base = db_path[:-3] if db_path.endswith(".db") else db_path
            path = path or base + ".anchors.jsonl"
            key_file = key_file or base + ".anchor-key"
        try:
            key = load_key(key_file, config.ANCHOR_KEY_HEX, create=create_key)
        except FileNotFoundError:
            return None
        return cls(path, key)

    def append(self, record):
        line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        # O_APPEND makes each write atomic against other appenders.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

    def read_all(self):
        """Return (records, malformed_line_numbers)."""
        if not os.path.exists(self.path):
            return [], []
        records, malformed = [], []
        with open(self.path, "r") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    malformed.append(lineno)
        return records, malformed

    def last(self):
        records, _ = self.read_all()
        return records[-1] if records else None


def database_path(conn):
    """Filesystem path backing a connection, or '' for in-memory."""
    for row in conn.execute("PRAGMA database_list"):
        if row["name"] == "main":
            return row["file"] or ""
    return ""


# ---------------------------------------------------------------------------
# Creating checkpoints
# ---------------------------------------------------------------------------

def chain_head(conn):
    """Return (seq, hash, entry_count) for the current ledger head."""
    row = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    count = conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"]
    if row is None:
        return 0, config.GENESIS_HASH, count
    return row["seq"], row["hash"], count


def create_anchor(conn, store, witness_url=None):
    """Publish a checkpoint of the current chain head.

    Returns the anchor record, or None when there is nothing to anchor.
    """
    with _lock:
        seq, head_hash, count = chain_head(conn)
        if seq == 0:
            return None
        previous = store.last()
        if previous is not None and previous.get("audit_seq") == seq:
            # Head has not moved; re-anchoring the same point adds nothing.
            return None
        anchor_seq = (previous["anchor_seq"] + 1) if previous else 1
        prev_hash = previous["hash"] if previous else GENESIS_ANCHOR_HASH
        record = build_anchor(store.key, anchor_seq, seq, head_hash, count, prev_hash)
        store.append(record)

    url = witness_url if witness_url is not None else config.WITNESS_URL
    if url:
        submit_to_witness(record, url)
    return record


def entries_since_last_anchor(conn, store):
    seq, _, _ = chain_head(conn)
    last = store.last()
    return seq - (last["audit_seq"] if last else 0)


def maybe_anchor(conn, store=None):
    """Anchor if enough entries have accumulated since the last checkpoint.

    Called after each audit append. Anchoring failures must never discard an
    audit write, so they are reported loudly on stderr rather than raised --
    and the audit page surfaces how far behind anchoring has fallen, so a
    persistent failure cannot pass unnoticed.
    """
    interval = config.ANCHOR_INTERVAL_ENTRIES
    if interval <= 0:
        return None
    try:
        store = store or AnchorStore.for_connection(conn)
        if store is None:
            return None
        if entries_since_last_anchor(conn, store) < interval:
            return None
        return create_anchor(conn, store)
    except Exception as exc:  # noqa: BLE001 - anchoring must not break auditing
        print(f"[justikey] WARNING: audit anchoring failed: {exc!r}", file=sys.stderr)
        return None


def submit_to_witness(record, url, timeout=None):
    """Send a checkpoint to the independent witness, off the request path."""
    timeout = timeout or config.WITNESS_TIMEOUT_SECONDS

    def _send():
        from urllib import error, request
        body = json.dumps(record).encode("utf-8")
        req = request.Request(url.rstrip("/") + "/anchors", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            request.urlopen(req, timeout=timeout).read()
        except (error.URLError, OSError) as exc:
            print(f"[justikey] WARNING: witness submission failed: {exc!r}", file=sys.stderr)

    threading.Thread(target=_send, daemon=True).start()


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_anchors(conn, store):
    """Check the ledger against its published checkpoints.

    Returns a dict describing what was found. `ok` is False only for real
    integrity failures; a ledger with no anchors yet is reported as
    status='no_anchors' with ok=True, since nothing has been claimed about
    it to contradict.
    """
    result = {
        "ok": True,
        "status": "ok",
        "message": "",
        "anchors_checked": 0,
        "highest_anchored_seq": 0,
        "ledger_seq": 0,
        "missing_entries": 0,
    }
    ledger_seq, _, _ = chain_head(conn)
    result["ledger_seq"] = ledger_seq

    records, malformed = store.read_all()
    if malformed:
        result.update(ok=False, status="malformed",
                      message=f"anchor log has unparseable lines: {malformed}")
        return result
    if not records:
        result.update(status="no_anchors",
                      message="no anchors published yet; tail truncation is undetectable")
        return result

    expected_anchor_seq = 1
    prev_hash = GENESIS_ANCHOR_HASH
    for rec in records:
        payload = anchor_payload(rec)
        if rec.get("anchor_seq") != expected_anchor_seq:
            result.update(ok=False, status="broken_anchor_chain",
                          message=f"anchor sequence gap: expected {expected_anchor_seq}, "
                                  f"found {rec.get('anchor_seq')}")
            return result
        if rec.get("prev_anchor_hash") != prev_hash:
            result.update(ok=False, status="broken_anchor_chain",
                          message=f"anchor {rec['anchor_seq']} does not link to its predecessor")
            return result
        if payload_hash(payload) != rec.get("hash"):
            result.update(ok=False, status="forged",
                          message=f"anchor {rec['anchor_seq']} hash does not match its contents")
            return result
        if not hmac.compare_digest(payload_mac(store.key, payload), rec.get("mac", "")):
            result.update(ok=False, status="forged",
                          message=f"anchor {rec['anchor_seq']} has an invalid signature")
            return result
        prev_hash = rec["hash"]
        expected_anchor_seq += 1

    result["anchors_checked"] = len(records)
    highest = max(r["audit_seq"] for r in records)
    result["highest_anchored_seq"] = highest

    # The check a hash chain cannot make on its own.
    if ledger_seq < highest:
        result.update(ok=False, status="truncated", missing_entries=highest - ledger_seq,
                      message=f"ledger ends at seq={ledger_seq} but seq={highest} was already "
                              f"anchored: {highest - ledger_seq} entries have been removed")
        return result

    # Each anchored point must still hold the hash that was published for it.
    for rec in records:
        row = conn.execute("SELECT hash FROM audit_log WHERE seq=?", (rec["audit_seq"],)).fetchone()
        if row is None:
            result.update(ok=False, status="truncated", missing_entries=1,
                          message=f"anchored entry seq={rec['audit_seq']} is missing from the ledger")
            return result
        if row["hash"] != rec["audit_hash"]:
            result.update(ok=False, status="rewritten",
                          message=f"entry seq={rec['audit_seq']} no longer matches the hash "
                                  f"anchored for it: history was rewritten")
            return result

    result["message"] = (f"{len(records)} anchors verified; ledger head seq={ledger_seq} "
                         f"is at or beyond the highest anchored seq={highest}")
    return result
