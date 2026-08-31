#!/usr/bin/env python3
"""Independent command-line verifier for the JustiKey audit ledger.

Deliberately does not import the justikey package -- it re-implements the
hash-chain and anchor checks directly against the stored files so it can act
as an independent integrity check, not merely a call back into the code that
wrote the records.

Three checks, in increasing order of strength:

  chain    Recomputes every entry's hash. Detects modification or removal of
           an interior entry, but by construction cannot detect truncation
           of the tail: deleting the newest entries leaves a shorter chain
           that still verifies.

  anchors  Compares the ledger against locally published checkpoints. A
           ledger shorter than something already anchored proves entries
           were deleted. Defeated by an attacker who rewrites the anchor log
           and holds the signing key.

  witness  Compares the ledger against checkpoints held by an independent
           service. This is the check that survives a compromise of the
           JustiKey host, because the attacker cannot reach the witness.

Usage:
    python3 scripts/verify_audit.py [DB] [--anchors FILE] [--key-file FILE]
                                    [--witness URL] [--require-anchors]
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
from urllib import error, request

GENESIS_HASH = "0" * 64
GENESIS_ANCHOR_HASH = "0" * 64


# ---------------------------------------------------------------------------
# Hash chain
# ---------------------------------------------------------------------------

def _entry_hash(seq, timestamp, event_type, actor, details_json, prev_hash):
    payload = "|".join([str(seq), timestamp, event_type, actor, details_json, prev_hash])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_entries(db_path):
    import sqlite3
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT seq, timestamp, event_type, actor, details, prev_hash, hash "
            "FROM audit_log ORDER BY seq ASC"
        ).fetchall()
    finally:
        conn.close()


def verify_chain(rows):
    expected_prev = GENESIS_HASH
    expected_seq = 1
    for row in rows:
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


# ---------------------------------------------------------------------------
# Anchors
# ---------------------------------------------------------------------------

def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _payload_of(record):
    return {k: v for k, v in record.items() if k not in ("hash", "mac")}


def _payload_hash(payload):
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _payload_mac(key, payload):
    return hmac.new(key, _canonical(payload).encode("utf-8"), hashlib.sha256).hexdigest()


def load_anchor_file(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                raise ValueError(f"anchor log line {lineno} is not valid JSON")
    return out


def fetch_witness_anchors(url, timeout=10.0):
    req = request.Request(url.rstrip("/") + "/anchors", method="GET")
    with request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8")).get("anchors", [])


def load_key(key_file, key_hex):
    if key_hex:
        return bytes.fromhex(key_hex)
    if key_file and os.path.exists(key_file):
        with open(key_file, "r") as fh:
            return bytes.fromhex(fh.read().strip())
    return None


def verify_anchors(anchors, rows, key):
    """Check a set of checkpoints against the ledger.

    Returns (ok, message). Signature checking is skipped when no key is
    available; linkage and truncation checks still apply, and the caller is
    told the signatures went unchecked.
    """
    if not anchors:
        return True, "no anchors present"

    anchors = sorted(anchors, key=lambda a: a["anchor_seq"])
    by_seq = {r["seq"]: r["hash"] for r in rows}
    ledger_seq = rows[-1]["seq"] if rows else 0

    # Structural checks first: a log that does not hang together at all
    # cannot support any further conclusion.
    expected_anchor_seq = 1
    prev_hash = GENESIS_ANCHOR_HASH
    bad_signatures = []
    for rec in anchors:
        payload = _payload_of(rec)
        if rec.get("anchor_seq") != expected_anchor_seq:
            return False, (f"anchor sequence gap: expected {expected_anchor_seq}, "
                           f"found {rec.get('anchor_seq')}")
        if rec.get("prev_anchor_hash") != prev_hash:
            return False, f"anchor {rec['anchor_seq']} does not link to its predecessor"
        if _payload_hash(payload) != rec.get("hash"):
            return False, f"anchor {rec['anchor_seq']} hash does not match its contents"
        if key is not None and not hmac.compare_digest(_payload_mac(key, payload), rec.get("mac", "")):
            bad_signatures.append(rec["anchor_seq"])
        prev_hash = rec["hash"]
        expected_anchor_seq += 1

    # Beyond this point, findings accumulate rather than short-circuit. A set
    # of anchors can be both unverifiable and contradicted by the ledger, and
    # "entries were deleted" is the more legible evidence of the two -- it
    # should not be hidden behind a signature complaint.
    findings = []
    if bad_signatures:
        findings.append(f"invalid signature on anchor(s) {bad_signatures}")

    highest = max(a["audit_seq"] for a in anchors)
    if ledger_seq < highest:
        findings.append(f"ledger ends at seq={ledger_seq} but seq={highest} was already "
                        f"anchored: {highest - ledger_seq} entries have been removed")
    else:
        for rec in anchors:
            actual = by_seq.get(rec["audit_seq"])
            if actual is None:
                findings.append(f"anchored entry seq={rec['audit_seq']} is missing from the ledger")
            elif actual != rec["audit_hash"]:
                findings.append(f"entry seq={rec['audit_seq']} no longer matches the hash "
                                f"anchored for it: history was rewritten")

    if findings:
        return False, "; ".join(findings)

    note = "" if key is not None else " (signatures UNCHECKED: no anchor key available)"
    return True, (f"{len(anchors)} anchors verified, highest anchored seq={highest}, "
                  f"ledger head seq={ledger_seq}{note}")


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Verify the JustiKey audit ledger")
    parser.add_argument("db_path", nargs="?", default=os.environ.get("JUSTIKEY_DB", "justikey.db"),
                        help="Path to the JustiKey SQLite database (default: justikey.db)")
    parser.add_argument("--anchors", help="Anchor log (default: derived from the database path)")
    parser.add_argument("--key-file", help="Anchor signing key (default: derived from the database path)")
    parser.add_argument("--witness", default=os.environ.get("JUSTIKEY_WITNESS_URL"),
                        help="URL of an independent witness to check against")
    parser.add_argument("--require-anchors", action="store_true",
                        help="Fail if no anchors exist, rather than warning")
    args = parser.parse_args()

    if not os.path.exists(args.db_path):
        print(f"Database not found: {args.db_path}")
        sys.exit(2)

    base = args.db_path[:-3] if args.db_path.endswith(".db") else args.db_path
    anchor_path = args.anchors or base + ".anchors.jsonl"
    key_file = args.key_file or base + ".anchor-key"
    key = load_key(key_file, os.environ.get("JUSTIKEY_ANCHOR_KEY"))

    rows = load_entries(args.db_path)
    failures = []

    ok, info, reason = verify_chain(rows)
    if ok:
        print(f"  chain   : OK, {info} entries, no tampering detected")
    else:
        print(f"  chain   : FAILED at seq={info}: {reason}")
        failures.append("chain")

    def report(label, ok, message):
        print(f"  {label:8}: {'OK, ' if ok else 'FAILED: '}{message}")
        if not ok:
            failures.append(label)

    try:
        local_anchors = load_anchor_file(anchor_path)
    except ValueError as exc:
        local_anchors = None
        report("anchors", False, str(exc))

    if local_anchors is not None:
        if not local_anchors:
            if args.require_anchors:
                report("anchors", False, "no anchors published; tail truncation is undetectable")
            else:
                print("  anchors : WARNING: none published yet; "
                      "tail truncation is undetectable until they exist")
        else:
            report("anchors", *verify_anchors(local_anchors, rows, key))

    if args.witness:
        try:
            witness_anchors = fetch_witness_anchors(args.witness)
        except (error.URLError, OSError, json.JSONDecodeError) as exc:
            report("witness", False, f"witness unreachable: {exc!r}")
        else:
            report("witness", *verify_anchors(witness_anchors, rows, key))

    print()
    if failures:
        print(f"FAILED: audit integrity check failed ({', '.join(sorted(set(failures)))})")
        sys.exit(1)
    print("OK: audit ledger verified.")
    sys.exit(0)


if __name__ == "__main__":
    main()
