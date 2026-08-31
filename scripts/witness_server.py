#!/usr/bin/env python3
"""Independent audit-anchor witness.

Keeps its own copy of the checkpoints JustiKey publishes. The point is
separation: this runs as a different process, and in a real deployment on
different infrastructure under different administrative control, so an
attacker who compromises the JustiKey host and rewrites both the ledger and
the local anchor log still cannot reach these records. Comparing the two
then proves what was removed.

The witness only ever appends. It refuses to overwrite or reorder an anchor
it has already recorded, so a later "correction" cannot quietly replace
history.

    python3 scripts/witness_server.py --port 8090 --store witness.jsonl

Endpoints:
    POST /anchors          record a checkpoint
    GET  /anchors          list every checkpoint held
    GET  /anchors/latest   the highest checkpoint held
    GET  /healthz
"""
import argparse
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY_BYTES = 64 * 1024
REQUIRED_FIELDS = ("anchor_seq", "audit_seq", "audit_hash", "entry_count",
                   "created_at", "prev_anchor_hash", "hash", "mac")

_lock = threading.Lock()
STORE_PATH = "witness.jsonl"


def read_all():
    if not os.path.exists(STORE_PATH):
        return []
    out = []
    with open(STORE_PATH, "r") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def record_anchor(anchor):
    """Append an anchor, rejecting anything that would rewrite history."""
    with _lock:
        existing = read_all()
        by_seq = {a["anchor_seq"]: a for a in existing}
        seq = anchor["anchor_seq"]
        if seq in by_seq:
            # Idempotent replay is fine; a *different* anchor at the same
            # position is an attempt to rewrite what was already witnessed.
            if by_seq[seq]["hash"] == anchor["hash"]:
                return "duplicate", 200
            return "conflict: an anchor with this sequence is already recorded", 409
        line = json.dumps(anchor, sort_keys=True, separators=(",", ":")) + "\n"
        fd = os.open(STORE_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        return "recorded", 201


class Handler(BaseHTTPRequestHandler):
    server_version = "JustiKeyWitness/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            return self._json(200, {"status": "ok"})
        if self.path == "/anchors":
            anchors = read_all()
            return self._json(200, {"count": len(anchors), "anchors": anchors})
        if self.path == "/anchors/latest":
            anchors = read_all()
            if not anchors:
                return self._json(404, {"error": "no anchors recorded"})
            return self._json(200, max(anchors, key=lambda a: a["anchor_seq"]))
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/anchors":
            return self._json(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            return self._json(400, {"error": "invalid Content-Length"})
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            return self._json(413, {"error": "body too large"})
        try:
            anchor = json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._json(400, {"error": "invalid JSON"})
        if not isinstance(anchor, dict) or any(f not in anchor for f in REQUIRED_FIELDS):
            return self._json(400, {"error": f"anchor must contain {list(REQUIRED_FIELDS)}"})

        message, code = record_anchor(anchor)
        print(f"[witness] anchor_seq={anchor['anchor_seq']} audit_seq={anchor['audit_seq']} "
              f"-> {message}", file=sys.stderr)
        self._json(code, {"status": message, "anchor_seq": anchor["anchor_seq"]})


def main():
    global STORE_PATH
    parser = argparse.ArgumentParser(description="Independent JustiKey anchor witness")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--store", default="witness.jsonl",
                        help="append-only file holding witnessed anchors")
    args = parser.parse_args()
    STORE_PATH = args.store

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"JustiKey anchor witness listening on http://{args.host}:{args.port} "
          f"(store: {STORE_PATH})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
