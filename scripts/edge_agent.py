#!/usr/bin/env python3
"""Edge agent: run recognition at the camera, send observations to JustiKey.

This is the device-side half of JustiKey's camera-independent design. The
edge device does one job -- turn frames into plate reads -- and pushes
normalized observations upstream. It holds no policy, answers no queries,
and stores no history beyond its own send buffer, so a stolen camera yields
almost nothing: its credential is revocable on its own, and it cannot search
anything.

RECOGNITION IS PLUGGABLE. JustiKey itself depends on nothing outside the
standard library, so no computer-vision stack ships here. A recognizer is
any callable taking an image path and returning a list of
(plate, confidence) candidates:

    --recognizer stub     deterministic fake reads, for wiring up a pipeline
    --recognizer command  shell out to any CLI recognizer (see --command)

`command` mode is the realistic path: point it at whatever engine a
deployment has chosen and parse that engine's output. Swapping engines
never touches JustiKey.

    # Watch a directory that a camera writes frames into
    edge_agent.py --api-key KEY --watch ./captures --camera-id gate-north-01

    # Use a real recognizer that prints "PLATE,CONFIDENCE" per line
    edge_agent.py --api-key KEY --watch ./captures \\
        --recognizer command --command "alpr-cli --json {image}"

OFFLINE BEHAVIOR: reads are buffered to disk and flushed in batches when the
link returns. A camera on a flaky rural connection must not lose
observations, and must not stall waiting for the server.
"""
import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib import error, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _signing import signed_headers  # noqa: E402


# ---------------------------------------------------------------------------
# Recognizers
# ---------------------------------------------------------------------------

def stub_recognizer(image_path):
    """Deterministic pseudo-reads derived from the filename.

    Lets the whole pipeline -- capture, buffer, retry, ingest, audit -- be
    exercised on a laptop with no camera and no CV dependencies. Never
    represents real recognition.
    """
    digest = hashlib.sha256(os.path.basename(image_path).encode()).hexdigest()
    letters = "".join(chr(ord("A") + int(digest[i:i + 2], 16) % 26) for i in (0, 2, 4))
    digits = "".join(str(int(digest[i:i + 2], 16) % 10) for i in (6, 8, 10))
    confidence = 0.80 + (int(digest[12:14], 16) % 20) / 100.0
    return [(f"{letters}{digits}", round(confidence, 3))]


def command_recognizer(command):
    """Wrap an external recognizer CLI.

    The command may contain {image}. Output is parsed as JSON when possible
    (a list of {plate, confidence}, or an object with a `results` array),
    otherwise as lines of "PLATE,CONFIDENCE".
    """
    def run(image_path):
        argv = shlex.split(command.replace("{image}", shlex.quote(image_path)))
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"  recognizer failed: {exc!r}", file=sys.stderr)
            return []
        if proc.returncode != 0:
            print(f"  recognizer exited {proc.returncode}: {proc.stderr.strip()[:200]}",
                  file=sys.stderr)
            return []
        return _parse_recognizer_output(proc.stdout)
    return run


def _parse_recognizer_output(text):
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        out = []
        for line in text.splitlines():
            parts = [p.strip() for p in line.split(",")]
            if parts and parts[0]:
                try:
                    confidence = float(parts[1]) if len(parts) > 1 else 0.9
                except ValueError:
                    confidence = 0.9
                out.append((parts[0].upper(), confidence))
        return out

    if isinstance(data, dict):
        data = data.get("results") or data.get("candidates") or []
    if not isinstance(data, list):
        return []
    out = []
    for item in data:
        if isinstance(item, dict):
            plate = item.get("plate") or item.get("plate_number") or item.get("text")
            if plate:
                try:
                    confidence = float(item.get("confidence", 0.9))
                except (TypeError, ValueError):
                    confidence = 0.9
                out.append((str(plate).upper(), confidence))
    return out


# ---------------------------------------------------------------------------
# Store-and-forward buffer
# ---------------------------------------------------------------------------

class ProcessedFrames:
    """Durable record of frames already recognized.

    Without this, restarting the agent re-reads every frame still sitting in
    the watch directory and sends the same vehicle again. Duplicated reads
    would inflate the protected record with observations that never happened
    -- the same car apparently seen several times at one instant -- which is
    both bad evidence and needless retention.

    A frame is keyed by name, size, and modification time, so a genuinely
    re-written file is treated as new.
    """

    def __init__(self, path):
        self.path = path
        self._keys = set()
        if os.path.exists(path):
            try:
                with open(path, "r") as fh:
                    self._keys = set(json.load(fh))
            except (json.JSONDecodeError, OSError, TypeError):
                self._keys = set()

    @staticmethod
    def key(image_path):
        stat = os.stat(image_path)
        return f"{os.path.basename(image_path)}:{stat.st_size}:{int(stat.st_mtime)}"

    def __contains__(self, image_path):
        try:
            return self.key(image_path) in self._keys
        except OSError:
            return False

    def add(self, image_path):
        try:
            self._keys.add(self.key(image_path))
        except OSError:
            pass

    def save(self, watch_dir):
        """Persist, dropping entries for frames that are gone."""
        try:
            present = set()
            for name in os.listdir(watch_dir):
                path = os.path.join(watch_dir, name)
                try:
                    present.add(self.key(path))
                except OSError:
                    continue
            self._keys &= present
            tmp = self.path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(sorted(self._keys), fh)
            os.replace(tmp, self.path)
        except OSError as exc:
            print(f"  could not persist processed-frame state: {exc!r}", file=sys.stderr)


class Buffer:
    """Append-only JSONL spool of observations not yet acknowledged."""

    def __init__(self, path):
        self.path = path

    def add(self, observation):
        with open(self.path, "a") as fh:
            fh.write(json.dumps(observation, separators=(",", ":")) + "\n")

    def read_all(self):
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, "r") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return out

    def keep_only(self, remaining):
        """Rewrite the spool, retaining observations still awaiting delivery."""
        tmp = self.path + ".tmp"
        with open(tmp, "w") as fh:
            for obs in remaining:
                fh.write(json.dumps(obs, separators=(",", ":")) + "\n")
        os.replace(tmp, self.path)

    def __len__(self):
        return len(self.read_all())


def flush(buffer, url, api_key, batch_size, timeout=10):
    """Send buffered observations. Returns (sent, remaining)."""
    pending = buffer.read_all()
    if not pending:
        return 0, 0
    sent = 0
    while pending:
        batch, rest = pending[:batch_size], pending[batch_size:]
        body = json.dumps({"observations": batch}).encode("utf-8")
        req = request.Request(url.rstrip("/") + "/ingest", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-API-Key", api_key)
        try:
            with request.urlopen(req, timeout=timeout) as resp:
                result = json.loads(resp.read().decode("utf-8"))
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:200]
            if exc.code in (400, 401, 403, 413):
                # The server will never accept these: a revoked credential or
                # a malformed batch. Retrying forever would spin and mask the
                # real problem, so drop them and say so loudly.
                print(f"  server rejected {len(batch)} observation(s) permanently "
                      f"(HTTP {exc.code}): {detail}", file=sys.stderr)
                pending = rest
                continue
            print(f"  send failed (HTTP {exc.code}): {detail}", file=sys.stderr)
            break
        except (error.URLError, OSError, json.JSONDecodeError) as exc:
            print(f"  link down ({exc!r}); {len(pending)} observation(s) held", file=sys.stderr)
            break
        sent += result.get("accepted", len(batch))
        pending = rest

    buffer.keep_only(pending)
    return sent, len(pending)


# ---------------------------------------------------------------------------

def observe(image_path, recognizer, camera_id, location, source_label, min_confidence):
    """Recognize one frame, returning observations worth sending."""
    out = []
    for plate, confidence in recognizer(image_path):
        if confidence < min_confidence:
            continue
        out.append({
            "plate": plate,
            "captured_at": datetime.fromtimestamp(
                os.path.getmtime(image_path), timezone.utc).isoformat(),
            "camera_id": camera_id,
            "confidence": round(float(confidence), 3),
            "location": location,
            "source_id": source_label,
        })
    return out


def main():
    parser = argparse.ArgumentParser(description="JustiKey edge recognition agent")
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--api-key", required=True, help="this device's ingest credential")
    parser.add_argument("--watch", required=True, help="directory the camera writes frames into")
    parser.add_argument("--camera-id", default="edge-camera-01")
    parser.add_argument("--location", help="human-readable place label")
    parser.add_argument("--source-label", default="justikey-edge-agent")
    parser.add_argument("--recognizer", choices=("stub", "command"), default="stub")
    parser.add_argument("--command", help="recognizer CLI; may contain {image}")
    parser.add_argument("--min-confidence", type=float, default=0.5,
                        help="discard reads below this confidence")
    parser.add_argument("--buffer", default="edge_buffer.jsonl")
    parser.add_argument("--state", default="edge_processed.json",
                        help="record of frames already recognized, so a restart "
                             "does not re-send them")
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between scans")
    parser.add_argument("--once", action="store_true", help="scan once and exit")
    parser.add_argument("--delete-after", action="store_true",
                        help="delete each frame once recognized (recommended: the "
                             "image is more sensitive than the plate read)")
    args = parser.parse_args()

    if args.recognizer == "command":
        if not args.command:
            parser.error("--recognizer command requires --command")
        recognizer = command_recognizer(args.command)
    else:
        recognizer = stub_recognizer
        print("Using the stub recognizer: reads are synthetic, not real recognition.",
              file=sys.stderr)

    os.makedirs(args.watch, exist_ok=True)
    buffer = Buffer(args.buffer)
    processed = ProcessedFrames(args.state)
    exts = (".jpg", ".jpeg", ".png", ".bmp")

    print(f"Edge agent watching {args.watch} -> {args.url} as camera {args.camera_id}")
    try:
        while True:
            frames = sorted(f for f in os.listdir(args.watch) if f.lower().endswith(exts))
            new_frames = 0
            for name in frames:
                path = os.path.join(args.watch, name)
                if path in processed:
                    continue
                new_frames += 1
                for obs in observe(path, recognizer, args.camera_id, args.location,
                                   args.source_label, args.min_confidence):
                    buffer.add(obs)
                    print(f"  read {obs['plate']} ({obs['confidence']}) from {name}")
                # Mark processed before any deletion, so a crash between the
                # two re-reads at most one frame rather than losing track.
                processed.add(path)
                if args.delete_after:
                    try:
                        os.remove(path)
                    except OSError as exc:
                        print(f"  could not delete {name}: {exc!r}", file=sys.stderr)
            if new_frames:
                processed.save(args.watch)

            sent, remaining = flush(buffer, args.url, args.api_key, args.batch_size)
            if sent:
                print(f"  delivered {sent} observation(s); {remaining} buffered")

            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        remaining = len(buffer)
        print(f"\nStopped. {remaining} observation(s) remain buffered for retry.")


if __name__ == "__main__":
    main()
