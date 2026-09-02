#!/usr/bin/env python3
"""Synthetic ALPR observation simulator.

Generates plate observations and submits them to JustiKey's authenticated
ingest API, so the whole platform can be exercised without any camera
hardware. Uses only the Python standard library (urllib).
"""
import argparse
import json
import os
import random
import string
import sys
import time
from datetime import datetime, timezone
from urllib import error, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _signing import signed_headers  # noqa: E402

KNOWN_PLATES = ["ABC123", "JST2026", "CIV101"]
CAMERAS = ["CAM-NORTH-GATE", "CAM-SOUTH-LOT", "CAM-MAIN-ENTRANCE", "CAM-LOADING-DOCK"]
LOCATIONS = ["North Gate", "South Lot", "Main Entrance", "Loading Dock"]


def random_plate():
    letters = "".join(random.choices(string.ascii_uppercase, k=3))
    digits = "".join(random.choices(string.digits, k=3))
    return f"{letters}{digits}"


def build_observation(forced_plate=None):
    idx = random.randrange(len(CAMERAS))
    plate = forced_plate or random.choice(KNOWN_PLATES + [random_plate() for _ in range(3)])
    return {
        "plate": plate,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "camera_id": CAMERAS[idx],
        "confidence": round(random.uniform(0.82, 0.99), 3),
        "location": LOCATIONS[idx],
        "source_id": "simulator-1",
    }


def send(base_url, api_key, observation, timeout=5, key_id=None):
    body = json.dumps(observation).encode("utf-8")
    req = request.Request(f"{base_url.rstrip('/')}/ingest", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if key_id:
        for header, value in signed_headers(key_id, api_key, body).items():
            req.add_header(header, value)
    else:
        req.add_header("X-API-Key", api_key)
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8")
    except error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def main():
    parser = argparse.ArgumentParser(description="JustiKey synthetic ALPR simulator")
    parser.add_argument("--url", default="http://127.0.0.1:8080", help="JustiKey base URL")
    parser.add_argument("--api-key", required=True, help="Sensor ingest API key (see run_server.py output)")
    parser.add_argument("--count", type=int, default=20, help="Observations to send (0 = run forever)")
    parser.add_argument("--interval", type=float, default=0.5, help="Seconds between observations")
    parser.add_argument("--plate", help="Force every observation to use this plate")
    parser.add_argument("--key-id", help="source key; signs requests instead of "
                                         "sending the secret (hmac sources)")
    args = parser.parse_args()

    sent = 0
    try:
        while args.count == 0 or sent < args.count:
            obs = build_observation(args.plate)
            status, resp_body = send(args.url, args.api_key, obs, key_id=args.key_id)
            print(f"[{sent + 1}] {obs['plate']} @ {obs['location']} -> HTTP {status}")
            if status >= 400:
                print(f"    error: {resp_body}")
            sent += 1
            if args.count == 0 or sent < args.count:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
