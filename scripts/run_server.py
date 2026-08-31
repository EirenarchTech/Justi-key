#!/usr/bin/env python3
"""Run the JustiKey prototype web application.

On first run (empty database) this creates demonstration accounts and a
sensor ingest API key, printing them to the console. No third-party
packages are required.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import config, seed, webapp  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Run the JustiKey prototype server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--reset", action="store_true", help="Delete the existing database before starting")
    args = parser.parse_args()

    if args.reset and os.path.exists(config.DB_PATH):
        os.remove(config.DB_PATH)
        print(f"Removed existing database at {config.DB_PATH}")

    created, api_key = seed.seed()
    if created or api_key:
        print("=== JustiKey demo credentials (prototype only, not for production) ===")
        for username, password, role, secret in created:
            print(f"  role={role:10s} username={username:12s} password={password:16s} totp_secret={secret}")
        if api_key:
            print(f"  sensor ingest API key: {api_key}")
            print(f"  (source '{seed.DEMO_SOURCE_KEY}'; manage feeds with scripts/manage_sources.py)")
        print("Get a current 2FA code for a demo account with:")
        print("  python scripts/show_totp.py <username>")
        print("========================================================================")

    webapp.run(args.host, args.port)


if __name__ == "__main__":
    main()
