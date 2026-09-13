#!/usr/bin/env python3
"""The JustiKey custodian: the key holder that protects the operation.

Stage 5 of docs/capability-model.md. Design: docs/stage-5-key-isolation.md.

    web application  ->  disclosure service  ->  CUSTODIAN  ->  AWS KMS
     (assume owned)      (assume owned)          (this)        (key never
                                                                exportable)

Everything to the left of the custodian is assumed compromised. That
assumption is why this process exists, and why it re-checks facts the
disclosure service has already checked: a second opinion from a component
that shares no code path, no database and no credentials with the first.

WHAT IT WILL NOT DO

There is no endpoint that derives a shared secret. The whole point of stage 5
is that `derive(ephemeral_pub)` is the unrestricted oracle -- a compromised
caller with every row's ephemeral key walks the archive one call at a time,
and a non-exportable KMS key does not slow it down. So the only operation
offered is:

    POST /open   {envelope, identity, statement, signature, requester,
                  presence, presence_proof, registry_versions}

and it opens exactly one record, after independently verifying record
identity, suite, recipient key, approval signature, scope re-derived from its
own index key, proof of presence, freshness, single use, and remaining
capacity.

STATE THIS PROCESS OWNS RATHER THAN TRUSTS

Approval counts and presence nonces are spent HERE, in one transaction. When
a custodian is configured the disclosure service stops spending them, so the
authoritative copy is the one furthest from the attacker rather than two
copies that disagree.

RUNNING IT INSIDE AN ENCLAVE

On AWS Nitro this process runs in the enclave and the parent instance
proxies to it over vsock; `--attestation-file` is the enclave's attestation
document, sent to KMS as `Recipient` so the derived secret is encrypted to
the enclave and the parent never sees it. The KMS key policy should require
the enclave measurement (kms:RecipientAttestation:ImageSha384), which makes a
call from the compromised parent fail at KMS rather than here.

Run over TCP for development; over vsock, behind the parent's proxy, in
production. Nothing in this file assumes which.

    python3 scripts/custodian_server.py --port 8091 \\
        --client-secret "$CUSTODIAN_SECRET" \\
        --index-key "$INDEX_KEY" \\
        --approvers approvers.json --requesters requesters.json \\
        --ledger custodian-audit.db \\
        --kms-key-arn arn:aws:kms:...:key/... --attestation-file /run/attestation.bin
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import (custodian, disclosure, kem, registry, sealing,  # noqa: E402
                      servicekit)

STATE = {}


class Handler(servicekit.AuthenticatedHandler, BaseHTTPRequestHandler):
    server_version = "JustiKeyCustodian/1.0"

    @property
    def state(self):
        return STATE

    def do_GET(self):
        if self.path == "/healthz":
            return self._json(200, {"status": "ok"})
        if self.path == "/publickey":
            agreement = STATE["custodian"].agreement
            return self._json(200, {
                "public_key": agreement.public_raw.hex(),
                "key_id": agreement.key_id,
                "kem": agreement.kem,
                "seal_version": sealing.FORMAT_VERSION,
                "backend": agreement.backend,
                # Stated rather than implied: a deployment should be able to
                # see from the outside whether this custodian is running in a
                # configuration that meets the stage 5 objective.
                "attested": bool(getattr(agreement, "meets_stage_5", False)),
                "registry_versions": STATE["registry_versions"],
            })
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path not in ("/index", "/open"):
            return self._json(404, {"error": "not found"})
        payload = self._payload()
        if payload is None:
            return
        if self.path == "/index":
            return self._handle_index(payload)
        return self._handle_open(payload)

    def _handle_index(self, payload):
        """A scope token, for the disclosure service's own candidate search.

        The custodian holds an index key so it can re-derive scope for itself
        at disclosure time. Exposing it here as well means the disclosure
        service need not hold a second copy -- but it is the same grinding
        channel described in threat-model finding 1, so it is rate limited
        and every call is recorded.
        """
        plate = payload.get("plate")
        if not isinstance(plate, str) or not plate.strip():
            return self._json(400, {"error": "plate is required"})
        if not index_rate_ok():
            STATE["record"]("index_rate_limited", "client",
                            {"limit_per_minute": STATE["index_limit"]})
            return self._json(429, {"error": "scope-token rate limit exceeded"})
        STATE["record"]("scope_token_issued", "client", {})
        return self._json(200, {"plate_index": blind_index(plate)})

    def _handle_open(self, payload):
        envelope = payload.get("envelope")
        identity = payload.get("identity")
        requester = payload.get("requester")
        if not isinstance(envelope, dict) or not isinstance(identity, dict):
            return self._json(400, {"error": "envelope and identity are required"})

        try:
            result = STATE["custodian"].open(
                envelope, identity, payload.get("statement"), payload.get("signature"),
                requester, payload.get("presence"), payload.get("presence_proof"),
                registry_versions=payload.get("registry_versions"),
                blind_index_of=blind_index)
        except custodian.AgreementUnavailable as exc:
            # The key holder being unreachable is an operating state, not a
            # fault, and never a reason to open anything another way.
            STATE["record"]("agreement_unavailable", f"requester:{requester}",
                            {"reason": str(exc)[:300]})
            return self._json(503, {"error": str(exc)})
        except custodian.CustodianError as exc:
            STATE["record"]("open_refused", f"requester:{requester}", {
                "reason": str(exc)[:300],
                "record_uid": envelope.get("record_uid"),
                "case": (payload.get("statement") or {}).get("case_number")
                if isinstance(payload.get("statement"), dict) else None})
            return self._json(403, {"error": str(exc)})

        # Recorded before the response is written: an opening that reached the
        # caller but not the ledger is exactly the gap that matters.
        STATE["record"]("open_granted", f"requester:{requester}", {
            "record_uid": envelope.get("record_uid"),
            "authorization_id": (payload.get("statement") or {}).get("authorization_id"),
            "approver": (payload.get("statement") or {}).get("approver"),
            "use_count": result["use_count"], "presence": result["presence"],
            "suite": result["suite"], "backend": result["backend"],
            "context": result["context_digest"]})
        # The plate never enters this ledger. Recording it here would rebuild
        # the archive the custodian exists to protect.
        return self._json(200, {"fields": result["fields"],
                                "use_count": result["use_count"],
                                "presence": result["presence"],
                                "context": result["context_digest"]})


# ---------------------------------------------------------------------------

def blind_index(plate):
    """The custodian's own scope function.

    Never the caller's: a custodian that accepted somebody else's idea of
    which records match an approval would have re-created the oracle with
    extra steps.
    """
    normalized = str(plate).strip().upper().encode("utf-8")
    return hmac.new(STATE["index_key"], normalized, hashlib.sha256).hexdigest()


def index_rate_ok():
    import time

    limit, window = STATE["index_limit"], 60.0
    if limit <= 0:
        return True
    now = time.monotonic()
    with STATE["index_lock"]:
        calls = STATE["index_calls"]
        while calls and now - calls[0] > window:
            calls.pop(0)
        if len(calls) >= limit:
            return False
        calls.append(now)
        return True


def build_agreement(args):
    """Pick a backend, and be explicit about what it is worth."""
    if args.kms_key_arn:
        try:
            import boto3
        except ImportError:
            raise SystemExit(
                "--kms-key-arn needs boto3 installed in the custodian's environment")
        recipient = enclave_decrypt = None
        if args.attestation_file:
            with open(args.attestation_file, "rb") as fh:
                recipient = {"AttestationDocument": fh.read(),
                             "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256"}
            enclave_decrypt = _enclave_decrypt_unavailable
        if not args.public_key:
            raise SystemExit(
                "--public-key is required with --kms-key-arn: the custodian must "
                "know which public key records are sealed to, and asking KMS for "
                "it at every open would make an availability problem a "
                "correctness one")
        return custodian.KmsAgreement(
            boto3.client("kms", region_name=args.region), args.kms_key_arn,
            bytes.fromhex(args.public_key), recipient=recipient,
            enclave_decrypt=enclave_decrypt)

    material = args.key
    if not material and args.key_file:
        with open(args.key_file, "r") as fh:
            material = fh.read().strip()
    if not material:
        raise SystemExit("a backend is required: --kms-key-arn, or --key/--key-file")
    kem_name, private_hex = disclosure.decode_key(material)
    return custodian.LocalAgreement(private_hex, args.kem or kem_name)


def _enclave_decrypt_unavailable(blob):
    raise custodian.CustodianError(
        "this build cannot decrypt CiphertextForRecipient: the enclave-side "
        "decryption of the KMS response is not implemented here. Run the "
        "custodian inside the enclave with a provider that can, or run without "
        "--attestation-file and understand that the configuration does not "
        "meet the stage 5 objective.")


def main():
    parser = argparse.ArgumentParser(
        description="JustiKey custodian: verifies the whole disclosure context, "
                    "then agrees exactly once")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8091)
    parser.add_argument("--client-secret",
                        default=os.environ.get("JUSTIKEY_CUSTODIAN_CLIENT_SECRET"),
                        help="shared secret the disclosure service authenticates with")
    parser.add_argument("--index-key", default=os.environ.get("JUSTIKEY_INDEX_KEY"),
                        help="blind-index key, so scope is re-derived here")
    parser.add_argument("--approvers", help="JSON file of enrolled approver keys")
    parser.add_argument("--requesters", help="JSON file of enrolled requester keys")
    parser.add_argument("--presence-mode", choices=("off", "enrolled", "required"),
                        default=os.environ.get("JUSTIKEY_PRESENCE_MODE", "required"))
    parser.add_argument("--ledger", default="custodian-audit.db",
                        help="this custodian's own append-only ledger and state")
    parser.add_argument("--max-disclosures", type=int, default=None,
                        help="times one approval may be spent; 0 disables the cap")
    parser.add_argument("--index-limit", type=int, default=600,
                        help="scope tokens per minute; 0 disables the limit")
    parser.add_argument("--accept-kem", action="append", default=None,
                        help="suites this custodian will open (repeatable)")
    # Backends.
    parser.add_argument("--kms-key-arn", default=os.environ.get("JUSTIKEY_KMS_KEY_ARN"),
                        help="AWS KMS ECC_NIST_P256 KEY_AGREEMENT key")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION"))
    parser.add_argument("--public-key", default=os.environ.get("JUSTIKEY_DISCLOSURE_PUBLIC_KEY"),
                        help="hex public key records are sealed to (with --kms-key-arn)")
    parser.add_argument("--attestation-file",
                        help="Nitro attestation document, sent to KMS as Recipient")
    parser.add_argument("--key", help="software private key (development only)")
    parser.add_argument("--key-file", help="file holding a software private key")
    parser.add_argument("--kem", help="suite of the software key")
    args = parser.parse_args()

    if not args.client_secret:
        parser.error("--client-secret is required")
    if not args.index_key:
        parser.error("--index-key is required: the custodian re-derives scope itself")
    if args.presence_mode == "required" and not args.requesters:
        parser.error("--presence-mode required needs --requesters: with no enrolled "
                     "requesters every disclosure would be refused")

    servicekit.init_ledger(args.ledger)
    record = servicekit.LedgerWriter(args.ledger)

    admitted, versions = {}, {}
    try:
        for role, path in (("approver", args.approvers), ("requester", args.requesters)):
            principals, status, detail = servicekit.admit_registry(args.ledger, role, path)
            admitted[role], versions[role] = principals, detail["version"]
            if status != "unchanged":
                record(f"registry_{status}", "custodian", dict(detail, role=role))
    except registry.RegistryError as exc:
        print(f"\nRefusing to start: {exc}", file=sys.stderr)
        sys.exit(3)

    agreement = build_agreement(args)
    usage = disclosure.UsageStore(args.ledger)
    usage.purge_expired()

    STATE.update({
        "record": record,
        "usage": usage,
        "client_secret": args.client_secret,
        "index_key": bytes.fromhex(args.index_key),
        "index_limit": args.index_limit,
        "index_lock": __import__("threading").Lock(),
        "index_calls": [],
        "registry_versions": versions,
        "custodian": custodian.Custodian(
            agreement, approvers=admitted["approver"], requesters=admitted["requester"],
            usage=usage, max_disclosures=args.max_disclosures,
            presence_mode=args.presence_mode,
            accepted_kems=tuple(args.accept_kem) if args.accept_kem else None,
            registry_versions=versions),
    })

    attested = bool(getattr(agreement, "meets_stage_5", False))
    record("custodian_started", "custodian", {
        "backend": agreement.backend, "key_id": agreement.key_id,
        "kem": agreement.kem, "attested": attested,
        "presence_mode": args.presence_mode, "registry_versions": versions,
        "accepted_kems": list(STATE["custodian"].accepted_kems)})

    print(f"JustiKey custodian on http://{args.host}:{args.port}")
    print(f"  backend    : {agreement.backend}"
          f"{' (attested)' if attested else ''}")
    print(f"  key id     : {agreement.key_id}  [{agreement.kem}]")
    print(f"  presence   : {args.presence_mode}")
    print(f"  registries : approver v{versions['approver']}, "
          f"requester v{versions['requester']}")
    print(f"  ledger     : {args.ledger}")
    if not attested:
        print("\n  NOTE: this configuration does NOT meet the stage 5 objective.")
        print("  Without an enclave attestation, anything holding the same")
        print("  credentials can make the same call to the key holder. See")
        print("  docs/stage-5-key-isolation.md.")

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
