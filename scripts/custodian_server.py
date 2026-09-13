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
                      servicekit, transport)

STATE = {}


# ---------------------------------------------------------------------------
# One dispatch, both transports
# ---------------------------------------------------------------------------
#
# HTTP and vsock call exactly this. Two dispatch tables would be two lists of
# what the custodian accepts, and the day they disagree is the day one
# transport offers something the other refuses.

ALLOWED_FIELDS = {
    "index": {"plate"},
    "search-token": {"statement", "signature", "registry_versions"},
    "open": {"envelope", "identity", "statement", "signature", "requester",
             "presence", "presence_proof", "registry_versions"},
    "publickey": set(),
}

# Which caller may ask for what. `index` mints a scope token for an ARBITRARY
# plate, which is the whole capability the blind-index key confers: a caller
# holding the archive and this operation can ask for a token per candidate
# plate and map every sealed row without opening one. Measured before the
# split: 25 of 25 records identified in 0.44s against a small candidate space.
#
# So it is reserved to an ingest credential that the disclosure host does not
# have, and an attested custodian refuses to offer it at all. The disclosure
# host gets `search-token` instead, which mints a token for exactly the plate
# an approver signed for and nothing else.
OPERATION_ROLES = {
    "index": {"ingest"},
    "search-token": {"disclosure"},
    "open": {"disclosure"},
    "publickey": {"ingest", "disclosure"},
}


def dispatch(operation, payload, role="disclosure"):
    """(reply, status). Unknown operations are refused by name."""
    if operation not in ALLOWED_FIELDS:
        return {"error": f"unknown operation {operation!r}"}, 404
    if role not in OPERATION_ROLES[operation]:
        return {"error": f"{operation!r} is not available to a {role!r} caller"}, 403
    if operation == "index" and not STATE.get("allow_ingest_tokens"):
        return {"error": "this custodian does not mint arbitrary scope tokens"}, 403
    unknown = set(payload or {}) - ALLOWED_FIELDS[operation]
    if unknown:
        # Refused rather than ignored: a field this version ignores is a field
        # a later version might read, and the two would disagree about what
        # the message meant.
        return {"error": f"unknown fields for {operation}: {sorted(unknown)}"}, 400
    return _OPERATIONS[operation](payload or {})


def op_publickey(_payload):
    agreement = STATE["custodian"].agreement
    return {
        "public_key": agreement.public_raw.hex(),
        "key_id": agreement.key_id,
        "kem": agreement.kem,
        "seal_version": sealing.FORMAT_VERSION,
        "backend": agreement.backend,
        # Stated rather than implied: a deployment should be able to see from
        # the outside whether this custodian meets the stage 5 objective.
        "attested": bool(getattr(agreement, "meets_stage_5", False)),
        "registry_versions": STATE["registry_versions"],
    }, 200


def op_search_token(payload):
    """A scope token for exactly the plate an approver signed for.

    This is what the disclosure host gets instead of `index`. The approval is
    verified here, in full, before a token exists -- so a compromised parent
    can obtain tokens only for plates an approver independently authorised,
    rather than for every plate it can think of.

    It spends nothing. `open` remains the single transactional point, so a
    search that finds no candidates costs the requester nothing.
    """
    statement = payload.get("statement")
    if not isinstance(statement, dict):
        return {"error": "malformed approval statement"}, 403
    instance = STATE["custodian"]
    try:
        instance._check_registries(payload.get("registry_versions"))
        # Requester is taken from the statement rather than from the caller:
        # this operation authorises a scope, not a person, and the person is
        # checked at open.
        instance._check_approval(statement, payload.get("signature"),
                                 statement.get("requester"))
    except custodian.CustodianError as exc:
        STATE["record"]("search_token_refused", "client", {"reason": str(exc)[:300]})
        return {"error": str(exc)}, 403
    if not search_token_rate_ok():
        STATE["record"]("search_token_rate_limited", "client",
                        {"limit_per_minute": STATE["index_limit"]})
        return {"error": "scope-token rate limit exceeded"}, 429

    STATE["record"]("search_token_issued", "client", {
        "authorization_id": statement.get("authorization_id"),
        "approver": statement.get("approver"),
        "case": statement.get("case_number")})
    return {"plate_index": blind_index(statement["target_plate"])}, 200


def op_index(payload):
    """A scope token for an ARBITRARY plate. Ingest only, and not in production.

    This operation is the blind-index key's capability, exposed. A caller with
    the sealed archive and this operation maps every row without opening one.
    It exists because ingest must index observations as they arrive, and it is
    gated by a credential the disclosure host does not hold -- so mapping the
    archive needs both the ingest capability (which has no archive) and the
    archive (which has no capability).

    An attested custodian refuses to offer it. The real fix is tokenisation at
    the sensor; see threat-model.md.
    """
    plate = payload.get("plate")
    if not isinstance(plate, str) or not plate.strip():
        return {"error": "plate is required"}, 400
    if not index_rate_ok():
        STATE["record"]("index_rate_limited", "client",
                        {"limit_per_minute": STATE["index_limit"]})
        return {"error": "scope-token rate limit exceeded"}, 429
    STATE["record"]("scope_token_issued", "client", {})
    return {"plate_index": blind_index(plate)}, 200


def op_open(payload):
    envelope = payload.get("envelope")
    identity = payload.get("identity")
    requester = payload.get("requester")
    if not isinstance(envelope, dict) or not isinstance(identity, dict):
        return {"error": "envelope and identity are required"}, 400
    # One record. A list here would let a caller hand over the table and have
    # the custodian sort out which ones it likes, which is the oracle's shape.
    if isinstance(envelope.get("record_uid"), (list, tuple)):
        return {"error": "open takes exactly one record"}, 400

    statement = payload.get("statement")
    try:
        result = STATE["custodian"].open(
            envelope, identity, statement, payload.get("signature"), requester,
            payload.get("presence"), payload.get("presence_proof"),
            registry_versions=payload.get("registry_versions"),
            blind_index_of=blind_index)
    except custodian.AgreementUnavailable as exc:
        # The key holder being unreachable is an operating state, not a fault,
        # and never a reason to open anything another way.
        STATE["record"]("agreement_unavailable", f"requester:{requester}",
                        {"reason": str(exc)[:300]})
        return {"error": str(exc)}, 503
    except custodian.CustodianError as exc:
        STATE["record"]("open_refused", f"requester:{requester}", {
            "reason": str(exc)[:300], "record_uid": envelope.get("record_uid"),
            "case": statement.get("case_number") if isinstance(statement, dict) else None})
        return {"error": str(exc)}, 403

    # Recorded before the response is written: an opening that reached the
    # caller but not the ledger is exactly the gap that matters.
    STATE["record"]("open_granted", f"requester:{requester}", {
        "record_uid": envelope.get("record_uid"),
        "authorization_id": statement.get("authorization_id")
        if isinstance(statement, dict) else None,
        "approver": statement.get("approver") if isinstance(statement, dict) else None,
        "use_count": result["use_count"], "presence": result["presence"],
        "suite": result["suite"], "backend": result["backend"],
        "context": result["context_digest"]})
    # The plate never enters this ledger. Recording it here would rebuild the
    # archive the custodian exists to protect.
    return {"fields": result["fields"], "use_count": result["use_count"],
            "presence": result["presence"], "context": result["context_digest"]}, 200


_OPERATIONS = {"index": op_index, "search-token": op_search_token,
               "open": op_open, "publickey": op_publickey}


class Handler(servicekit.AuthenticatedHandler, BaseHTTPRequestHandler):
    server_version = "JustiKeyCustodian/1.0"

    @property
    def state(self):
        return STATE

    def do_GET(self):
        if self.path == "/healthz":
            return self._json(200, {"status": "ok"})
        if self.path == "/publickey":
            reply, status = dispatch("publickey", {})
            return self._json(status, reply)
        self._json(404, {"error": "not found"})

    def do_POST(self):
        operation = self.path.lstrip("/")
        if operation not in ALLOWED_FIELDS:
            return self._json(404, {"error": "not found"})
        payload = self._payload()
        if payload is None:
            return
        reply, status = dispatch(operation, payload, role=self.client_role)
        self._json(status, reply)


# ---------------------------------------------------------------------------

def blind_index(plate):
    """The custodian's own scope function.

    Never the caller's: a custodian that accepted somebody else's idea of
    which records match an approval would have re-created the oracle with
    extra steps.
    """
    normalized = str(plate).strip().upper().encode("utf-8")
    return hmac.new(STATE["index_key"], normalized, hashlib.sha256).hexdigest()


def search_token_rate_ok():
    return _rate_ok("search_calls")


def index_rate_ok():
    return _rate_ok("index_calls")


def _rate_ok(bucket):
    import time

    limit, window = STATE["index_limit"], 60.0
    if limit <= 0:
        return True
    now = time.monotonic()
    with STATE["index_lock"]:
        calls = STATE.setdefault(bucket, [])
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
        from justikey import enclave

        attestation = None
        if args.attest:
            # Inside an enclave: a fresh recipient keypair per operation, with
            # the NSM signing a document that carries its public key.
            attestation = enclave.NsmAttestation()
        elif args.attestation_file:
            with open(args.attestation_file, "rb") as fh:
                attestation = enclave.StaticAttestation(fh.read())
        if not args.public_key:
            raise SystemExit(
                "--public-key is required with --kms-key-arn: the custodian must "
                "know which public key records are sealed to, and asking KMS for "
                "it at every open would make an availability problem a "
                "correctness one")
        return custodian.KmsAgreement(
            boto3.client("kms", region_name=args.region), args.kms_key_arn,
            bytes.fromhex(args.public_key), attestation=attestation)

    material = args.key
    if not material and args.key_file:
        with open(args.key_file, "r") as fh:
            material = fh.read().strip()
    if not material:
        raise SystemExit("a backend is required: --kms-key-arn, or --key/--key-file")
    kem_name, private_hex = disclosure.decode_key(material)
    return custodian.LocalAgreement(private_hex, args.kem or kem_name)


def main():
    parser = argparse.ArgumentParser(
        description="JustiKey custodian: verifies the whole disclosure context, "
                    "then agrees exactly once")
    parser.add_argument("--transport", choices=("http", "vsock"), default="http",
                        help="http for development; vsock inside a Nitro enclave, "
                             "which is the only channel an enclave has")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8091)
    parser.add_argument("--vsock-cid", type=int, default=transport.VMADDR_CID_ANY,
                        help="CID to bind; the default accepts from the parent")
    parser.add_argument("--vsock-port", type=int, default=8091)
    parser.add_argument("--max-connections", type=int,
                        default=transport.DEFAULT_MAX_CONNECTIONS,
                        help="concurrent connections; an enclave has a fixed "
                             "memory allocation, so this is a refusal not a queue")
    parser.add_argument("--client-secret",
                        default=os.environ.get("JUSTIKEY_CUSTODIAN_CLIENT_SECRET"),
                        help="shared secret the disclosure service authenticates with")
    parser.add_argument("--ingest-secret",
                        default=os.environ.get("JUSTIKEY_CUSTODIAN_INGEST_SECRET"),
                        help="separate secret for the ingest path, which may mint "
                             "scope tokens for arbitrary plates. Must NOT be present "
                             "on the disclosure host, and an attested custodian "
                             "refuses it outright")
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
    parser.add_argument("--attest", action="store_true",
                        help="request an attestation document from the NSM per "
                             "KMS operation; requires running inside an enclave")
    parser.add_argument("--attestation-file",
                        help="a pre-obtained attestation document, for a deployment "
                             "that gets one out of band")
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
        "client_secrets": {"disclosure": args.client_secret,
                           "ingest": args.ingest_secret},
        "allow_ingest_tokens": bool(args.ingest_secret),
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

    # A production invariant, enforced rather than documented: an attested
    # custodian must not listen on TCP. A Nitro enclave has no external
    # network and no persistent storage, and vsock is its only channel -- a
    # TCP listener in that configuration either means this is not really an
    # enclave, or means something has been arranged to reach it that should
    # not exist. Refusing is cheaper than discovering which.
    # An attested custodian must not be an enumeration oracle. `index` mints a
    # token for any plate asked of it, which is the blind-index key's entire
    # capability; offering it from the component that also holds the archive's
    # only key would undo the isolation the enclave exists to provide.
    if attested and args.ingest_secret:
        print("\nRefusing to start: an attested custodian must not offer ingest "
              "scope tokens.\n`index` mints a token for any plate, which is the "
              "blind-index key's whole\ncapability -- a caller with the archive and "
              "that operation maps every row\nwithout opening one. Run ingest against "
              "its own custodian, on a host that\nholds no archive.", file=sys.stderr)
        sys.exit(5)

    if attested and args.transport != "vsock":
        print("\nRefusing to start: an attested custodian must serve on vsock, not "
              "TCP.\nAn enclave's only channel is AF_VSOCK; a TCP listener here means "
              "either\nthis is not an enclave, or something reaches it that should not.",
              file=sys.stderr)
        sys.exit(4)
    record("custodian_started", "custodian", {
        "backend": agreement.backend, "key_id": agreement.key_id,
        "kem": agreement.kem, "attested": attested,
        "presence_mode": args.presence_mode, "registry_versions": versions,
        "accepted_kems": list(STATE["custodian"].accepted_kems)})

    where = (f"vsock cid={args.vsock_cid} port={args.vsock_port}"
             if args.transport == "vsock" else f"http://{args.host}:{args.port}")
    print(f"JustiKey custodian on {where}")
    print(f"  backend    : {agreement.backend}"
          f"{' (attested)' if attested else ''}")
    print(f"  key id     : {agreement.key_id}  [{agreement.kem}]")
    print(f"  presence   : {args.presence_mode}")
    print(f"  scope tokens: search-token (approved scope only)"
          f"{'; index ENABLED for ingest' if args.ingest_secret else ''}")
    print(f"  registries : approver v{versions['approver']}, "
          f"requester v{versions['requester']}")
    print(f"  ledger     : {args.ledger}")
    if not attested:
        print("\n  NOTE: this configuration does NOT meet the stage 5 objective.")
        print("  Without an enclave attestation, anything holding the same")
        print("  credentials can make the same call to the key holder. See")
        print("  docs/stage-5-key-isolation.md.")

    if args.transport == "vsock":
        server = transport.VsockServer(
            args.vsock_cid, args.vsock_port, dispatch,
            max_connections=args.max_connections).bind()
        record("listener_started", "custodian",
               {"transport": "vsock", "cid": args.vsock_cid, "port": args.vsock_port})
    else:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if args.transport == "vsock":
            server.shutdown()
        else:
            server.server_close()


if __name__ == "__main__":
    main()
