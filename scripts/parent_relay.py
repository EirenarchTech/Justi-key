#!/usr/bin/env python3
"""The ingress relay: a network endpoint on the parent, vsock into the enclave.

WHY THIS EXISTS

The custodian runs inside a Nitro enclave, whose only channel is vsock, and
vsock does not cross a network. When the disclosure service runs on the same
parent instance it needs nothing: it opens `vsock://<cid>:8091` directly. When
it runs on an on-premises appliance -- which is the JustiKey prototype
topology -- something on the parent has to accept the request and carry it the
last hop.

That something is this. It is deliberately not a generic TCP-to-vsock pipe:

  * it accepts exactly the custodian's operations, by name, and refuses the
    rest, including `index` -- the operation that mints a scope token for an
    arbitrary plate. The disclosure side must never reach it, and a relay that
    forwarded whatever path it was handed would be one custodian
    misconfiguration away from re-opening attack 13
  * it parses the JSON body and re-frames it, so a malformed or oversized
    request dies here rather than inside the enclave
  * it bounds concurrency, because an enclave has a fixed memory allocation

WHAT IT IS NOT

It is not an authorization boundary, and nothing here should ever be cited as
one. Two specific things follow.

First, it grants no privilege the parent did not already have. Anything
running on the parent can open a vsock connection to the enclave, and the
custodian treats every vsock caller as the `disclosure` role already -- the
CID is not a credential. So this process does not widen what the parent can
ask for. It narrows it.

Second, its HMAC authentication says which appliance is calling. It does not
say the call is allowed. That remains, entirely and only, the custodian's
judgement against its own copies of the approver and requester registries,
the presence proof, the scope and the nonce state.

THE RESIDUAL, STATED PLAINLY

TLS terminates here, on the parent, which is inside the threat model. This
process therefore sees the plaintext of every record it relays back -- not the
archive, and not the key, but every record actually disclosed while it is
compromised.

That is a real reduction against the same-host arrangement and it is not
closed by anything in this file. Closing it needs TLS terminating *inside*
the enclave, with the appliance pinning the enclave's attested key rather
than a certificate authority, so the relay forwards bytes it cannot read. The
transport layer has the pin (`transport.TlsPolicy`); the enclave side does
not exist yet. Until it does, the honest claim for this relay is: the
archive-decryption key stays isolated, and disclosures in flight do not.
"""
import argparse
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import disclosure, servicekit, transport  # noqa: E402

# `index` is absent on purpose. See the module docstring.
RELAY_OPERATIONS = ("open", "search-token", "publickey")

STATE = {}


class Handler(servicekit.AuthenticatedHandler, BaseHTTPRequestHandler):

    @property
    def state(self):
        return STATE

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
        operation = self.path.strip("/")
        if operation not in RELAY_OPERATIONS:
            STATE["record"]("relay_operation_refused", "client",
                            {"operation": operation[:64]})
            self._json(404, {"error": f"the relay does not carry {operation!r}"})
            return

        # servicekit's ceiling is 8 MiB; a vsock frame's is 1 MiB. Enforce the
        # smaller one here, because a body the enclave could never be sent
        # should be refused with the reason rather than forwarded into a
        # framing error the caller cannot interpret.
        try:
            declared = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            declared = 0
        if declared > transport.MAX_FRAME_BYTES:
            self.close_connection = True
            STATE["record"]("relay_body_too_large", "client",
                            {"operation": operation, "declared": declared})
            self._json(413, {"error": "request body too large for one frame"})
            return

        payload = self._payload()
        if payload is None:
            return

        if not STATE["slots"].acquire(blocking=False):
            STATE["relay_rejected_over_capacity"] += 1
            STATE["record"]("relay_at_capacity", "client", {"operation": operation})
            self._json(503, {"error": "the relay is at capacity"})
            return
        try:
            reply, status = STATE["forward"](operation, payload)
        except transport.TransportError as exc:
            STATE["record"]("relay_custodian_unreachable", "client",
                            {"operation": operation, "detail": str(exc)[:300]})
            self._json(502, {"error": "the custodian is unreachable"})
            return
        except Exception as exc:  # noqa: BLE001 - see below
            # Deliberately broad, and only here. An unhandled exception in a
            # handler thread closes the connection with no reply, which reaches
            # the appliance as a network error and reaches the operator as
            # nothing at all. A relay that fails must say so in its own ledger
            # and answer with a status, not disappear.
            STATE["record"]("relay_internal_error", "client",
                            {"operation": operation, "detail": repr(exc)[:300]})
            self._json(500, {"error": "the relay failed to carry this request"})
            return
        finally:
            STATE["slots"].release()

        STATE["record"]("relay_forwarded", f"client:{self.client_role}",
                        {"operation": operation, "status": status})
        self._json(status, reply)


def main():
    parser = argparse.ArgumentParser(
        description="Relay custodian requests from a network into an enclave")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=8443)
    parser.add_argument("--enclave-cid", type=int,
                        help="the enclave's CID, from nitro-cli describe-enclaves")
    parser.add_argument("--enclave-port", type=int, default=8091)
    parser.add_argument("--custodian-url",
                        help="rehearsal: reach the custodian at this URL instead of "
                             "vsock. Goes through transport.for_url like everything "
                             "else, so a remote http:// custodian is refused here too")
    parser.add_argument("--appliance-secret",
                        default=os.environ.get("JUSTIKEY_RELAY_APPLIANCE_SECRET"),
                        help="shared secret the appliance's disclosure service signs with")
    parser.add_argument("--tls-cert", help="PEM certificate chain for this endpoint")
    parser.add_argument("--tls-key", help="PEM private key; defaults to --tls-cert")
    parser.add_argument("--client-ca",
                        help="require a client certificate signed by this CA (mutual TLS)")
    parser.add_argument("--custodian-secret",
                        default=os.environ.get("JUSTIKEY_CUSTODIAN_CLIENT_SECRET"),
                        help="only used with --custodian-url; a vsock custodian "
                             "authenticates nothing at the transport layer")
    parser.add_argument("--max-connections", type=int, default=32)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--ledger", default="relay-audit.db")
    args = parser.parse_args()

    if not args.appliance_secret:
        print("Refusing to start: --appliance-secret is required.", file=sys.stderr)
        return 2
    if args.custodian_url and not args.custodian_secret:
        print("Refusing to start: --custodian-url needs --custodian-secret; an "
              "HTTP transport signs every request.", file=sys.stderr)
        return 2
    if not args.custodian_url and args.enclave_cid is None:
        print("Refusing to start: one of --enclave-cid or --custodian-url is "
              "required.", file=sys.stderr)
        return 2

    local = transport.is_loopback(args.listen_host)
    if not args.tls_cert and not local:
        print("\nRefusing to start: this endpoint would carry opened records in "
              "clear.\n"
              f"  --listen-host {args.listen_host} is not a loopback address and "
              "no --tls-cert was given.\n"
              "  Supply a certificate, or bind to loopback for a local test.\n",
              file=sys.stderr)
        return 6
    if args.client_ca and not args.tls_cert:
        print("Refusing to start: --client-ca requires --tls-cert; mutual TLS "
              "needs a server certificate too.", file=sys.stderr)
        return 7

    servicekit.init_ledger(args.ledger)
    record = servicekit.LedgerWriter(args.ledger)
    usage = disclosure.UsageStore(args.ledger)
    usage.purge_expired()

    if args.custodian_url:
        forward = transport.for_url(args.custodian_url, "relay",
                                    args.custodian_secret, args.timeout)
        destination = args.custodian_url
    else:
        forward = transport.VsockTransport(args.enclave_cid, args.enclave_port,
                                           args.timeout)
        destination = f"vsock cid={args.enclave_cid} port={args.enclave_port}"
    STATE.update({
        "client_secrets": {"disclosure": args.appliance_secret},
        "usage": usage,
        "record": record,
        "slots": threading.Semaphore(args.max_connections),
        "relay_rejected_over_capacity": 0,
        "forward": forward.request,
    })

    server = ThreadingHTTPServer((args.listen_host, args.listen_port), Handler)
    scheme = "http"
    if args.tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.tls_cert, args.tls_key or args.tls_cert)
        if args.client_ca:
            context.load_verify_locations(args.client_ca)
            context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"

    where = f"{scheme}://{args.listen_host}:{args.listen_port}"
    print(f"JustiKey ingress relay on {where}")
    print(f"  to the custodian at {destination}")
    print(f"  carrying {', '.join(RELAY_OPERATIONS)} (not 'index')")
    if args.client_ca:
        print("  mutual TLS: a client certificate is required")
    if scheme == "http":
        print("  plaintext, loopback only -- development")
    print("  TLS terminates here, on the parent. This process sees every record")
    print("  it relays back. See the module docstring.")
    record("relay_started", "relay", {
        "listen": where, "destination": destination,
        "mutual_tls": bool(args.client_ca), "operations": list(RELAY_OPERATIONS)})

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
