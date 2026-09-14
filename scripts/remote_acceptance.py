#!/usr/bin/env python3
"""Acceptance for the remote path: appliance -> TLS relay -> vsock -> enclave.

WHAT THIS IS FOR

The 13 gates in docs/nitro-deployment-runbook.md ask whether AWS enforces the
attestation boundary. They say nothing about the topology the JustiKey
prototype actually deploys: an on-premises appliance reaching a custodian
that lives in an enclave in a cloud account, through a relay on the parent.

That path has its own properties, and they are the gate on promoting the
relay and the hardened transport out of the feature branch. This script runs
the ones a client can prove by itself and prints, for the rest, exactly what
an operator has to look at and record.

WHAT IT DELIBERATELY DOES NOT DO

It does not open a record. A disclosure needs an approver signature and a
requester presence proof, which come from the appliance's own enrolment, not
from a test harness -- and a script that could manufacture them would be a
script that had defeated the thing being tested. R11 is therefore an operator
observation: perform a real approved disclosure through the application and
confirm the record comes back.

VERDICTS

  PASS          the property held, proved here
  FAIL          the property did not hold; do not promote
  INCONCLUSIVE  the check could not be driven from here; the detail says why
  OBSERVE       an operator has to look at a ledger, a console or CloudTrail
"""
import argparse
import json
import os
import secrets
import ssl
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import servicekit, timeutil, transport  # noqa: E402

PASS, FAIL, INCONCLUSIVE, OBSERVE = "PASS", "FAIL", "INCONCLUSIVE", "OBSERVE"


class Checks:

    def __init__(self, options):
        self.options = options
        self.results = []

    def record(self, identifier, name, verdict, detail):
        self.results.append({"id": identifier, "name": name, "verdict": verdict,
                             "detail": detail,
                             "observed_at": timeutil.now_iso()})
        marker = {PASS: "ok", FAIL: "FAIL", INCONCLUSIVE: "--", OBSERVE: "look"}[verdict]
        print(f"  [{marker:>4}] {identifier}  {name}")
        if detail:
            print(f"         {detail}")

    def policy(self, **overrides):
        settings = {
            "ca_file": self.options.tls_ca,
            "spki_pin": self.options.tls_pin,
            "client_cert": self.options.client_cert,
            "client_key": self.options.client_key,
        }
        settings.update(overrides)
        return transport.TlsPolicy(**settings)

    def client(self, **overrides):
        return transport.for_url(self.options.url, "disclosure",
                                 self.options.client_secret,
                                 self.options.timeout, tls=self.policy(**overrides))

    # -- R1 ----------------------------------------------------------------

    def r1_endpoint_answers(self):
        """Appliance -> TLS relay -> vsock -> enclave, in one call."""
        try:
            body, status = self.client().request("publickey", {})
        except transport.TransportError as exc:
            return self.record("R1", "TLS relay reachable end to end", FAIL,
                               f"{exc}")
        if status != 200 or not body.get("public_key"):
            return self.record("R1", "TLS relay reachable end to end", FAIL,
                               f"status={status} body={json.dumps(body)[:200]}")
        self.custodian_public_key = body["public_key"]
        self.record("R1", "TLS relay reachable end to end", PASS,
                    f"publickey returned {len(body['public_key'])//2} bytes, "
                    f"backend={body.get('backend', 'unreported')}")
        self.record("R2", "Relay reached the enclave over vsock", OBSERVE,
                    "R1 could only be answered by the custodian. Confirm in the "
                    "relay ledger that the destination recorded at startup is "
                    "vsock, not a URL.")
        self.record("R3", "Enclave reached KMS in the expected Region", OBSERVE,
                    "CloudTrail: a DeriveSharedSecret with a Recipient, from the "
                    "enclave's role, in the Region the key was created in.")

    # -- R4 ----------------------------------------------------------------

    def r4_carried_operations(self):
        carried, refused = [], []
        for operation in ("publickey", "search-token"):
            try:
                _body, status = self.client().request(operation, {})
            except transport.TransportError as exc:
                refused.append(f"{operation}: {exc}")
                continue
            # 400/403 is a fine answer here: it means the request reached the
            # custodian and the custodian judged it. 404 would mean the relay
            # does not carry the operation at all.
            (refused if status == 404 else carried).append(f"{operation}:{status}")
        verdict = FAIL if refused else PASS
        self.record("R4", "search-token and publickey are carried", verdict,
                    f"carried={carried} refused={refused}")
        self.record("R11", "An approved disclosure returns to the appliance",
                    OBSERVE,
                    "Not driven from here: a disclosure needs a real approver "
                    "signature and presence proof. Perform one through the "
                    "application and confirm the record comes back.")

    # -- R5 ----------------------------------------------------------------

    def r5_index_refused(self):
        try:
            body, status = self.client().request("index", {"plate": "ACCEPT01"})
        except transport.TransportError as exc:
            return self.record("R5", "index is refused at the relay", FAIL,
                               f"transport error rather than a refusal: {exc}")
        if status != 404:
            return self.record("R5", "index is refused at the relay", FAIL,
                               f"expected 404, got {status}: {json.dumps(body)[:200]}")
        self.record("R5", "index is refused at the relay", PASS,
                    f"404 {body.get('error', '')!r}")
        self.record("R6", "index never reached the enclave", OBSERVE,
                    "The custodian's own ledger must contain no index or "
                    "scope_token_issued event for plate ACCEPT01 at the time "
                    "above. The relay ledger should show relay_operation_refused.")

    # -- R7 ----------------------------------------------------------------

    def r7_oversized(self):
        oversized = {"pad": "x" * (transport.MAX_FRAME_BYTES + 4096)}
        try:
            body, status = self.client().request("open", oversized)
        except transport.TransportError as exc:
            return self.record("R7", "An oversized request fails at the parent",
                               PASS,
                               f"refused mid-send: {str(exc)[:120]}. The relay "
                               "answers on Content-Length and closes without "
                               "draining, so this or a 413 are both correct.")
        if status != 413:
            return self.record("R7", "An oversized request fails at the parent",
                               FAIL,
                               f"expected 413 or a dropped connection, got {status}")
        self.record("R7", "An oversized request fails at the parent", PASS,
                    f"413 {body.get('error', '')!r}")

    # -- R8 ----------------------------------------------------------------

    def r8_capacity(self):
        """Exhaustion must refuse, not queue."""
        fan_out = self.options.capacity_fan_out
        statuses, errors = [], []
        lock = threading.Lock()

        def attempt():
            try:
                _body, status = self.client().request("publickey", {})
            except transport.TransportError as exc:
                with lock:
                    errors.append(str(exc)[:80])
                return
            with lock:
                statuses.append(status)

        started = time.time()
        threads = [threading.Thread(target=attempt) for _ in range(fan_out)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        elapsed = time.time() - started

        refused = statuses.count(503)
        if refused:
            self.record("R8", "Capacity exhaustion refuses rather than queues",
                        PASS,
                        f"{refused} of {fan_out} got 503 in {elapsed:.1f}s "
                        f"(statuses={sorted(set(statuses))}, errors={len(errors)})")
        else:
            self.record("R8", "Capacity exhaustion refuses rather than queues",
                        INCONCLUSIVE,
                        f"no 503 in {fan_out} concurrent calls ({elapsed:.1f}s). "
                        "Restart the relay with --max-connections 1 and rerun; a "
                        "custodian fast enough to answer everything cannot "
                        "demonstrate the refusal.")

    # -- R9 ----------------------------------------------------------------

    def r9_no_plaintext(self):
        from urllib.parse import urlsplit

        insecure = self.options.url.replace("https://", "http://", 1)
        host = urlsplit(self.options.url).hostname
        loopback = transport.is_loopback(host)
        try:
            transport.for_url(insecure, "disclosure", self.options.client_secret,
                              tls=transport.TlsPolicy())
        except transport.TransportError as exc:
            return self.record("R9", "A remote http:// custodian is impossible",
                               PASS, str(exc)[:160])
        # Plain HTTP to loopback is allowed on purpose: nothing crosses a wire.
        # So against a loopback relay this check cannot say anything, and must
        # not report a pass it did not earn.
        verdict = INCONCLUSIVE if loopback else FAIL
        self.record("R9", "A remote http:// custodian is impossible", verdict,
                    f"{insecure} was accepted; {host!r} is a loopback address, so "
                    "run this check against the real relay hostname"
                    if loopback else f"{insecure} was accepted")

    # -- R10 ---------------------------------------------------------------

    def r10_pinning(self):
        wrong = secrets.token_hex(32)
        try:
            self.client(spki_pin=wrong).request("open", {"canary": self.canary})
        except transport.TransportError as exc:
            if "pin" not in str(exc):
                self.record("R10a", "A wrong pin refuses before sending", FAIL,
                            f"failed for another reason: {exc}")
            else:
                self.record("R10a", "A wrong pin refuses before sending", PASS,
                            str(exc)[:120])
        else:
            self.record("R10a", "A wrong pin refuses before sending", FAIL,
                        "the request completed against an unpinned peer")

        # A right pin over a chain no CA vouches for must still fail.
        if not self.options.tls_pin:
            self.record("R10b", "A right pin over an untrusted chain still fails",
                        INCONCLUSIVE, "no --tls-pin configured")
        else:
            try:
                self.client(ca_file=None).request("publickey", {})
            except transport.TransportError as exc:
                self.record("R10b",
                            "A right pin over an untrusted chain still fails",
                            PASS, str(exc)[:120])
            else:
                self.record("R10b",
                            "A right pin over an untrusted chain still fails",
                            FAIL if self.options.tls_ca else INCONCLUSIVE,
                            "the system trust store already vouches for this "
                            "chain, so this check proves nothing here")

        self.record("R10c", "The pinned refusal sent no request body", OBSERVE,
                    f"The relay ledger must contain no entry for canary "
                    f"{self.canary}. If it does, the approval was written to the "
                    "socket before the peer was checked.")

    # -- R12 ---------------------------------------------------------------

    def r12_client_certificate(self):
        if not self.options.client_cert:
            return self.record("R12", "Mutual TLS is enforced", INCONCLUSIVE,
                               "no --client-cert configured; run this against a "
                               "relay started with --client-ca")
        try:
            self.client(client_cert=None, client_key=None).request("publickey", {})
        except transport.TransportError as exc:
            return self.record("R12", "Mutual TLS is enforced", PASS,
                               f"refused without a client certificate: "
                               f"{str(exc)[:110]}")
        self.record("R12", "Mutual TLS is enforced", FAIL,
                    "the relay answered a client with no certificate")

    # -- authentication ----------------------------------------------------

    def r13_authentication(self):
        try:
            _body, status = self.client().request("publickey", {})
            unauthenticated = transport.for_url(
                self.options.url, "disclosure", secrets.token_hex(32),
                self.options.timeout, tls=self.policy())
            _body, wrong = unauthenticated.request("publickey", {})
        except transport.TransportError as exc:
            return self.record("R13", "A wrong client secret is refused",
                               INCONCLUSIVE, str(exc)[:140])
        if wrong == 401 and status == 200:
            self.record("R13", "A wrong client secret is refused", PASS,
                        "401 for an unknown secret, 200 for the configured one")
        else:
            self.record("R13", "A wrong client secret is refused", FAIL,
                        f"configured={status} wrong-secret={wrong}")

    def r14_ledgers(self):
        self.record("R14", "Audit behaviour is unchanged through the remote path",
                    OBSERVE,
                    "Run scripts/verify_audit.py against the relay ledger and the "
                    "custodian ledger. Both chains must verify, and the custodian's "
                    "disclosure events must match the appliance's.")

    def run(self):
        self.canary = f"acceptance-{secrets.token_hex(8)}"
        print(f"\nJustiKey remote-path acceptance against {self.options.url}")
        print(f"canary {self.canary}\n")
        self.custodian_public_key = None
        self.r1_endpoint_answers()
        self.r4_carried_operations()
        self.r5_index_refused()
        self.r7_oversized()
        self.r8_capacity()
        self.r9_no_plaintext()
        self.r10_pinning()
        self.r12_client_certificate()
        self.r13_authentication()
        self.r14_ledgers()
        return self.results


def main():
    parser = argparse.ArgumentParser(
        description="Acceptance for the appliance -> relay -> enclave path")
    parser.add_argument("--url", required=True,
                        help="the relay endpoint, e.g. https://parent.example:8443")
    parser.add_argument("--client-secret",
                        default=os.environ.get("JUSTIKEY_RELAY_APPLIANCE_SECRET"),
                        required=False)
    parser.add_argument("--tls-ca")
    parser.add_argument("--tls-pin")
    parser.add_argument("--client-cert")
    parser.add_argument("--client-key")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--capacity-fan-out", type=int, default=64)
    parser.add_argument("--evidence", help="write the results here as JSON")
    options = parser.parse_args()

    if not options.client_secret:
        parser.error("--client-secret is required "
                     "(or JUSTIKEY_RELAY_APPLIANCE_SECRET)")

    results = Checks(options).run()
    counts = {}
    for result in results:
        counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1
    print("\n  " + "  ".join(f"{verdict}={count}"
                             for verdict, count in sorted(counts.items())))

    if options.evidence:
        with open(options.evidence, "w", encoding="utf-8") as handle:
            json.dump({"url": options.url, "run_at": timeutil.now_iso(),
                       "results": results}, handle, indent=2)
        print(f"  evidence written to {options.evidence}")

    if counts.get(FAIL):
        print("\n  Do not promote: a property this topology depends on did not "
              "hold.\n")
        return 1
    if counts.get(OBSERVE) or counts.get(INCONCLUSIVE):
        print("\n  No failures. The OBSERVE rows are not optional -- they are the "
              "half\n  a client cannot prove about itself.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
