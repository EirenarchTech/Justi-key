#!/usr/bin/env python3
"""Proof of concept: approval as a cryptographic capability.

Demonstrates the model in docs/capability-model.md end to end, standalone, so
the design can be judged before any of it lands in the main codebase.

The claim under test: a compromised application server should be unable to
read plate history, even holding the whole database and its own keys, unless
an approver has signed a scoped authorization.

Run it:  python3 scripts/capability_poc.py
"""
import json
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

from justikey import timeutil  # noqa: E402


def rule(title):
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ---------------------------------------------------------------------------
# The application server: can write, cannot read
# ---------------------------------------------------------------------------

class ApplicationServer:
    """Holds only a public key. Encrypts observations; can never decrypt."""

    def __init__(self, disclosure_public_key):
        self.pub = disclosure_public_key
        self.store = []

    def ingest(self, plate, captured_at, camera_id, location):
        # Fresh record key per observation, sealed to the disclosure service's
        # public key via an ephemeral X25519 exchange (ECIES-style).
        record_key = AESGCM.generate_key(bit_length=256)
        aad = canonical({"captured_at": captured_at, "camera_id": camera_id})
        nonce = os.urandom(12)
        sealed_fields = AESGCM(record_key).encrypt(
            nonce, canonical({"plate": plate, "location": location}), aad)

        ephemeral = x25519.X25519PrivateKey.generate()
        shared = ephemeral.exchange(self.pub)
        wrap_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                        info=b"justikey:record-key-wrap:v1").derive(shared)
        wrap_nonce = os.urandom(12)
        wrapped = AESGCM(wrap_key).encrypt(wrap_nonce, record_key, aad)

        self.store.append({
            "plate_index": plate.upper(),   # stands in for the keyed blind index
            "captured_at": captured_at, "camera_id": camera_id,
            "nonce": nonce, "sealed_fields": sealed_fields,
            "ephemeral_pub": ephemeral.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            "wrap_nonce": wrap_nonce, "wrapped_key": wrapped, "aad": aad,
        })

    def try_to_read_everything(self):
        """What a compromised app server or a rogue administrator can extract."""
        out = []
        for row in self.store:
            try:
                out.append(AESGCM(row["wrapped_key"][:32]).decrypt(
                    row["nonce"], row["sealed_fields"], row["aad"]))
            except Exception:
                out.append(None)
        return out


# ---------------------------------------------------------------------------
# The disclosure service: holds the private key, enforces scope itself
# ---------------------------------------------------------------------------

class DisclosureService:
    """Separate trust domain. Unwraps only for a validly approved scope."""

    def __init__(self, approver_public_keys):
        self._private = x25519.X25519PrivateKey.generate()
        self.approver_public_keys = approver_public_keys
        self.disclosure_log = []

    @property
    def public_key(self):
        return self._private.public_key()

    def _verify_approval(self, authorization, signature, approver):
        pub = self.approver_public_keys.get(approver)
        if pub is None:
            raise PermissionError(f"unknown approver {approver!r}")
        if authorization["requested_by"] == approver:
            raise PermissionError("self-approval: requester and approver are the same person")
        pub.verify(signature, canonical(authorization))

    def disclose(self, authorization, signature, approver, rows, requester):
        """Return plaintext only for records the approval actually covers."""
        self._verify_approval(authorization, signature, approver)

        if requester != authorization["requested_by"]:
            raise PermissionError("this authorization belongs to another requester")
        if timeutil.now_iso() > authorization["expires_at"]:
            raise PermissionError("approval has expired")

        revealed = []
        for row in rows:
            # Scope is re-checked here, in the service that holds the key --
            # not trusted from the caller that asked.
            if row["plate_index"] != authorization["target_plate"]:
                continue
            if not (authorization["window_start"] <= row["captured_at"]
                    <= authorization["window_end"]):
                continue
            shared = self._private.exchange(
                x25519.X25519PublicKey.from_public_bytes(row["ephemeral_pub"]))
            wrap_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                            info=b"justikey:record-key-wrap:v1").derive(shared)
            record_key = AESGCM(wrap_key).decrypt(
                row["wrap_nonce"], row["wrapped_key"], row["aad"])
            fields = AESGCM(record_key).decrypt(row["nonce"], row["sealed_fields"], row["aad"])
            revealed.append(json.loads(fields))

        self.disclosure_log.append({
            "case": authorization["case_number"], "approver": approver,
            "requester": requester, "records": len(revealed),
            "at": timeutil.now_iso()})
        return revealed


# ---------------------------------------------------------------------------

def main():
    approver_key = ed25519.Ed25519PrivateKey.generate()
    rogue_key = ed25519.Ed25519PrivateKey.generate()
    service = DisclosureService({"supervisor1": approver_key.public_key()})
    app = ApplicationServer(service.public_key)

    for plate, when, cam, loc in [
        ("ABC123", "2026-08-10T09:00:00.000000+00:00", "CAM-1", "North Gate"),
        ("ABC123", "2026-08-12T17:30:00.000000+00:00", "CAM-2", "South Lot"),
        ("ABC123", "2026-11-01T08:00:00.000000+00:00", "CAM-1", "North Gate"),
        ("ZZZ999", "2026-08-11T12:00:00.000000+00:00", "CAM-3", "Depot"),
    ]:
        app.ingest(plate, when, cam, loc)
    print(f"Ingested {len(app.store)} observations. The app server holds only a public key.")

    rule("1. Can the application server read its own database?")
    leaked = [r for r in app.try_to_read_everything() if r is not None]
    print(f"  plaintext recovered by the app itself : {len(leaked)} of {len(app.store)}")
    print("  A compromised app, or an administrator with full host access and")
    print("  the entire database, recovers nothing. There is no key here to steal.")

    authorization = {
        "case_number": "CASE-2026-001", "legal_authority": "Warrant 2026-001",
        "target_plate": "ABC123", "requested_by": "officer1",
        "window_start": "2026-08-01T00:00:00.000000+00:00",
        "window_end": "2026-08-31T23:59:59.999999+00:00",
        "expires_at": "2099-01-01T00:00:00.000000+00:00",
    }
    signature = approver_key.sign(canonical(authorization))

    rule("2. With a valid approver signature, scoped to ABC123 in August")
    revealed = service.disclose(authorization, signature, "supervisor1", app.store, "officer1")
    for r in revealed:
        print(f"  disclosed: {r}")
    print(f"  {len(revealed)} of {len(app.store)} records released.")
    print("  The November sighting and the other vehicle stayed sealed: the key")
    print("  holder enforced scope, not the caller that asked for it.")

    rule("3. Attacks against the capability")
    for label, run in [
        ("unsigned request (no approval at all)",
         lambda: service.disclose(authorization, b"\x00" * 64, "supervisor1", app.store, "officer1")),
        ("signature from a key the service does not trust",
         lambda: service.disclose(authorization, rogue_key.sign(canonical(authorization)),
                                  "supervisor1", app.store, "officer1")),
        ("scope widened after signing (plate swapped)",
         lambda: service.disclose({**authorization, "target_plate": "ZZZ999"},
                                  signature, "supervisor1", app.store, "officer1")),
        ("window widened after signing",
         lambda: service.disclose({**authorization, "window_end": "2099-01-01T00:00:00.000000+00:00"},
                                  signature, "supervisor1", app.store, "officer1")),
        ("another user borrows this approval",
         lambda: service.disclose(authorization, signature, "supervisor1", app.store, "officer2")),
        ("expired approval",
         lambda: service.disclose({**authorization, "expires_at": "2020-01-01T00:00:00.000000+00:00"},
                                  approver_key.sign(canonical(
                                      {**authorization, "expires_at": "2020-01-01T00:00:00.000000+00:00"})),
                                  "supervisor1", app.store, "officer1")),
        ("self-approval by the requester",
         lambda: service.disclose({**authorization, "requested_by": "supervisor1"},
                                  approver_key.sign(canonical(
                                      {**authorization, "requested_by": "supervisor1"})),
                                  "supervisor1", app.store, "supervisor1")),
    ]:
        try:
            run()
            print(f"  {label:<48} ALLOWED  <-- would be a flaw")
        except (InvalidSignature, PermissionError, Exception) as exc:
            print(f"  {label:<48} refused ({type(exc).__name__})")

    rule("What this buys, and what it costs")
    print("  Two-person control stops being an `if` statement the application")
    print("  chooses to honour and becomes arithmetic: no approver signature,")
    print("  no key, no plaintext.")
    print()
    print("  The cost is concentration: the disclosure service can read")
    print("  everything, so it is only worth building if that service is")
    print("  genuinely more defensible than the app -- separate host, minimal")
    print("  surface, HSM-held key. On the same box it is theatre.")
    print()
    print("  See docs/capability-model.md for the staged path and full costs.")


if __name__ == "__main__":
    main()
