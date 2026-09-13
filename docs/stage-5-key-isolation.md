# Stage 5: key isolation

**Objective.** *Compromise of the disclosure-service process must not reveal a
reusable archive-decryption secret or provide an unrestricted cryptographic
oracle.*

This document records what has to be decided before any of it is written,
because two findings change the design rather than the implementation.

---

## Finding 1: an HSM alone does not meet the objective

The obvious reading of "put the key in an HSM" is: create a non-exportable
key pair, and have the disclosure service call `DeriveSharedSecret` (or
`CKM_ECDH1_DERIVE`) instead of holding the private half. The key can never be
exfiltrated. Objective met.

It is not. Consider what a compromised disclosure service still holds:

- every sealed row, including each record's `ephemeral_pub`
- credentials to call the HSM
- no obligation to run any of its own checks first

So it calls the HSM once per record, with that record's own ephemeral public
key, and receives the shared secret that opens it. Walk the table; decrypt the
archive. The private key never leaves the HSM and the archive is gone anyway.

**A non-exportable key stops exfiltration of the key. It does nothing about an
unrestricted oracle, because raw ECDH *is* the oracle.** The second half of
the stated objective is the harder half, and it is not solved by procurement.

What follows from that: the thing holding the key cannot be a raw KMS
operation. It has to be a **custodian** that verifies the disclosure context
for itself before agreeing to anything — an independent re-check of the same
facts the disclosure service checks, performed by a different principal. The
KMS or HSM is then where the custodian's key lives, not the boundary itself.

The boundary is the *operation*, not the storage.

```
  disclosure service  ──unwrap(context)──▶  custodian  ──derive──▶  HSM/KMS
   (may be compromised)                    (verifies for itself)   (non-exportable)
```

The custodian's operation must be bound to, at minimum:

| Bound to | Why |
|---|---|
| record/envelope identity (`record_uid`, `recipient_key_id`) | one call opens one record, not a table scan |
| approval statement digest | the scope an approver actually signed |
| requester proof of presence | a live human, not a replayed row |
| scope (plate index, window) | re-derived, not accepted from the caller |
| key version | rotation is expressible without an exportable master |

Anything less and the custodian is a slower HSM.

---

## Finding 2: the current envelope uses a curve HSMs mostly will not do

`jk-seal-v3` is X25519 → HKDF → AES-256-GCM. Checked against the products a
deployment would actually buy:

| Product | ECDH key agreement | X25519 for agreement |
|---|---|---|
| AWS KMS | `ECC_NIST_P256/384/521`, SM2 | **No.** `ECC_NIST_EDWARDS25519` is explicitly excluded from key agreement |
| Google Cloud KMS | no standalone ECDH purpose at all | **No.** Curve25519 is EdDSA-signing only; X25519 appears only inside the X-Wing hybrid KEM |
| Azure Key Vault Managed HSM | P-256, P-256K, P-384, P-521 | **No** |
| YubiHSM 2 | "all curves except curve25519" | **No.** Curve25519 is EdDSA-only |
| Thales Luna | `CKM_ECDH1_DERIVE` with `EC_MONT` | **Partial, and narrowing.** Vendor doc distinguishes "X25519 Montgomery" from "X25519"; firmware 7.8.9+ enforces FIPS-approved curves only, and X25519 is not FIPS-approved for key agreement |
| Entrust nShield | `CKM_ECDH1_DERIVE`, accepts `CKK_EC_MONTGOMERY` per RFC 7748 | **Apparently yes** — the one mainstream option |

The pattern: **P-256 ECDH is universally available non-exportably; X25519 is
not.** Building stage 5 on the current envelope would strand the project on a
single vendor, or on a non-FIPS configuration, and that is exactly the
"redesign around a provider and discover afterwards" failure this was checked
to avoid.

Worth noting in passing: Google's `KEY_ENCAPSULATION` purpose (ML-KEM-768,
ML-KEM-1024, X-Wing) is a *better-shaped* primitive than raw ECDH —
encapsulate/decapsulate is closer to "derive for one context" than "here is a
Diffie-Hellman oracle" — but it is one vendor, and decapsulation still hands
the caller a shared secret, so it does not remove the need for a custodian.

### The decision

**A. Move to P-256 (`jk-seal-v4`), curve-agile.** Envelope names its KEM
explicitly so the format never hard-codes a curve again. Works with every
product above. Requires a v3 → v4 reseal — the ceremony machinery already
exists (`scripts/seal_store.py`), and this time no key needs destroying,
because the v3 disclosure key stays available for historical records until
they are resealed. Cost: P-256 needs explicit point validation on every
caller-supplied public key, which X25519 does not — and "arbitrary
attacker-controlled public-key agreement is refused" is already on the
required attack list, so that check has to be written either way.

**B. Keep X25519, accept PKCS#11-only custody.** Entrust nShield, possibly
Luna with FIPS mode off. No cloud KMS, no AWS/GCP/Azure deployment path.

**C. Curve-agile envelope, both implemented, migrate lazily.** New records
sealed to P-256; v3 records opened through a software custodian until
resealed. Avoids a flag day, doubles the surface under test.

**Recommendation: A, with the curve-agility of C built in from the start.**
Not because P-256 is a better curve — X25519 is the better curve — but
because the property being bought here is *the key not existing in the
service's memory*, and that property is only purchasable at P-256. Trading
misuse-resistance in the primitive for non-exportability in the key is the
right trade when the threat is a compromised host, and the misuse-resistance
is recoverable with an explicit validation step that the attack suite
requires regardless.

---

## Required attack suite

From review, with how each is addressed:

| Attack | Addressed by |
|---|---|
| Stolen database + application compromise cannot decrypt | unchanged from stage 3; re-run against v4 envelopes |
| Arbitrary attacker-controlled public-key agreement refused | custodian validates the peer point (on-curve, correct order, not identity) and only agrees to points bound into a record's envelope |
| Edited scope refused | custodian re-derives scope from the approval digest; does not accept the caller's |
| Replay refused | approval nonce + presence nonce, spent by the custodian as well, not only by the service |
| Old/rolled-back policy or registry state detected | registry versioning already built (finding 7); extend to the custodian's own policy state |
| Concurrent spend cannot duplicate disclosure | already enforced by one transaction + uniqueness constraint; must remain true across the custodian boundary |
| HSM/KMS failure fails closed | the existing `disclosure_unavailable` posture, extended: no fallback path that opens records without the custodian |
| Key rotation leaves authorized historical records decryptable | `recipient_key_id` is already a version handle; custodian holds N versions, none exportable |

## Open question for the deployment

Which custody backend is being targeted — AWS KMS, GCP KMS, Azure Managed
HSM, or an on-premise PKCS#11 device — decides whether the envelope moves to
P-256 and whether the v3 → v4 reseal happens now or later. Everything else in
this document is independent of that choice.
