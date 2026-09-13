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

---

## What was built

`jk-seal-v4`, with the suite named in the record rather than assumed:

```
seal_version      jk-seal-v4
seal_kem          P256-ECDH-HKDF-SHA256
recipient_key_id  <suite-bound key id>
ephemeral_pub     <validated uncompressed SEC1 P-256 point>
```

`kem` is bound into the AEAD associated data alongside the KDF and AEAD
names, so a record cannot be reinterpreted under a weaker primitive than the
one it was sealed with, and a stripped `seal_kem` is a refusal rather than a
default. `justikey/kem.py` holds the suites; adding the next primitive is an
entry there, not `jk-seal-v5`.

`justikey/custodian.py` offers exactly one operation:

```python
open(envelope, identity, statement, signature, requester,
     proof_statement, proof, registry_versions, blind_index_of)
```

There is no `derive`, no `agree`, no `unwrap` — a test asserts those
attributes do not exist, because the oracle restated as an API is the thing
being avoided. `blind_index_of` is required: a custodian that accepted the
caller's word for which records are in scope would have re-created the
oracle with extra steps.

Backends: `LocalAgreement` (software, development, and the reference the
hardware path is checked against — `meets_stage_5` is `False` and says so)
and `KmsAgreement` (AWS KMS `DeriveSharedSecret`, `ECC_NIST_P256`,
`KeyUsage=KEY_AGREEMENT`). With `Recipient` set, KMS returns
`CiphertextForRecipient` and an empty `SharedSecret`; a response that carries
*both* is refused, because that is not the attested path and the plaintext
secret just reached the parent. `meets_stage_5` is true only for the attested
configuration.

### Measured

Same adversary as every other stage: full control of the disclosure service
— its database, its KMS credentials, the code it runs. 25 sealed records.

```
attack 1: call KMS directly, once per row
  rows walked 25    secrets obtained 0    denied by KMS policy 25

attack 2: ask the custodian for each row, with no authorization
  rows attempted 25    opened 0    refused 25

attack 3: ONE genuine approval for CAR007, replayed across every row
  rows attempted 25    opened 1    refused 24
  plates revealed: ['CAR007']
```

The third is the one that matters. A live, genuine, correctly signed approval
naming one vehicle, driven across the entire archive by a fully compromised
service, yields that one vehicle.

### The custodian as its own process

`scripts/custodian_server.py` runs it as its own process and principal, with
its own ledger, its own registries, its own index key, and the state it owns
rather than trusts. Two routes and no third:

```
POST /index   a scope token, so the custodian can re-derive scope itself
POST /open    one record, after verifying the whole disclosure context
```

A test asserts that `/derive`, `/agree`, `/unwrap`, `/key`, `/privatekey` and
`/decrypt` all return 404 — the oracle restated as a route is the thing being
avoided.

**`/open` takes one record, not a list.** Batching would let a caller hand
over the whole table and have the custodian sort out which ones it likes,
which is convenient and is exactly the oracle's shape. The disclosure service
still narrows candidates locally; the custodian re-deriving scope per record
is what makes that narrowing untrusted rather than load-bearing.

**The custodian owns the spending.** When `JUSTIKEY_CUSTODIAN_URL` is set the
disclosure service stops claiming approval counts and presence nonces — it
still runs every check it ran before, because a second opinion is the point,
but two components both *spending* would halve every cap and leave the two
ledgers disagreeing about what happened. Tested: after one disclosure the
application's `authorization_usage` table is empty and the custodian's shows
a count of 1.

**The application holds no private key.** With a custodian configured,
`service_for` installs a `_PublicOnlyOpener` in the opener's place. It raises
rather than opening, so a code path that ever reaches it fails loudly instead
of quietly working.

**Registry versions must agree across the boundary.** The caller states which
registry versions it used; a mismatch refuses before anything else is
checked. Neither side opens a record while they disagree about whose keys
count.

Measured through the real HTTP transport, ten sealed records, one genuine
approval naming one of them, replayed against every row:

```
opened: ['SECRET99']
custodian ledger: 1 open_granted, 9 open_refused, chain verifies
```

The custodian's ledger records every refusal and **contains no plate** — a
test asserts none of the ten plate strings appears anywhere in it, because a
ledger that recorded them would rebuild the archive the custodian exists to
protect.

### Running it inside an enclave

On AWS Nitro the custodian runs in the enclave and the parent proxies to it
over vsock; nothing in the server assumes which transport it is behind.
`--attestation-file` is the enclave's attestation document, sent to KMS as
`Recipient`.

`GET /publickey` reports `"attested": true|false`, and an unattested
custodian prints a startup notice saying plainly that the configuration does
not meet the stage 5 objective. That seemed better than letting a
development configuration look like a production one.

One piece is deliberately a refusal rather than a stub: decrypting
`CiphertextForRecipient` requires the enclave's private key and the NSM
device, so outside an enclave `--attestation-file` raises an error naming
what is missing rather than silently degrading to an unattested call.

### Where the evidence stops

Attack 1 is the only control that does not depend on JustiKey's code being
correct — and it is enforced by AWS, not here. `tests/fake_kms.py` implements
the documented policy semantics (attested calls get an empty `SharedSecret`;
`kms:RecipientAttestation:ImageSha384` refuses a mismatched, revoked, or
absent attestation) so the JustiKey side is testable. **These tests prove
JustiKey behaves correctly given that behaviour. They are not evidence about
AWS.** Confirming the real service behaves as documented is a deployment
step, not a unit test.

What remains: the enclave-side decryption of `CiphertextForRecipient` (it
needs the NSM device, so it is a named refusal outside an enclave rather than
a stub), a vsock transport to replace TCP in production, and the v3 → v4
reseal, which is available through the existing ceremony but has not been run
against a production store.

## Decided

AWS KMS, P-256, `jk-seal-v4`, with Nitro attestation as the production
boundary. The attestation path is what turns "the key is in a KMS" into a
control: without it, a compromised parent holding the same IAM credentials
makes the same call the custodian does.
