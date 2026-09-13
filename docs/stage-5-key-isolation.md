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

### The recipient path, corrected

An earlier draft of this document said the NSM decrypts
`CiphertextForRecipient`. It does not, and the correction makes the design
cleaner rather than harder. The NSM's job is to **produce and sign an
attestation document**. The decryption key is an ordinary RSA keypair the
enclave generates for itself:

1. the enclave generates an RSA-2048 keypair in its own memory
2. it asks the NSM for an attestation document carrying that public key
3. KMS is called with `Recipient` = that document
4. KMS returns the secret encrypted to that public key, `SharedSecret` empty
5. the enclave decrypts with the private key, which never left its memory

So everything except step 2 is ordinary cryptography that runs and is tested
anywhere. Only the attestation document needs the device.

**`CiphertextForRecipient` is not a bare RSA-OAEP blob.** It is a CMS
`EnvelopedData` (RFC 5652): RSA-OAEP-SHA-256 wraps a content-encryption key,
and the content itself is AES-256-CBC with the IV in the algorithm
parameters. An implementation that RSA-decrypts the blob directly works
against a convenient stand-in and fails against AWS, so `justikey/enclave.py`
parses the real structure and `tests/fake_kms.py` produces genuine DER — the
parser is exercised against the format rather than against a shortcut.

The parser is strict where strictness is cheap: indefinite-length BER is
refused, exactly one recipient is required, and the key-encryption and
content-encryption algorithms are *checked* rather than read, because a
parser that accepts whatever algorithm the blob names will accept one the
sender chose.

**A fresh recipient key per operation.** Each KMS agreement generates its
own RSA keypair, so a captured `CiphertextForRecipient` is useless outside
the single operation that asked for it — there is no longer-lived key to
replay it against — and the lifetime story is one sentence rather than a
rotation policy. Tested: a response produced for one operation, fed to the
next, is refused with *"not encrypted to this operation's recipient key"*.

Only step 2 is unavailable outside an enclave, and it is a **named refusal**
rather than a stub: a fabricated attestation would be refused by KMS anyway,
and a stand-in that looked real would let a development configuration pass
for a production one.

### The transport, and what it is not

```
CustodianClient
    ├── HttpTransport     development and process tests
    └── VsockTransport    Nitro production
```

On Nitro, vsock is the only channel between an enclave and its parent, the
parent is always CID 3, and the enclave has no external network and no
persistent storage. That is genuine isolation.

**It is not authorization, and the distinction is worth stating twice.** Once
the parent is inside the threat model — it runs the disclosure service — the
parent holds whatever transport credential the parent holds. A shared secret
proves the caller is the parent; the parent is the adversary. A CID proves
which side of a socket someone is on; being on that side is not permission to
read a plate. So the authorization remains entirely and only: approver
signature, requester presence, scope, registry versions, nonce and cap state,
record identity — verified by the custodian against its own copies.

What the transport layer does own: an explicit length prefix with a ceiling
checked **before** allocation, a read deadline, bounded concurrency (a
refusal, not a queue — an enclave has a fixed memory allocation), one request
per connection, and a strict schema in which unknown fields are refused
rather than ignored, because a field this version ignores is one a later
version might read.

Both transports call **one** dispatch function. Two dispatch tables would be
two lists of what the custodian accepts, and the day they disagree is the day
one transport offers something the other refuses.

### A production invariant, enforced

**An attested custodian refuses to start a TCP listener** and exits 4. A
Nitro enclave's only channel is AF_VSOCK, so a TCP listener in an attested
configuration means either this is not really an enclave or something has
been arranged to reach it that should not exist — refusing is cheaper than
finding out which. Development may use HTTP; it simply may not claim to be
attested, and an unattested custodian prints a startup notice saying so.

Tested as a real subprocess, because an invariant asserted by reading the
source is an invariant that survives the code being deleted.

### The vsock attacks

| Attack | Result |
|---|---|
| parent sends `derive` (or `agree`, `unwrap`, `decrypt`, `privatekey`) | refused: unknown operation |
| parent sends `open` carrying multiple records | refused: `open` takes exactly one record |
| parent replays a completed `open` frame verbatim | refused: proof of presence already used |
| parent sends oversized, truncated, non-JSON, wrong-magic or unknown-field frames | refused before allocation; the server does not hang |
| parent feeds a stale `CiphertextForRecipient` to a later `open` | refused: not encrypted to this operation's recipient key |

And the archive attack is re-run over the framed path, giving the same
answer as over HTTP — which is the point: swapping TCP for vsock must not
move record selection outside the custodian.

**What this kernel could not test.** It has `AF_VSOCK` and permits binding a
listener (exercised), but has no `vsock_loopback`, so a local connect times
out. The framing is therefore driven over a socketpair — the same code on
the same sockets, minus the kernel's vsock routing. Confirming that routing
needs a real enclave.

### Where the evidence stops

Attack 1 is the only control that does not depend on JustiKey's code being
correct — and it is enforced by AWS, not here. `tests/fake_kms.py` implements
the documented policy semantics (attested calls get an empty `SharedSecret`;
`kms:RecipientAttestation:ImageSha384` refuses a mismatched, revoked, or
absent attestation) so the JustiKey side is testable. **These tests prove
JustiKey behaves correctly given that behaviour. They are not evidence about
AWS.** Confirming the real service behaves as documented is a deployment
step, not a unit test.

What remains is no longer code-shaped. The NSM attestation request needs the
device; the vsock round trip needs a kernel with vsock routing; the KMS
behaviour needs KMS. Each is a named refusal or a stated gap rather than a
stub, and the next meaningful evidence is a small real Nitro + KMS
deployment rather than another stand-in. The v3 → v4 reseal is available
through the existing ceremony but has not been run against a production
store.

## Migrating an existing store

`scripts/seal_store.py reseal-v4` re-wraps every record from X25519 to the
custodian's suite. It destroys nothing: the old key stays valid for anything
not yet resealed, so the store is openable throughout and an interruption
costs a retry. Batched and resumable; a second run is a no-op.

Rehearsed against a 5,013-record store built by the pre-v4 code at `e975ddd`,
with real users, sources, a signed sensor credential, and three live case
files:

```
before   CASE-2026-000 -> 3 records   CASE-2026-001 -> 3   CASE-2026-002 -> 4
reseal   5,013 records in 3.0s
after    CASE-2026-000 -> 3 records   CASE-2026-001 -> 3   CASE-2026-002 -> 4
         TOTP readable, sensor secret intact, new ingest v4,
         old X25519 key refused, audit chain verifies
```

Two bugs surfaced, both fixed and both now tested. The ceremony failed with a
raw SQLite error on a genuine v3 store, which has no `seal_kem` column
because there was only one suite — it now brings the schema forward itself.
And `JUSTIKEY_DISCLOSURE_KEM` was honoured when *reading* a store's suite but
ignored when *creating* its key, so a store configured as X25519 received a
P-256 key and then read itself as X25519. Configuration now chooses only for
a fresh store; what the database recorded always wins, because an
environment variable must not be able to reinterpret records already sealed.

## Deploying it

[nitro-deployment-runbook.md](nitro-deployment-runbook.md) is the executable
version of this design: parent instance, EIF build and PCR measurements, the
KMS key policy pinned to the measurement, vsock-proxy, credential placement,
and twelve acceptance gates.

Three of those gates — modified EIF denied, parent direct call denied,
`SharedSecret` empty on an attested response — are assertions about AWS, and
no local test can answer them. They are the difference between a custodian
and an expensive proxy, which is why the runbook says to stop if either of
the last two does not behave as documented.

## Decided

AWS KMS, P-256, `jk-seal-v4`, with Nitro attestation as the production
boundary. The attestation path is what turns "the key is in a KMS" into a
control: without it, a compromised parent holding the same IAM credentials
makes the same call the custodian does.
