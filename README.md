# JustiKey — Privacy-First ALPR Access Control Platform

JustiKey is a laboratory prototype for a privacy-first license-plate
recognition (LPR/ALPR) access-control platform built around one principle:

> **Collecting a sensor event should not automatically grant someone the
> authority to identify, search, or use that event.**

License-plate observations may be ingested continuously, but historical,
identifiable records stay locked away until a documented legal authorization
is created, **independently approved by a second authenticated person**,
used within a narrow plate-and-time scope, and permanently recorded in a
tamper-evident audit ledger.

This repository is a runnable prototype of that architecture. It runs on the
Python standard library with a single dependency — `cryptography`, for
AES-256-GCM encryption at rest — and no external services, so the whole
workflow can be exercised on a laptop.

## Quickstart

Requires Python 3.9+ and `pip install -r requirements.txt`.

```bash
# 1. Start the server (creates demo accounts + a sensor API key on first run)
python3 scripts/run_server.py --port 8080

# 2. In another terminal, feed it synthetic ALPR observations
python3 scripts/simulator.py --api-key <printed-by-run_server> --count 30

# 3. Open http://127.0.0.1:8080/login in a browser
```

Optionally run an independent audit witness alongside it, so deletion of the
audit tail becomes provable rather than merely suspected:

```bash
python3 scripts/witness_server.py --port 8090 --store witness.jsonl
JUSTIKEY_WITNESS_URL=http://127.0.0.1:8090 python3 scripts/run_server.py --port 8080
```

The first `run_server.py` run prints demo credentials to the console:

| role       | username     | password          | purpose                              |
|------------|--------------|-------------------|---------------------------------------|
| requester  | `officer1`     | `Requester#2026!`  | creates authorization requests, searches once approved |
| approver   | `supervisor1`  | `Approver#2026!`   | independently reviews and approves/denies requests |
| auditor    | `auditor1`     | `Auditor#2026!`    | read-only oversight of requests and the audit ledger |

Every account also has a TOTP secret. Since this is a local lab prototype
with no external authenticator app in the loop, generate the current code
with:

```bash
python3 scripts/show_totp.py officer1
```

Use `--reset` to wipe the database and start over: `python3 scripts/run_server.py --reset`.

## Demonstration workflow

1. `officer1` signs in (password, then TOTP) and creates an authorization
   naming a case number, legal authority (warrant reference), investigative
   purpose, a single target plate, and a bounded time window. The request
   sits in `pending` state — nothing is disclosable yet.
2. `officer1` cannot approve their own request: the UI hides the control,
   and the server independently rejects it even if the request were forged.
3. `supervisor1` signs in separately, reviews the request, and approves it
   with their password and a fresh TOTP code. The password unlocks their
   signing key, so the approval is signed rather than merely recorded.
   Approval is valid for ~30 minutes.
4. `officer1` can now search — but only for the exact plate named in the
   authorization, and only within the authorized time window. Any other
   plate, a stale/expired authorization, or an authorization belonging to
   someone else is denied and logged.
5. `auditor1` signs in and can review every event in the hash-chained audit
   ledger, publish a checkpoint of the ledger head, and run an integrity
   check from the UI or the command line:

```bash
python3 scripts/verify_audit.py justikey.db
python3 scripts/verify_audit.py justikey.db --witness http://127.0.0.1:8090
```

`verify_audit.py` deliberately re-implements every check from scratch
against the raw stored files, rather than importing the server's own audit
module — an independent verifier, not a callback into the code that wrote
the ledger. It reports three layers: the hash chain, the local anchor log,
and an independent witness (see
[External anchoring](#external-anchoring-closing-the-tail-truncation-gap)).

## Architecture

```
justikey/
  config.py      settings (paths, lifetimes, cookie flags) via env vars
  db.py          SQLite schema and connection helper
  crypto_utils.py  PBKDF2 password hashing, RFC 6238 TOTP, session tokens
  audit.py       hash-chained audit ledger (append + verify)
  models.py      data access: users, sessions, events, authorizations
  anchor.py      signed checkpoints making tail truncation detectable
  adapters.py    vendor payload translation into one canonical observation
  crypto_store.py AES-256-GCM field encryption and keyed blind index
  approvals.py   approver signing keys and signed authorization statements
  sealing.py     per-record seal with a public key, open with the private one
  disclosure.py  the only path that opens a sealed record (local or remote)
  policy.py      disclosure policy engine — the only path to protected data
  templates.py   minimal HTML templating (all interpolation is escaped)
  webapp.py      http.server-based router, auth flow, CSRF, all routes
  seed.py        deterministic demo accounts + sensor API key

scripts/
  run_server.py     start the app (seeds demo data on first run)
  simulator.py      synthetic ALPR observation generator (no camera needed)
  show_totp.py      dev helper: current TOTP code for a demo account
  anchor_audit.py   publish a checkpoint of the ledger head on demand
  witness_server.py independent witness holding its own copy of checkpoints
  manage_sources.py register, rotate, suspend, and revoke sensor feeds
  edge_agent.py     device-side recognition with store-and-forward buffering
  encrypt_store.py  migrate a plaintext database to encryption at rest
  enforce_retention.py delete observations past their retention period
  seal_store.py     the v1 -> v3 migration ceremony, step by step
  manage_keys.py    enrol hardware authenticators; export the service registries
  disclosure_server.py the disclosure service, as its own process and principal
  custodian_server.py  the custodian: verifies the whole context, then agrees once
                       (--transport vsock inside a Nitro enclave)
  verify_audit.py   independent verifier: chain + anchors + witness

tests/
  test_totp.py        TOTP + password hashing correctness
  test_totp_replay.py single-use enforcement for TOTP codes
  test_audit.py       hash-chain integrity, including tamper detection
  test_policy.py      disclosure policy: ownership, approval, expiry, plate match
  test_timeutil.py    canonical timestamps; window filtering across vendor formats
  test_concurrency.py no audit entry lost under concurrent append; atomic approval
  test_anchor.py      truncation, rewrite, and forged-anchor detection
  test_verify_cli.py  the standalone verifier's own reimplementation of the checks
  test_sources.py     authenticated provenance, revocation isolation, migration
  test_adapters.py    vendor translation, timestamps, confidence, candidates
  test_edge_agent.py  buffering, once-only recognition, recognizer parsing
  test_encryption.py  plaintext absent from disk, AAD binding, key handling
  test_enforcement.py scope breadth, disclosure caps, lockout, retention
  test_signed_ingest.py request signing, replay refusal, need-to-know
  test_approval_signing.py post-approval tampering, forgery, receipts
  test_sealing.py     envelope binding, scoped disclosure, index-key withholding
```

## Storage formats: v1, v2, v3

How an observation is protected at rest has changed three times, and the
differences are not cosmetic — they are different answers to *who can read
this*. A database records which format it uses in `meta.encryption_mode`, and
`crypto_store.encryption_mode(conn)` reports it. **New databases are created
as v3.**

| Mode | Protection | Who can read a stored plate |
|---|---|---|
| `none` | plaintext columns | anyone with the file |
| `v1` | AES-256-GCM fields, one root key held by the application | the application, at will |
| `v2` | per-record sealing under a disclosure public key | only the disclosure key holder — in `local` mode, still this process |
| `v3` | v2 plus full envelope binding, with the index key moved out of the application | only the separate disclosure service |

The rest of this section describes v1, because a database created before the
split still uses it and the migration path has to be documented. For how v2
and v3 actually work, see [Per-record sealing](#per-record-sealing-the-application-cannot-read-what-it-collects)
and [Running the service separately](#running-the-service-separately-stage-3).

### Legacy v1 encryption architecture

Every other control in JustiKey governs *access*: who asked, who approved,
how narrow the scope was. None of them help if someone simply takes the
database file. A stolen backup, a decommissioned disk, or a copied volume
would yield the entire location history with no authorization, no approval,
and no audit entry -- defeating every control at once.

v1 answers exactly that threat and no other. Plate and location values, and
TOTP secrets, are stored as AES-256-GCM ciphertext
(`justikey/crypto_store.py`). Exact-plate search still works because each
observation also carries a **blind index**: a keyed HMAC of the normalized
plate. Lookups match on the index, so the query never handles plaintext;
values are decrypted only for rows the policy engine has already authorized.

Two keys, derived from one root by HKDF with distinct labels, so the index
key can never decrypt and the encryption key can never build lookup values:

```
root ─┬─ HKDF("justikey:field-encryption:v1") → AES-256-GCM key
      └─ HKDF("justikey:blind-index:v1")      → HMAC-SHA256 index key
```

Each ciphertext is bound by AAD to its capture time and camera, so someone
with write access to the database cannot move a plate ciphertext onto a
different time to fabricate a sighting -- the tag check fails. A wrong key is
detected at startup against a stored canary and refused, rather than silently
writing records that can never be read back.

**Why this is not enough, and what v3 changes.** Both keys come from one
root, and the application holds that root. So a compromised application can
decrypt every record, and — worse — can derive the index key and enumerate
the plate space offline: plates are low-entropy enough that a measured run
recovered three of them in 23.7 seconds. Under v3 the application holds
neither key. It seals against a public key it cannot invert, asks the
disclosure service for scope tokens over an authenticated, rate-limited,
logged channel, and `crypto_store.resolve_index_key()` refuses outright to
produce an index key in remote mode. See
[threat-model.md](docs/threat-model.md) finding 1.

### Key custody is the whole point

A key sitting beside the database protects against a stolen file and nothing
more. Supply it out of band so possession of the database alone is not
enough:

```bash
JUSTIKEY_DATA_KEY=$(openssl rand -hex 32) python3 scripts/run_server.py
```

The generated `*.data-key` file is a development fallback and says so on
stderr every time it is created.

### Migrating `none` → v1

A database created before encryption holds plaintext. `init_db` deliberately
will **not** switch it over on its own -- a half-encrypted store is worse
than either state, because callers cannot tell which rows are protected. The
migration is explicit, transactional, and audited:

```bash
python3 scripts/encrypt_store.py --db justikey.db            # dry run
python3 scripts/encrypt_store.py --db justikey.db --apply
```

Back up first, and be sure the key is one you will still have tomorrow.
Losing it means losing every protected record; that is what encryption means,
and it cuts both ways.

Migrating v1 → v3 is a different and heavier operation, because it ends with
destroying a key that currently opens everything. It is a ceremony, not a
command: see [Migrating v1 -> v3](#migrating-v1---v3-a-ceremony-not-a-command).

### Residual exposure under v1, stated plainly

Listed for the sake of anyone still running a v1 database. The first two
carry over to v3; the third and fourth are what the split removes.

- **The blind index is deterministic.** An attacker holding the database can
  tell that two rows concern the same (still unknown) vehicle and count how
  often it was seen. That is inherent to searchable encryption; removing it
  would mean giving up authorized lookup entirely. *(Carries over to v3.)*
- **camera_id and captured_at stay plaintext.** They are needed to operate
  the system and to bind the AAD. With the blind index they reveal movement
  patterns of an unidentified vehicle, not its identity. *(Carries over to
  v3.)*
- **A running server holds the key.** This protects data at rest, not against
  a live host compromise. *(Removed in v3: the application holds only a
  public key.)*
- **The index key is derivable from the data key**, so a compromised
  application can enumerate the plate space offline and silently. *(Removed
  in v3: the index key lives in the disclosure service and is never derived
  in the application.)*

## Approver-signed authorizations

Approval used to be a status column. Anyone able to write to the database
could flip it — or, more quietly, leave the approval alone and change what it
authorizes. Swapping `target_plate` on an already-approved row yields a
different vehicle's history under a real approval with a real approver's
name on it, and nothing notices.

Approvals are now signed (`justikey/approvals.py`). The approver holds an
Ed25519 key whose private half is wrapped under their password, so approval
requires password **and** TOTP, and the server can only sign while the
approver is actually present. The signed statement covers the case, legal
authority, purpose, target plate, window, requester, approver, and expiry.

Before any disclosure the policy engine rebuilds that statement from the
row's *current* values and verifies it. Live, against a direct database edit:

```
row now says: plate=ZZZ999 status=approved approved_by=2
  (a real approver, a real approval, pointed at a different vehicle)

DENIED: This authorization's approval signature does not match its
        current contents. It may have been altered after approval.
```

An approval also produces a portable receipt — statement, signature, and the
approver's public key — verifiable by a third party without access to the
database.

**What this does not yet do.** The data key still opens every record, so a
server compromised *at the moment an approver is signing* could misuse that
moment. Closing that needs the disclosure service in
[docs/capability-model.md](docs/capability-model.md), demonstrated end to end
by `scripts/capability_poc.py`. What signing buys today is that approvals
cannot be forged for periods when no approver was present, and cannot be
altered afterwards.

**Upgrading:** approvals predating signing are refused by default
(`JUSTIKEY_REQUIRE_SIGNED_APPROVALS=0` to bridge a migration; re-approve
outstanding authorizations). A wrong signature is refused either way.

## Per-record sealing: the application cannot read what it collects

Encryption at rest protects a database file that has left the building. It
does nothing against the application itself, which under v1 held one key that
opened every observation — so the policy engine was the only thing between a
compromised process and the whole archive.

Each observation is now sealed under its own record key, and that key is
wrapped to a **disclosure public key** (`justikey/sealing.py`). The write path
holds only the public half:

```
encryption mode : v2
plate column    : ''
sealed record   : LVY+Pam6an7uYs0kq5dY1tgVO8RkJr3U3cWH...
wrapped key     : cr4zaLrjPqNh+82BQtcAj5jNxTSVYGRwQ0X4...

search_events returned 1 row(s)
plate value visible to the application: ''
data key cannot open it: WrongKeyError
```

Opening goes through the disclosure service (`justikey/disclosure.py`), which
verifies the approver's signature and **re-derives scope from the signed
statement** rather than trusting the caller's selection — a caller that has
been compromised is precisely the one whose filtering cannot be believed.
Scope is checked against the blind index, so an out-of-scope record is never
opened in the act of deciding not to disclose it.

Handed *every* row in the database, the service still opens only the one the
approval covers.

### Running the service separately (stage 3)

```bash
python3 scripts/disclosure_server.py --port 8090 \
    --key-file service.key --index-key "$INDEX_KEY" \
    --client-secret "$CLIENT_SECRET" --approvers approvers.json \
    --ledger disclosure-audit.db --max-disclosures 25
```

The application then gets the public key and the client secret, and **neither
private key**:

```bash
JUSTIKEY_DISCLOSURE_URL=http://disclosure-host:8090 \
JUSTIKEY_DISCLOSURE_PUBLIC_KEY=<public key> \
JUSTIKEY_DISCLOSURE_CLIENT_SECRET=<secret> python3 scripts/run_server.py
```

With the web application fully compromised — database, environment,
arbitrary SQL, code execution:

| Attempt | Result |
|---|---|
| Read plate/location columns | empty; sealed |
| Decrypt with the application's data key | refused (`WrongKeyError`) |
| Find a disclosure private key on the host | none present |
| Derive the index key and enumerate offline | refused |
| Forge an approval with an attacker's key | refused: the service holds its own approver registry |
| Replay a captured authenticated request | refused: transport nonces are spent once |
| Reuse a genuine approval past its cap | refused: the service counts uses, not the caller |

The service keeps its own hash-chained ledger, and its writes are serialized
so concurrent disclosures cannot fork the chain. It deliberately does not log
the plate in a scope-token request: doing so would rebuild the archive it
exists to protect. The same database holds the state the service owns rather
than trusts: how many times each approval has been spent, and which transport
nonces have been seen.

In `local` mode (no `JUSTIKEY_DISCLOSURE_URL`) the private key and index key
live in the application process, so the split is structural rather than
enforced. That mode is for development.

**Availability becomes a safety property.** With the disclosure key absent,
lawful access stops — correctly — and stops legibly:

```
with the disclosure key present : Disclosed records (1)
with the disclosure key removed : The disclosure service is unavailable, so these
                                  records cannot be opened. Records stay sealed;
                                  no partial disclosure occurs.
key restored                    : Disclosed records (1)
```

### Migrating v1 -> v3: a ceremony, not a command

The last step of this migration destroys a key that currently opens every
record, so it is not one command. Each step is separate, checkable, and
recorded:

```bash
python3 scripts/seal_store.py plan --db justikey.db
python3 scripts/seal_store.py migrate --db justikey.db --approver supervisor1
python3 scripts/seal_store.py verify --db justikey.db
python3 scripts/seal_store.py rekey-credentials --db justikey.db
python3 scripts/seal_store.py destroy-legacy-key --db justikey.db \
    --confirm "destroy the legacy key for justikey.db"
```

`migrate` reseals every observation under its own key, rebuilds every blind
index (the index key changes with the format), and then opens a sample back
out **through the real disclosure path** — search, scope check, service,
envelope — comparing each one against what went in. A migration that wrote an
index the search path cannot reproduce would leave a store that is intact,
verified by every other measure, and permanently unfindable; this is the
check that catches it. It runs while the legacy key is still there, so a
failure is recoverable.

Each step appends to a manifest (`<db>.ceremony.json`): counts before and
after, a digest over every sealed record, the disclosure key id, what the
sample check proved, and key fingerprints. The manifest is a convenience, not
the evidence — its digest goes into the hash-chained audit ledger at every
step, so an altered manifest is detectable against a chain that is itself
externally anchored.

**Two things building this turned up.** First, the v1 root key does not only
protect observations: users' TOTP secrets and sensors' HMAC signing secrets
hang off it too. Sealing the observations moves only the first out of its
reach, so destroying the key at that point would lock every user out of their
second factor and break every signed feed. Hence `rekey-credentials`, which
moves that material onto a fresh key, and hence `destroy-legacy-key`
refusing until it has been run.

Second, the ceremony can only *finish* against a separated disclosure
service. In local mode the application derives the blind-index key from the
same root as the data key, so rotating that root silently rotates the index
key and orphans every stored index — and repairing it would mean resealing
every record, which requires opening them, which under v3 the application
cannot do. `rekey-credentials` checks for that coupling and refuses rather
than producing a store that verifies clean and can never be searched again.
Standing up the service is not an optional hardening step here; it is what
makes the last two steps possible.

## Proof of presence: an approval is not a bearer token

Through stage 3 the disclosure service checks that an approval is genuine,
unexpired, in scope and within its count. Every one of those is equally true
of a request a **compromised application** sends on its own, using an
approval lifted from its own database and the string `requester="officer1"`.
The scope bounds held. Nothing proved the officer was there.

So the requester now signs each disclosure at the moment they ask for it —
not the authorization, which was the approver's signature made earlier, but
*this request*:

```
{"v", "approval_nonce", "statement_digest", "requester", "requester_key_id",
 "request_nonce", "issued_at", "expires_at"}
```

Every field carries weight. `approval_nonce` and `statement_digest` bind the
proof to one approval and to the exact scope the approver signed, so it
cannot be moved onto another approval or onto one whose row was edited after
signing. `request_nonce` is spent once by the service, so one confirmation
buys one disclosure. The lifetime is capped by the verifier rather than
claimed by the caller — otherwise a compromised application would simply
issue itself one good for a year.

Measured against the attack it exists to stop:

```
no requester key enrolled : approval replayed with nobody present -> OPENED
key enrolled              : refused - this disclosure needs proof that the
                            requester is present; an approval on its own is
                            not sufficient
requester actually present: OPENED (custody: software)
that proof replayed       : refused - already been used
that proof on another approval: refused - made for a different approval
```

### Hardware custody

A password-wrapped key has a fixed ceiling: it passes through this process,
so an attacker already inside gets it at that moment — and keeps it. A
WebAuthn authenticator never exports its private key, so the attacker gets
only the operations a present human physically confirmed, and none
afterwards.

Both are the same proof envelope, so there is one verification path rather
than two sets of bugs:

```
{"alg": "ed25519",  "sig": "<hex>"}                         software
{"alg": "webauthn", "authenticator_data": ..., ...}         hardware
```

The challenge the authenticator signs is the **digest of the exact statement
being authorized**, so an assertion is good for that statement and no other.
User presence is required unconditionally and has no off switch; user
verification (PIN or biometric — the enrolled operator, not whoever picked
the token up) is required per role via `JUSTIKEY_WEBAUTHN_REQUIRE_UV`,
defaulting to every role.
Verification (`justikey/webauthn.py`) checks the signature, the ceremony
type, the challenge, the origin, the RP id, the user-present and
user-verified flags, and the signature counter — each a separate attack, each
a separate refusal. COSE keys are decoded in-module for ES256 and Ed25519
rather than through a CBOR dependency that would parse attacker-supplied
input.

Enrolling hardware **raises** the bar rather than adding to it:

```
attacker knows the password and forges a software proof:
  refused - this principal is enrolled with a hardware authenticator,
            so a software signature is not accepted
```

```bash
python3 scripts/manage_keys.py list --db justikey.db
python3 scripts/manage_keys.py enrol --db justikey.db --user officer1 \
    --credential-id <base64url> --public-key <base64url COSE> --label "YubiKey 5"
python3 scripts/manage_keys.py export --db justikey.db \
    --approvers approvers.json --requesters requesters.json
```

The service reads those registries on its own host and never asks the
application, which is what stops a compromised application choosing whose
keys count:

```bash
python3 scripts/disclosure_server.py --port 8090 ... \
    --approvers approvers.json --requesters requesters.json \
    --presence-mode required
```

`--presence-mode enrolled` (the default) requires a proof from every
requester who has a key, so a deployment can enrol people gradually;
`required` refuses any disclosure without one.

**What an assertion proves, exactly.** That the enrolled authenticator
participated, that a user was present at it, and — where UV is required —
that the operator authenticated to the authenticator. It does **not** prove
the person understood the transaction: a commodity security key has no
display, so what the human reads is a browser prompt rendered by software
that may itself be the compromised component. Only a trusted-display
authenticator would close that. The scope binding is what limits the damage:
a confirmation obtained under false pretences is still worth one disclosure,
inside a scope an approver independently signed.

**Registry integrity.** The registries are versioned, and the service commits
each version and digest to its own ledger. A registry whose contents changed
without the version moving, or whose version went backwards, refuses to start
the service — the two shapes a swapped or rolled-back registry takes. This is
detection, not prevention: an attacker who owns the service host owns its
ledger too. See [threat-model.md](docs/threat-model.md) finding 7.

**Not built:** the browser pages that run the WebAuthn registration and
assertion ceremonies. Verification and enrolment are complete and tested
against a synthetic authenticator (`tests/authenticator.py`) that produces
byte-exact assertions; what is missing is the front door to them. The web
interface today collects the requester's password and signs with their
software key. See [threat-model.md](docs/threat-model.md) finding 5 for
exactly how far each custody gets you.

## Key isolation: the custodian

A non-exportable key in an HSM stops the key being stolen and does nothing
about the second half of the problem. A compromised disclosure service holds
every row's `ephemeral_pub` and credentials to call the KMS; one call per
record decrypts the archive while the key never leaves the hardware. **Raw
ECDH is the unrestricted oracle.**

    KMS protects the key.  The custodian protects the operation.

So `scripts/custodian_server.py` runs as its own process and principal, and
offers two routes and no third:

```
POST /index   a scope token, so the custodian re-derives scope itself
POST /open    ONE record, after verifying the whole disclosure context
```

There is no `/derive`, no `/agree`, no `/unwrap` — a test asserts those
return 404. `/open` takes one record rather than a list, because batching
would let a caller hand over the table and have the custodian sort out which
ones it likes, which is the oracle's shape with extra steps.

Before agreeing to anything it independently re-checks registry versions,
envelope well-formedness, suite, recipient key, the approver's signature,
scope re-derived from **its own** index key, the requester's proof of
presence, freshness, single use, and remaining capacity — then spends the
approval count and the presence nonce in one transaction.

```bash
python3 scripts/custodian_server.py --port 8091 \
    --client-secret "$CUSTODIAN_SECRET" --index-key "$INDEX_KEY" \
    --approvers approvers.json --requesters requesters.json \
    --ledger custodian-audit.db \
    --kms-key-arn arn:aws:kms:...:key/... --attestation-file /run/attestation.bin
```

The application then holds **no private key and no index key**:

```bash
JUSTIKEY_CUSTODIAN_URL=http://custodian-host:8091 \
JUSTIKEY_CUSTODIAN_CLIENT_SECRET=<secret> \
JUSTIKEY_DISCLOSURE_PUBLIC_KEY=<public key> python3 scripts/run_server.py
```

`service_for` installs an opener that *cannot open* — it raises rather than
working — so a code path that ever reaches it fails loudly. And the custodian
owns the spending: the disclosure service still runs every check it ran
before, because a second opinion is the point, but two components both
spending would halve every cap and leave the ledgers disagreeing.

Measured through the real transport, ten sealed records, one genuine approval
naming one of them, replayed against every row:

```
opened: ['SECRET99']
custodian ledger: 1 open_granted, 9 open_refused, chain verifies
plate anywhere in that ledger: no
```

**On Nitro** the custodian runs inside the enclave and the parent proxies over
vsock; `--attestation-file` goes to KMS as `Recipient`, so the secret is
encrypted to the enclave and the parent never sees it, and the key policy can
require the enclave measurement. `GET /publickey` reports `"attested"`, and an
unattested custodian prints a startup notice saying plainly that the
configuration does not meet the objective — a development setup should not be
able to pass for a production one.

### Transport: vsock in production

```
CustodianClient
    ├── HttpTransport     development and process tests
    └── VsockTransport    Nitro production
```

vsock is the only channel between an enclave and its parent, and the enclave
has no external network and no persistent storage. That is real isolation —
and **not** authorization: once the parent is in the threat model it holds
whatever transport credential the parent holds, and a CID only says which
side of a socket someone is on. Authorization stays entirely with the
approver signature, the presence proof, scope, registry versions, nonce and
cap state, and record identity.

The transport owns framing: a length prefix with a ceiling checked *before*
allocation, read deadlines, bounded concurrency (a refusal, not a queue), one
request per connection, and unknown fields refused rather than ignored. Both
transports call one dispatch function, so they cannot drift in what they
accept.

**An attested custodian refuses to start a TCP listener** and exits 4 —
tested as a real subprocess. Development may use HTTP; it just may not claim
to be attested.

| vsock attack | Result |
|---|---|
| `derive` / `agree` / `unwrap` / `decrypt` | refused: unknown operation |
| `open` with multiple records | refused: exactly one record |
| completed `open` frame replayed verbatim | refused: proof already used |
| oversized / truncated / malformed frames | refused before allocation; no hang |
| stale `CiphertextForRecipient` reused | refused: not this operation's key |

The archive attack re-run over the framed path gives the same answer as over
HTTP — swapping transport must not move record selection out of the
custodian.

### The recipient path

The NSM signs the attestation document; it does **not** decrypt anything. The
enclave generates an RSA-2048 keypair per KMS operation, the NSM attests to
its public key, KMS encrypts the secret to it and returns an empty
`SharedSecret`, and the enclave decrypts with a private key that never left
its memory. `CiphertextForRecipient` is a CMS `EnvelopedData` (RFC 5652) —
RSA-OAEP-SHA-256 over a content key, AES-256-CBC content — and the stand-in
produces genuine DER so the parser is tested against the real format.

**Not built:** the NSM attestation request needs the device; the vsock round
trip needs a kernel with vsock routing (this one binds listeners but has no
`vsock_loopback`); the KMS behaviour is exercised against a stand-in
implementing the documented policy semantics, not against AWS. Each is a
named refusal or a stated gap rather than a stub. See
[stage-5-key-isolation.md](docs/stage-5-key-isolation.md).

## Limits enforced in software, not policy

The stated goal is to turn privacy requirements into enforceable
architecture. These were previously human expectations only:

| Control | Setting | Default |
|---|---|---|
| Maximum authorization time window | `JUSTIKEY_MAX_WINDOW_DAYS` | 90 days |
| Disclosures per approval | `JUSTIKEY_MAX_DISCLOSURES` / `--max-disclosures` | 25 |
| Proof-of-presence mode | `JUSTIKEY_PRESENCE_MODE` / `--presence-mode` | enrolled |
| Proof-of-presence lifetime | `JUSTIKEY_PRESENCE_TTL` | 120s |
| Roles needing hardware user verification | `JUSTIKEY_WEBAUTHN_REQUIRE_UV` | all |
| Failed sign-ins before lockout | `JUSTIKEY_MAX_FAILED_LOGINS` | 5 |
| Lockout duration | `JUSTIKEY_LOCKOUT_SECONDS` | 900 |
| Observation retention | `JUSTIKEY_RETENTION_DAYS` | 365 days |

**Scope breadth.** A request spanning years is refused before anyone can
approve it, and the limit is re-checked at disclosure time -- a check applied
only at creation could be bypassed by any path that edits an authorization
afterwards.

**Disclosure cap.** One approval no longer authorizes unlimited re-querying
inside its window — and the count that enforces that is kept by the
*disclosure service*, not by the application. This matters because the
application is the component assumed compromised: it holds every approval
row, so it can replay a genuine signed approval straight at `/disclose` and
never run its own check. The service claims a use from
`disclosure.UsageStore` — keyed by the approval's nonce, inside a
`BEGIN IMMEDIATE` transaction, in its own database — before it opens
anything, so attempt 26 is refused whatever the caller says about the first
25, restarts do not reset the count, and concurrent requests cannot both slip
past the last slot. The application keeps its own count too, but only so the
honest path can refuse early with a specific message.

A signed request to the service is also single-use: `X-JustiKey-Nonce` is
spent once, so a captured authenticated request cannot be resent inside the
clock-skew window. See [threat-model.md](docs/threat-model.md) finding 5 for
what remains — within a live approval's scope, window and remaining count, a
compromised application can still act in a requester's name.

**Oversight is itself audited.** Reading the audit log and running an
integrity check are recorded. The ledger names every plate ever
investigated, so the one role able to see everything must not be the one role
nobody can review.

**Brute force.** PBKDF2's cost bounds an attacker's guess rate but never
stops it; accounts now lock after repeated failures, and the lockout is
audited.

**Retention.** Indefinite retention of location history is itself the harm
this system exists to limit, and deletion is the only control that gets
stronger with time -- a record that no longer exists cannot be disclosed by a
future compromise or a future policy change. Purges are audited, and audit
entries outlive the data they describe.

```bash
python3 scripts/enforce_retention.py --db justikey.db            # dry run
python3 scripts/enforce_retention.py --db justikey.db --apply    # from cron
```

## Integrating other LPR systems

JustiKey's privacy architecture is indifferent to who made the camera, which
only works if every upstream format is reduced to one canonical observation
at the trust boundary. Integration therefore has two halves: **who is
sending** (identity) and **what they sent** (translation).

### Sources: authenticated identity, independent revocation

Every camera, edge device, or upstream ALPR system is a registered *source*
with its own credential:

```bash
python3 scripts/manage_sources.py register gate-north "North gate camera" \
    --adapter justikey --operator "in-house"
python3 scripts/manage_sources.py list
python3 scripts/manage_sources.py rotate gate-north      # new key, retire old
python3 scripts/manage_sources.py suspend gate-north     # pause a feed
python3 scripts/manage_sources.py revoke gate-north      # cut one vendor off
```

Two properties matter and neither is cosmetic:

**Revocation is per-source.** Cutting off one vendor leaves every other feed
running. A single shared ingest key cannot do this — revoking it stops
everything, so in practice nobody revokes it.

**Provenance is proven, not claimed.** The source an observation is
attributed to comes from the credential it authenticated with. A payload may
still carry the vendor's own feed name; it is stored as `source_id` (a claim,
kept for troubleshooting) and never becomes identity. The authenticated
source is `source_ref`, and it is what audit attribution and provenance use.
Ingest audit entries read `source:gate-north` because that source proved it,
not because the payload said so.

Credentials are separate rows from source identity, so a key can be rotated
or one of several revoked without disturbing the feed's history.

### Adapters: one observation shape

Each source declares the payload format it speaks, and `justikey/adapters.py`
translates it. Three ship today:

| adapter | shape |
|---|---|
| `justikey` | JustiKey's native observation |
| `flat_epoch_v1` | flat fields, epoch timestamps, 0–100 score |
| `nested_results_v1` | recognizer output with a ranked `results` array |

Adapters normalize the things that silently corrupt a scoped search:
timestamps become one fixed-width UTC form regardless of epoch-millis, `Z`
suffix, or offset; confidence becomes 0.0–1.0 whether the vendor sent a
fraction or a percentage. For `nested_results_v1`, only the winning candidate
is stored — keeping rejected guesses about a vehicle would widen the
protected record for no investigative benefit.

Sending the wrong format for a source's adapter is rejected with a 400 rather
than silently mangled.

**These are reference patterns, not certified vendor integrations.** The two
generic adapters model the payload shapes that dominate in practice. A real
vendor adapter needs that vendor's specification and captured sample
payloads, and should ship with fixtures of those samples in the test suite.
Add one with `@adapter("name")` and set the source's `adapter` column.

### Batch ingest and intermittent links

`/ingest` accepts either a single observation or
`{"observations": [...]}`. Each item is translated independently: valid ones
are stored, invalid ones are reported per-index and audited, so one
malformed read does not discard a whole batch. Batching is what lets an edge
device flush a backlog after an outage.

### The federation hazard — read before building outbound query

Several commercial ALPR networks expose *search* APIs, and "let investigators
query them from JustiKey too" is the obvious next feature. Built naively it
would destroy the product.

Every control here — the warrant record, the second approver, the plate and
time scope, the audit entry — governs the local event store. An outbound
query to a third-party network that skipped those checks would let anyone
with a JustiKey login obtain exactly the history JustiKey exists to protect,
while the audit ledger recorded nothing. JustiKey would become a laundering
layer that makes unaccountable search look accountable.

If federated query is built, it must be strictly harder than local search,
never easier:

- An outbound query requires an approved, unexpired authorization, checked by
  the same policy engine, before any request leaves the building.
- The remote query is constrained to the authorized plate and time window;
  the authorization is the only thing that can widen it.
- The request *and* its response are audited — including a query that
  returned nothing, since a null result still reveals that someone asked.
- Results are held under the same scope and expiry as local records, not
  cached into a parallel store that outlives the authorization.
- Each federated network is a peer with its own credential and its own
  revocation, exactly as inbound sources are.

None of this is implemented. It is written down because the safe design and
the naive one look similar at the API layer and diverge completely in what
they permit.

## Building our own cameras

The edge agent (`scripts/edge_agent.py`) is the device-side half, and it runs
today:

```bash
python3 scripts/edge_agent.py --api-key KEY --watch ./captures \
    --camera-id gate-north-01 --delete-after
```

It watches a directory the camera writes frames into, recognizes plates,
buffers observations to disk, and flushes them in batches when the link
returns. A frame is recognized once and only once — tracked across restarts,
because re-reading frames would invent observations that never happened.

**Recognition is pluggable.** JustiKey depends on nothing outside the
standard library, so no CV stack ships here. `--recognizer stub` produces
deterministic fake reads so the whole pipeline can be exercised without a
camera. `--recognizer command` shells out to any engine and parses its output
(JSON or `PLATE,CONFIDENCE` lines). Swapping engines never touches JustiKey.

The device holds no policy, answers no queries, and keeps no history beyond
its send buffer. A stolen camera yields almost nothing: its credential is
revocable on its own, and it cannot search anything. Prefer `--delete-after`
in the field — the frame is more sensitive than the plate read.

### What building the hardware actually involves

The honest split: the integration and privacy work above is done, and the
recognition work is a genuine, separate engineering effort. The hard parts
are optics and ML, not the JustiKey interface.

- **Optics dominate.** Plates are retroreflective, so IR illumination and a
  matched IR-pass filter matter more than sensor megapixels. A short exposure
  is needed to freeze a moving vehicle, which forces the illuminator to be
  strong. Fixed focus at a known distance and a narrow field of view beat a
  wide general-purpose lens.
- **Compute.** A Raspberry Pi 5 class board handles a single lane at modest
  frame rates; heavier detector plus OCR models want something like a Jetson
  Orin Nano. Decide the frame budget before choosing models.
- **Recognition.** Plate detection then OCR, as two stages. Accuracy is an
  iterative grind against motion blur, skew, weather, night glare, and
  regional plate formats — not a one-time integration.
- **Licensing.** Check the license of any engine before it ships in a
  product; some well-known ALPR engines are AGPL, which has real
  implications for a commercial deployment.
- **Field reality.** Mounting angle, enclosure heat, lens cleaning, and power
  determine real-world accuracy at least as much as the model does.

A sensible order is: prove the pipeline end-to-end with the stub recognizer
(done), swap in an off-the-shelf engine behind `--recognizer command` and
measure accuracy on real footage from the intended mounting position, and
only then decide whether custom hardware and a custom model earn their cost.
Nothing above that line requires custom hardware, and the JustiKey interface
does not change when you cross it.

### Core principle: collection is not access

Sensors (or the simulator) authenticate with an API key and POST
observations to `/ingest`. That's it — ingestion never makes a plate
searchable by itself. The dashboard shows only aggregate counts (total
events, pending/active authorizations); there is no page that lists plate
history.

### Two-person authorization

`models.approve_authorization()` and the `/authorizations/<id>/approve`
route both hard-block a user approving their own request
(`requested_by == approver_id`) — this is enforced in the data layer, not
just hidden in the UI, and is covered by `tests/test_policy.py`.

### Strong authentication

- PBKDF2-HMAC-SHA256 password hashing (200,000 iterations, random salt).
- RFC 6238 TOTP, required at login and again before approving a request.
- TOTP codes are single-use per security context, so one code cannot
  approve two requests inside the same 30-second step.
- Login spends the same PBKDF2 work whether or not the username exists, so
  response time does not turn the login form into a username oracle.
- Random 256-bit session tokens; only a SHA-256 hash of the token is
  stored server-side.
- HttpOnly, `SameSite=Lax` session cookies (add `JUSTIKEY_COOKIE_SECURE=1`
  when serving over HTTPS in a real deployment).
- CSRF tokens bound to the session, required on every state-changing POST.
- `Cache-Control: no-store` on every response, so disclosed records are
  never written to a browser or proxy cache.

### Narrowly scoped disclosure

Every search re-checks all conditions at request time
(`justikey/policy.py`): the authorization exists, belongs to the requester,
is approved, has not expired, the searched plate exactly matches the
authorized target plate, and only observations inside the authorized time
window are returned. Approval expires ~30 minutes after being granted
(`JUSTIKEY_APPROVAL_VALIDITY`), after which a fresh authorization is
required.

Scoping is only as trustworthy as the time comparison behind it. Because
the ingest API is deliberately camera-independent, it receives whatever
ISO-8601 flavor a vendor emits, and timestamps are range-compared as text
in SQLite. Every timestamp is therefore normalized at the trust boundary to
one fixed-width UTC form (`justikey/timeutil.py`), so lexicographic order
always equals chronological order. Without that, a `Z` suffix or a naive
timestamp sorts outside a window it genuinely falls inside, and an
investigator holding a valid warrant silently receives incomplete results.

### Tamper-evident audit ledger

Every sensitive action — logins (success/failure), authorization requests,
approvals, denials, self-approval attempts, denied searches, successful
disclosures, and sensor ingestion — is appended to `audit_log` with a
SHA-256 hash over its own fields *and* the previous entry's hash. Altering
or deleting any row breaks the chain from that point forward, which
`scripts/verify_audit.py` and the in-app `/audit/verify` page both detect.

Appends are wrapped in a `BEGIN IMMEDIATE` transaction. The server is
threaded, so reading the chain head and writing the next link has to be one
atomic step; otherwise two concurrent appends compute the same sequence
number, one loses the uniqueness race, and the entry is dropped while the
surviving chain still verifies clean — a silent hole in exactly the record
the ledger exists to keep. Verification also checks for sequence gaps, not
just hash continuity, since removing a whole entry leaves the remaining
links internally consistent.

### External anchoring: closing the tail-truncation gap

A hash chain proves no entry was *modified*, but not that none was *removed
from the end*. Deleting the newest entries leaves a shorter chain that
still verifies perfectly — so the record an attacker most wants to erase,
the one covering what they just did, is exactly the one the chain alone
cannot protect.

Anchoring closes that gap by periodically publishing a signed checkpoint of
the chain head (`justikey/anchor.py`). Verification then compares the ledger
against the highest checkpoint: a ledger shorter than something already
witnessed proves entries were deleted.

Each checkpoint carries two values. `hash` is a plain SHA-256 over its
fields, so anyone can check that checkpoints link together and match the
ledger without holding any secret. `mac` is an HMAC-SHA256 proving the
checkpoint was issued by this system and not forged by whoever rewrote the
ledger. Checkpoints chain to each other too, so one cannot be quietly
removed from the middle.

Checkpoints go to two places, and **they are not equally strong**:

| destination | protects against | defeated by |
|---|---|---|
| local anchor log (`*.anchors.jsonl`) | deleting ledger rows | an attacker who also rewrites the log and holds the signing key |
| independent witness (`scripts/witness_server.py`) | deleting ledger rows *and* rewriting the local log | nothing the JustiKey host alone can do |

The witness is the control that actually works against a host-level
adversary, because its records are out of reach. Run one and point JustiKey
at it:

```bash
python3 scripts/witness_server.py --port 8090 --store witness.jsonl
JUSTIKEY_WITNESS_URL=http://127.0.0.1:8090 python3 scripts/run_server.py
```

The witness only appends. It accepts an identical re-submission but returns
409 on a *different* checkpoint at a sequence it already holds, so history
cannot be quietly replaced.

Anchors are written automatically every `JUSTIKEY_ANCHOR_INTERVAL` entries
(default 25), on demand from the audit page, or from cron:

```bash
python3 scripts/anchor_audit.py --db justikey.db --witness http://127.0.0.1:8090
```

Verification reports all three layers:

```bash
python3 scripts/verify_audit.py justikey.db --witness http://127.0.0.1:8090
```

Deleting the last 8 entries produces exactly the split the design predicts —
the chain sees nothing wrong, the anchors prove what is missing:

```
  chain   : OK, 22 entries, no tampering detected
  anchors : FAILED: ledger ends at seq=22 but seq=30 was already anchored:
            8 entries have been removed
  witness : FAILED: ledger ends at seq=22 but seq=30 was already anchored:
            8 entries have been removed
```

**Key custody is what makes this real.** By default the signing key is
generated beside the database, which an attacker who can rewrite the ledger
can usually also read — that fallback raises the bar but does not hold
against host compromise. Supply the key out of band so it never touches the
host, and give auditors their own copy:

```bash
JUSTIKEY_ANCHOR_KEY=$(openssl rand -hex 32) python3 scripts/run_server.py
```

With the key held independently, an attacker who deletes the tail *and*
forges a replacement anchor log is caught on both counts: the forged log
fails signature verification, and the witness proves the deletion.

**Remaining limitation:** anchoring bounds how much can be erased
undetected, it does not reduce it to zero. Entries written since the last
checkpoint are still truncatable without contradiction, so the interval sets
the exposure window. Shorten it, and treat the audit page's "entries since
last checkpoint" figure as the live measure of that gap. Production should
additionally use asymmetric signatures (so verifiers need only a public key)
and anchor to WORM storage or a public transparency log.

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

## Known limitations of this prototype

This is a lab prototype, not a deployable system. Read
[docs/threat-model.md](docs/threat-model.md) alongside this list — it states
what the architecture does and does not defend against, including the
residuals that survive every control here.

**Not implemented, and needed before real plate data:**

- **The WebAuthn browser ceremonies.** Assertion verification, the custody
  layer and credential enrolment are built and tested; the registration and
  assertion pages that would let a user enrol and use a security key through
  the web interface are not. Hardware custody works today only for a
  deployment that obtains the registration values by other means.
- **The disclosure key in hardware.** It is a file the service reads into
  memory. An HSM or KMS that performs the key agreement itself, and re-checks
  scope before doing so, is the next concentration of risk to break up
  (threat-model finding 2).
- **mTLS or device-identity authentication for sensor ingest.** Sensors
  authenticate with per-source bearer or HMAC credentials, not device
  identity.
- **Enterprise identity** — FIDO2/WebAuthn, CAC/PIV, or an IdP — in place of
  local accounts with TOTP.
- **Cryptographically signed warrant documents.** The legal authority is a
  text field an approver attests to; it is not itself verifiable.
- **Asymmetric anchor signatures and WORM or transparency-log anchoring.**
  The prototype ships HMAC checkpoints plus an independent witness, so a
  party holding the anchor key can forge checkpoints.
- **Ingest rate limiting.** Login throttling exists; the ingest endpoints
  have none, so a caller with a bad credential can still drive audit writes.
- **Legal holds, multi-tenancy, intrusion monitoring, and incident-response
  tooling.**
- **A durable job to prune spent TOTP records.** Sessions are purged
  opportunistically at login; `used_totp` rows accumulate.

**Implemented, but read the caveat:**

- **Proof of presence.** The requester signs each disclosure, so a stored
  approval is no longer enough on its own. With a software key the attacker's
  window narrows to moments the requester is actually working rather than
  closing entirely; with hardware it closes.

- **Keys outside the database.** Data, index, anchor and disclosure keys can
  all be supplied from a secrets manager, and under v3 the disclosure and
  index keys live in a separate service. The development fallback writes a
  key file beside the database and says so on stderr every time.
- **Retention.** `scripts/enforce_retention.py` deletes observations past
  their window and audits the purge, but nothing schedules it for you.
- **Login lockout.** Accounts lock after repeated failures and the lockout is
  audited. It is per-username, so it does not stop password spraying across
  many accounts.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

Two things the licence does not do, stated here because this project is about
not overclaiming: it grants no warranty, and it is not an assurance that
running JustiKey satisfies any jurisdiction's requirements for ALPR
collection, retention, or disclosure. Those are questions for your own
counsel.
