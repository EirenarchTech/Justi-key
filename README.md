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
3. `supervisor1` signs in separately, reviews the request, enters a fresh
   TOTP code, and approves it. Approval is valid for ~30 minutes.
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
```

## Encryption at rest

Every other control in JustiKey governs *access*: who asked, who approved,
how narrow the scope was. None of them help if someone simply takes the
database file. A stolen backup, a decommissioned disk, or a copied volume
would yield the entire location history with no authorization, no approval,
and no audit entry -- defeating every control at once.

Plate and location values, and TOTP secrets, are therefore stored as
AES-256-GCM ciphertext (`justikey/crypto_store.py`). Exact-plate search still
works because each observation also carries a **blind index**: a keyed HMAC
of the normalized plate. Lookups match on the index, so the query never
handles plaintext; values are decrypted only for rows the policy engine has
already authorized.

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

### Key custody is the whole point

A key sitting beside the database protects against a stolen file and nothing
more. Supply it out of band so possession of the database alone is not
enough:

```bash
JUSTIKEY_DATA_KEY=$(openssl rand -hex 32) python3 scripts/run_server.py
```

The generated `*.data-key` file is a development fallback and says so on
stderr every time it is created.

### Migrating an existing database

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

### Residual exposure, stated plainly

- **The blind index is deterministic.** An attacker holding the database can
  tell that two rows concern the same (still unknown) vehicle and count how
  often it was seen. That is inherent to searchable encryption; removing it
  would mean giving up authorized lookup entirely.
- **camera_id and captured_at stay plaintext.** They are needed to operate
  the system and to bind the AAD. With the blind index they reveal movement
  patterns of an unidentified vehicle, not its identity.
- **A running server holds the key.** This protects data at rest, not against
  a live host compromise.

## Limits enforced in software, not policy

The stated goal is to turn privacy requirements into enforceable
architecture. These were previously human expectations only:

| Control | Setting | Default |
|---|---|---|
| Maximum authorization time window | `JUSTIKEY_MAX_WINDOW_DAYS` | 90 days |
| Disclosures per approval | `JUSTIKEY_MAX_DISCLOSURES` | 25 |
| Failed sign-ins before lockout | `JUSTIKEY_MAX_FAILED_LOGINS` | 5 |
| Lockout duration | `JUSTIKEY_LOCKOUT_SECONDS` | 900 |
| Observation retention | `JUSTIKEY_RETENTION_DAYS` | 365 days |

**Scope breadth.** A request spanning years is refused before anyone can
approve it, and the limit is re-checked at disclosure time -- a check applied
only at creation could be bypassed by any path that edits an authorization
afterwards.

**Disclosure cap.** One approval no longer authorizes unlimited re-querying
inside its window.

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

This is intentionally a lab prototype, not a deployable system. It does
not implement (and a production JustiKey should add):

- Encryption at rest for protected records with keys held outside the
  application database (HSM/KMS/TPM).
- mTLS or device-identity-based authentication for sensor ingest.
- Enterprise identity, hardware-backed MFA, FIDO2/WebAuthn, or CAC/PIV in
  place of the deterministic demo accounts.
- Cryptographically signed/verified warrant documents.
- Asymmetric anchor signatures and WORM or transparency-log anchoring (the
  prototype ships HMAC checkpoints plus an independent witness; see the
  anchoring section above).
- Rate limiting and lockout on the login and ingest endpoints. Nothing here
  throttles password guessing, and a caller with a bad API key can still
  drive audit writes.
- Retention policies, legal holds, multi-tenancy, intrusion monitoring, and
  incident-response tooling.
- A durable job to prune spent TOTP records and expired sessions; the
  prototype purges sessions opportunistically at login.

See the platform description for the full production security roadmap.
