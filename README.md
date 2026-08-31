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

This repository is a runnable prototype of that architecture. It uses only
the Python standard library — no third-party packages, no external
services — so the whole workflow can be exercised on a laptop.

## Quickstart

Requires Python 3.9+ and nothing else.

```bash
# 1. Start the server (creates demo accounts + a sensor API key on first run)
python3 scripts/run_server.py --port 8080

# 2. In another terminal, feed it synthetic ALPR observations
python3 scripts/simulator.py --api-key <printed-by-run_server> --count 30

# 3. Open http://127.0.0.1:8080/login in a browser
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
   ledger, and run an integrity check from the UI or the command line:

```bash
python3 scripts/verify_audit.py justikey.db
```

`verify_audit.py` deliberately re-implements the hash-chain check from
scratch against the raw SQLite file, rather than importing the server's own
audit module — an independent verifier, not a callback into the code that
wrote the ledger.

## Architecture

```
justikey/
  config.py      settings (paths, lifetimes, cookie flags) via env vars
  db.py          SQLite schema and connection helper
  crypto_utils.py  PBKDF2 password hashing, RFC 6238 TOTP, session tokens
  audit.py       hash-chained audit ledger (append + verify)
  models.py      data access: users, sessions, events, authorizations
  policy.py      disclosure policy engine — the only path to protected data
  templates.py   minimal HTML templating (all interpolation is escaped)
  webapp.py      http.server-based router, auth flow, CSRF, all routes
  seed.py        deterministic demo accounts + sensor API key

scripts/
  run_server.py    start the app (seeds demo data on first run)
  simulator.py     synthetic ALPR observation generator (no camera needed)
  show_totp.py     dev helper: current TOTP code for a demo account
  verify_audit.py  independent CLI audit-chain verifier

tests/
  test_totp.py        TOTP + password hashing correctness
  test_totp_replay.py single-use enforcement for TOTP codes
  test_audit.py       hash-chain integrity, including tamper detection
  test_policy.py      disclosure policy: ownership, approval, expiry, plate match
  test_timeutil.py    canonical timestamps; window filtering across vendor formats
  test_concurrency.py no audit entry lost under concurrent append; atomic approval
```

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

**Known limitation:** a hash chain cannot detect truncation of its own
tail. Deleting the most recent N entries leaves a shorter but perfectly
valid chain. Detecting that requires an anchor outside the database — a
countersigned checkpoint, WORM storage, or an external witness — which is
listed below as production work.

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
- Externally anchored or WORM audit storage (see the tail-truncation
  limitation above).
- Rate limiting and lockout on the login and ingest endpoints. Nothing here
  throttles password guessing, and a caller with a bad API key can still
  drive audit writes.
- Retention policies, legal holds, multi-tenancy, intrusion monitoring, and
  incident-response tooling.
- A durable job to prune spent TOTP records and expired sessions; the
  prototype purges sessions opportunistically at login.

See the platform description for the full production security roadmap.
