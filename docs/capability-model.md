# Design: authorization as a cryptographic capability

## The problem with what exists today

JustiKey currently encrypts plate and location at rest, and the policy engine
decides whether a search may run. Those are different guarantees than they
look:

- **Encryption at rest** protects a database file that has left the building
  — a stolen backup, a decommissioned disk, a copied volume.
- **The policy engine** protects nothing against the application itself. It
  is an `if` statement. The server holds one key that can decrypt every
  record, and it chooses to obey the check.

So the honest statement of the current trust model is: *a compromised
application process, or an administrator who can run code on the server, can
read every plate ever collected without an authorization, without a second
approver, and without an audit entry.* Encrypting the SQLite file does not
change that, because the running process holds the key that opens it.

For a system whose entire claim is "collection is not access", that is the
gap that matters most. Approval should not merely permit a query — it should
be the only thing that produces the ability to decrypt.

## Target model

Split the ability to **write** observations from the ability to **read**
them, and make approval the step that mints a narrowly scoped read capability.

```
                  ┌──────────────────────────────────────────┐
   camera ───────►│ JustiKey app        (public key only)    │
                  │  · encrypts every observation             │
                  │  · CANNOT decrypt anything                │
                  └──────────────┬───────────────────────────┘
                                 │ authorization + approver signature
                                 ▼
                  ┌──────────────────────────────────────────┐
                  │ Disclosure service   (private key, HSM)  │
                  │  · verifies the approver's signature      │
                  │  · re-checks scope independently          │
                  │  · returns keys for in-scope records ONLY │
                  └──────────────────────────────────────────┘
```

**Ingest is write-only.** Each observation gets a fresh random record key
`K_r`; the fields are sealed under `K_r`, and `K_r` is wrapped to a public
key. The application server holds only the public half. A compromised app
server can keep collecting and can prove nothing about what it already holds
— it cannot read a single stored plate.

**Approval mints a capability.** The approver signs the authorization with
their own key (in the strong form, a smartcard or HSM-held key). The
disclosure service will not unwrap anything without a valid approver
signature over that exact authorization: plate, window, case, requester,
expiry.

**Unwrapping is scoped.** The disclosure service unwraps `K_r` only for
records inside the authorized plate and window, and only until the approval
expires. It never hands back the root private key, so the application never
gains the ability to decrypt anything else.

## What this changes

| Adversary | Today | With capabilities |
|---|---|---|
| Stolen database file | blocked (encryption at rest) | blocked |
| Malicious/compromised app server | **reads everything** | reads nothing without an approver signature |
| Administrator on the app host | **reads everything** | reads nothing without an approver signature |
| Insider with a valid login | blocked by policy checks | blocked, and cryptographically so |
| Compromised app replaying a live approval | **reads that plate's history** | refused without fresh proof the requester is present (stage 4) |
| Compromised app that captured a password | **signs as that person** | refused once they hold a security key (stage 4) |
| Compromised disclosure service | n/a | reads everything — the new concentration of risk |

The two-person rule stops being a procedural control the application chooses
to honour and becomes an arithmetic precondition: without the approver's
signature, there is no key, so there is no plaintext.

## Honest costs

- **The disclosure service becomes the crown jewels.** Risk is concentrated,
  not eliminated. It is worth it only if that service is genuinely more
  defensible than the app — separate host, minimal surface, HSM-backed key,
  its own audit trail. Running it on the same box as the application is
  theatre.
- **Blind-index search still leaks.** The index must remain computable at
  query time to find candidate rows, so equality leakage survives this
  change. Narrowing it means per-window index keys, which trade recall for
  privacy.
- **Key loss becomes final.** No decryption path outside the disclosure
  service means losing that key loses the archive. Escrow reintroduces the
  problem it solves, so it needs a deliberate M-of-N custody design.
- **Retroactive approval is impossible by construction.** That is a feature —
  it is what makes the guarantee real — but it means an outage of the
  disclosure service blocks all lawful access, so availability becomes a
  safety property.
- **Approver key management is the hard part.** The scheme is only as good as
  the approver's private key. Software keys on the same host would collapse
  the whole model back to an `if` statement.

## Staged path

1. **Approver-signed authorizations.** *(built — `justikey/approvals.py`)*
   Approvers hold an Ed25519 key whose private half is wrapped under their
   password, so the server can only sign while the approver is present.
   Approval requires password plus TOTP, and the approver signs a statement
   covering the case, legal authority, purpose, target plate, window,
   requester, approver, and expiry. The policy engine rebuilds that statement
   from the row's *current* values and verifies it before any disclosure, so a
   post-approval edit — swapping the target plate onto a genuine approval —
   is refused rather than silently honoured.

   Not yet cryptographic enforcement: the data key still opens every record,
   so a server compromised *while an approver is signing* could misuse that
   moment. What it does buy is that approvals cannot be forged for periods
   when no approver was present, and cannot be altered after the fact.
2. **Split the key.** *(built — `justikey/sealing.py`, `justikey/disclosure.py`)*
   Each observation is sealed under a fresh record key, which is itself
   wrapped to a disclosure public key via an ephemeral X25519 exchange. The
   write path holds only the public half, so `search_events` returns rows
   still sealed and has no way to open them. Everything that turns a sealed
   record into a plate goes through the disclosure service, which verifies
   the approver's signature and re-derives scope from the signed statement
   rather than trusting the caller's selection. Scope is checked against the
   blind index, so an out-of-scope record is never opened in the act of
   deciding not to disclose it.

   In `local` mode the private key is loaded into the application process,
   so the split is structural rather than enforced: it establishes the
   chokepoint, the wrapping format, and the independent scope check. An
   attacker with code execution in the application can still reach the key
   until stage 3 moves it out.
3. **Separate the service.** *(built — `scripts/disclosure_server.py`)*
   The service runs as its own process and principal, holding the disclosure
   private key **and** the blind-index key, with its own append-only
   hash-chained ledger. The application holds neither key: it seals against a
   public key, obtains scope tokens from the service, and sends candidate
   rows to be opened.

   Three things the service does not take from its caller: the approver's
   public key (it keeps its own enrolment, so a compromised application
   cannot present a key it controls), the index key, and the selection of
   rows. Envelopes bind format version, recipient key id, record uid, capture
   time, camera and blind index as AAD, so nothing can be transplanted
   between records.

   The service also owns the state that bounds a live approval, because the
   application cannot be trusted to bound itself: `approval nonce ->
   disclosure count -> expiry`, claimed atomically in the service's own
   database before anything is opened. The cap had been enforced in
   `policy.evaluate_disclosure()` — inside the component assumed compromised
   — so calling `disclose()` directly opened records 60 times against a cap
   of 25. Transport nonces are spent once as well, so a captured
   authenticated request cannot be replayed inside the clock window. See
   [threat-model.md](threat-model.md) finding 5.

   Building this found that removing the *use* of the index key from the
   application was not enough — it remained derivable from the data key, so a
   compromised application could still enumerate offline.
   `resolve_index_key()` now refuses outright in remote mode. See
   [threat-model.md](threat-model.md) finding 1 for the residual that
   remains.
   Migrating an existing v1 store into this arrangement is a ceremony rather
   than a command, because its last step destroys a key that opens every
   record: `scripts/seal_store.py plan | migrate | verify | rekey-credentials
   | destroy-legacy-key`. Building it turned up two things the design had not
   accounted for. The v1 root key also protects TOTP secrets and sensor
   signing secrets, so destroying it after sealing the observations would lock
   every user out of their second factor. And the ceremony can only be
   completed against a separated service: in local mode the blind-index key is
   derived from the data key, so rotating that key orphans every stored index
   and the archive cannot be repaired, because repairing it would mean opening
   records the application can no longer open.

4. **Hardware custody and proof of presence.** *(built — `justikey/webauthn.py`,
   `justikey/custody.py`, `justikey/presence.py`)*
   Stage 3 leaves an approval a **bearer capability**: the disclosure service
   checks that it is genuine, unexpired, in scope and within its count, and
   all of that is equally true of a request a compromised application sends
   on its own, using an approval from its own database and the string
   `requester="officer1"`. Nothing proved the officer was there.

   Now the requester signs each disclosure as they ask for it — not the
   authorization, which was the approver's signature made earlier, but *this
   request*: which approval, over which exact signed scope, by whom, once,
   now. The service verifies it against a requester registry it holds and the
   application does not, spends the proof's nonce so one confirmation buys
   one disclosure, and caps the lifetime a proof may claim for itself.

   Keys move off the host through one proof envelope covering both custodies:

       {"alg": "ed25519",  "sig": ...}                    software, password-wrapped
       {"alg": "webauthn", "authenticator_data": ..., ...} hardware, key never exported

   `custody.verify_proof` dispatches on that field, so a deployment migrates
   one person at a time without a second verification path — and a principal
   with hardware enrolled has their software signature **refused**, because
   enrolling a security key must raise the bar rather than add a second way
   in that the old password still opens.

   The challenge a WebAuthn authenticator signs is the digest of the exact
   statement being authorized, so an assertion is usable for that statement
   and no other. Verification checks the signature, the ceremony type, the
   challenge, the origin, the RP id, the user-present and user-verified
   flags, and the signature counter — each a distinct attack, each a distinct
   refusal.

   Four invariants this stage commits to, each pinned by a test rather than
   left to a default: user presence is mandatory for every hardware assertion
   with no way to disable it; user verification is required per role
   (`JUSTIKEY_WEBAUTHN_REQUIRE_UV`, defaulting to all); the approval count and
   the presence nonce are spent in **one** transaction with a uniqueness
   constraint as the backstop, so concurrent requests cannot both get through
   and a request refused by the cap does not also burn a confirmation; and the
   registries are versioned with their digests committed to the service's
   ledger, so a rollback or a silent swap refuses to start it.

   An assertion proves the enrolled authenticator participated, that a user
   was present, and — under UV — that the operator authenticated to the
   authenticator. It does **not** prove the person understood the
   transaction; that needs a trusted display, which no commodity key has.

   **What is not built:** the browser pages that run the WebAuthn
   registration and assertion ceremonies. Verification and enrolment are
   complete and tested against a synthetic authenticator
   (`tests/authenticator.py`); `scripts/manage_keys.py` enrols a credential
   from registration values obtained by any means. The disclosure key in an
   HSM or KMS that enforces the scope check itself also remains ahead.

Each stage closed a hole the previous one made visible: stage 2's split made
it obvious the application still held the index key, stage 3's chokepoint
made it obvious the disclosure cap lived in the untrusted side, and stage 3
finished made it obvious an approval was a bearer token. The remaining one is
stated in threat-model finding 5.

Stage 1 is worth doing on its own merits and is a prerequisite for the rest.
`scripts/capability_poc.py` demonstrates stages 2–3 end to end so the design
can be evaluated before any of it is committed to the main codebase.
