# JustiKey threat model

Ordered by how much each finding costs if it is wrong, not by how hard it is
to fix. Every claim here is one the test suite exercises; where a mitigation
is partial, this says so rather than rounding up.

## 1. Offline inference through the blind index — the top residual

Authorized search needs exact-match lookup over encrypted plates, which is
done with a keyed blind index: `HMAC(k_index, plate)`. **Plates are
low-entropy.** The AAA999 space is about 17.5 million candidates, so whoever
holds `k_index` can enumerate it against the stored indexes and recover plate
identities *without decrypting anything*.

This is measured, not hypothetical. Against a stage-2 database:

```
recovered 3/3 plates in 23.7s (6,572,000 guesses, 277,467/s)
full AAA999 space -> ~1.1 min single-threaded, unoptimised
```

That invalidated the stage-2 claim that the application "cannot read what it
collects". It could not read `location`, but plate identity together with
timestamp and camera is the substance of the harm.

**Mitigation (stage 3).** `k_index` belongs to the disclosure service. The
application does not hold it and cannot derive it: `resolve_index_key()`
refuses outright whenever a separate service is configured, because removing
the *usage* while leaving the key derivable from the data key would leave the
attack fully intact.

**Residual, stated plainly.** The application still needs scope tokens to
index arriving observations, so the service exposes `/index`. A compromised
application can grind the plate space through it. That path is:

* online — one network round trip per guess, not 277k/s locally;
* rate limited — `--index-limit` tokens per minute, default 600;
* recorded — every call writes `scope_token_issued` to the service's ledger.

So the attack goes from *offline, silent, about a minute* to *online, slow,
and loud*. It is not eliminated. An OPRF would hide the plate from the
service but would not remove this channel either, because the application can
still query for arbitrary inputs. **The real fix is tokenization at the
camera**, so the ordinary server never handles a plate it could ask about —
see the future stage below.

## 2. Compromise of the disclosure service

The service holds the disclosure private key and the index key, so
compromising it yields the archive. Risk is concentrated, not eliminated.
This is only worth doing if the service is genuinely more defensible than the
application: separate host, separate OS principal, minimal request
vocabulary, its own ledger, and — at stage 4 — a key in hardware that cannot
be exported even by that host's administrator.

Running it on the same box as the application is theatre.

## 3. Compromise of the web application

With the application fully compromised — database, environment, arbitrary
SQL, code execution — the following hold and are tested:

| Attempt | Result |
|---|---|
| Read plate/location columns | empty; values are sealed |
| Decrypt a record with the application's data key | refused (`WrongKeyError`) |
| Find a disclosure private key on the host | none present |
| Derive the index key and enumerate offline | refused |
| Forge an approval with an attacker-controlled key | refused: the service holds its own approver registry |
| Grind the index through `/index` | possible, rate limited, logged (finding 1) |
| Replay a captured authenticated request | refused: transport nonces are spent once |
| Reuse a genuine live approval at `/disclose` | refused without fresh proof the requester is present (finding 5); where no requester key is enrolled, possible within scope, window and count, capped and logged |
| Sign as a requester whose password it captured | refused once that requester holds a security key |

The precise claim this supports is: **the application cannot decrypt stored
observations after ingestion.** It is *not* "the application never has access
to the plate" — the application receives the plaintext plate at ingest and
seals it. Those are different statements and only the first is true today.

## 4. Approval forgery

Approvals are Ed25519 signatures over a canonical statement carrying schema
version, authorization id, case, legal authority, purpose, target plate,
window, requester, approver, approver key id, issue time, expiry, and a
nonce. The disclosure service rejects unknown schema versions, missing
fields, expired or future-dated approvals, self-approval, unenrolled or
revoked approver keys, and any statement whose named key id does not match
the key it has enrolled.

The approver's key is wrapped under their password, so the application can
sign only while an approver is actually present. It cannot mint approvals for
last month or for tomorrow. **Residual:** an application compromised at the
moment of signing can misuse that moment — and, having seen the password, can
keep signing afterwards. An approver enrolled on a WebAuthn authenticator
(`justikey/custody.py`) closes the second half of that: the key never reaches
this process, so the attacker gets the operations a present human confirmed
and nothing more.

## 5. Active authorization abuse — the residual inside a valid approval

The controls in section 4 stop an attacker *minting* an approval. They do
nothing about one that already exists. A fully compromised application holds
the database, so it holds every approval row: statement, signature, nonce and
all. It can replay a genuine, unexpired, correctly signed approval belonging
to officer1 straight at `/disclose`, sending `requester="officer1"`, and the
service will honour it — because from the service's side that request is
indistinguishable from the real one. Nothing in the protocol proves officer1
is at a keyboard.

So the honest statement is: **an approval is a bearer capability for as long
as it is live.** What stops it from being an unlimited one is that the
service, not the application, decides how far it goes.

| Bound | Where it is enforced |
|---|---|
| Scope: this plate, this window, nothing else | service, re-derived from the signed statement |
| Lifetime: until `approval_expires_at` | service, checked per request and again in the usage store |
| Count: N disclosures, 25 by default | service (`disclosure.UsageStore`), one row per approval nonce |
| Visibility: every use lands in the service's ledger | service, written before the response |

The count is the one that changed most recently, and it changed because the
earlier arrangement did not survive this threat. The cap lived in
`policy.evaluate_disclosure()` — in the application, the very component
assumed compromised — and a nonce was written to an in-process dictionary
that nothing ever read. Calling `disclose()` directly opened records 60 times
against a configured cap of 25, and a restart reset even that. The count now
lives in the service's own database, is claimed inside a `BEGIN IMMEDIATE`
transaction before anything is opened, and survives restarts; the
application's copy is advisory, kept only so the honest path can refuse early
with a specific message.

A second, smaller version of the same problem is at the transport layer: an
authenticated request stays valid for the whole clock-skew window, so a
captured one could be resent verbatim. Each `X-JustiKey-Nonce` is now spent
once, in a separate namespace from approval nonces, and reuse is a 401 and a
`transport_replay_refused` ledger entry.

### What stage 4 changed

The bounds above were real; the absent officer was too. A fifth bound now
sits ahead of all of them: the requester signs each disclosure at the moment
they ask for it (`justikey/presence.py`), and the service checks it against a
requester registry it holds and the application does not.

| Bound | Where it is enforced |
|---|---|
| Presence: this person, this approval, this scope, once, now | service, against its own requester registry |

The proof carries the approval's nonce and the digest of the approver's exact
signed statement, so it cannot be moved onto a different approval or onto one
whose row was edited afterwards; its nonce is spent once, so one confirmation
buys one disclosure; and the lifetime it may claim for itself is capped by the
verifier, not by the caller. Measured against the same attack: with no key
enrolled, replaying a stored approval opened the record; with a key enrolled,
`this disclosure needs proof that the requester is present; an approval on
its own is not sufficient`.

**What is still open, and how far.** It depends on where the requester's key
lives, and the difference is the whole reason stage 4 has two halves:

| Requester's key | What a fully compromised application can still do |
|---|---|
| None enrolled (`presence_mode: enrolled`) | everything above: spend live approvals in that person's name |
| Software, password-wrapped | mint further proofs *while it holds the unwrapped key* — i.e. during moments the officer is actually present and working, and not afterwards |
| Hardware (WebAuthn) | obtain a proof only for a challenge a present human physically confirmed, one touch at a time, and none afterwards |

So the honest claim is no longer "an approval is a bearer capability". It is:
**a live approval plus a present requester is a bearer capability for that
moment**, and with hardware custody, for that single confirmed operation. A
compromised application that captured an officer's password gets nothing once
they hold a security key — `custody.verify_proof` refuses a software
signature from a principal with hardware enrolled, so enrolling a key raises
the bar rather than adding a second way in.

What remains beyond this is not about the requester. The disclosure service
still holds its private key in process memory (finding 2): an HSM or KMS that
performs the key agreement itself, and re-checks scope before doing so, is
the next concentration of risk to break up. And the browser pages that run
the WebAuthn ceremonies are not written, so hardware custody today requires
obtaining registration values by other means — the verification path is
complete and tested, the front door to it is not.

## 6. Record transplantation

Each envelope authenticates, as AEAD associated data, its format version,
recipient key id, record uid, capture time, camera id, and blind index. Any
attempt to move a ciphertext, wrapped key, index, or timestamp between
records fails the tag check. The record uid is generated at seal time rather
than taken from the row id, which the database — and therefore an attacker
with SQL — controls.

## 7. Audit integrity

The application and the disclosure service each keep their own hash-chained
ledger. Appends are serialized (`BEGIN IMMEDIATE`, plus an in-process lock in
the service) because a chain that forks under concurrent writes destroys the
evidentiary property; 50 concurrent writers across threads and processes are
tested to produce 50 entries and verify clean. Chains cannot detect
truncation of their own tail, which is why checkpoints are anchored to an
independent witness.

The disclosure ledger deliberately does **not** record the plate involved in
a scope-token request. Logging it would rebuild the archive the service
exists to protect.

## 8. Availability as a safety property

If the disclosure service is unreachable, lawful access stops. That is
correct, and it is deliberate: there is no fallback path that opens records
without the service. The policy engine returns `disclosure_unavailable` and
records stay sealed.

## Future stage: tokenization at the sensor

The strongest version of finding 1 is to remove the application from the
plaintext path entirely. If the camera seals and tokenizes the plate before
transmission, the ordinary server is incapable of interpreting an observation
from the moment it arrives, and there is no `/index` channel to grind because
the application never needs to ask about a plate it holds.

That moves key material onto physically exposed devices, which is its own
threat model — a stolen camera must not become an enumeration oracle. It is
the right direction and it is not free.
