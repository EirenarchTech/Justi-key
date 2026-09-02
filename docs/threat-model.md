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
moment of signing can misuse that moment. Stage 4 (smartcard / WebAuthn)
closes it.

## 5. Record transplantation

Each envelope authenticates, as AEAD associated data, its format version,
recipient key id, record uid, capture time, camera id, and blind index. Any
attempt to move a ciphertext, wrapped key, index, or timestamp between
records fails the tag check. The record uid is generated at seal time rather
than taken from the row id, which the database — and therefore an attacker
with SQL — controls.

## 6. Audit integrity

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

## 7. Availability as a safety property

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
