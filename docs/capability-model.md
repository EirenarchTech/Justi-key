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
3. **Separate the service.** Move it to its own host/trust domain, with its
   own audit ledger and its own anchoring. `DisclosureService.disclose()` is
   deliberately already the interface a remote service would expose, so this
   changes where it runs rather than what it does.
4. **Hardware custody.** Approver keys on smartcards; disclosure key in an
   HSM or KMS that enforces the policy check itself.

Stage 1 is worth doing on its own merits and is a prerequisite for the rest.
`scripts/capability_poc.py` demonstrates stages 2–3 end to end so the design
can be evaluated before any of it is committed to the main codebase.
