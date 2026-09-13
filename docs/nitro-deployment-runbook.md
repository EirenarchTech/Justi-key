# Deployment runbook: JustiKey custodian on AWS Nitro Enclaves

The custodian holds the only key that opens the archive. This runbook is how
that key comes to exist somewhere no operator, no administrator and no
compromised process can export it — and, just as importantly, how you find
out whether that is actually true before any real plate data is behind it.

**Read [stage-5-key-isolation.md](stage-5-key-isolation.md) first.** It
explains why an HSM alone does not meet the objective, and why the boundary
is the *operation* rather than the storage.

Every command here is meant to be run. Where something could not be verified
from this repository — anything that needs real AWS — it is marked and the
acceptance gate tells you what to check.

---

## 0. What you are building

```
        ┌──────────────────────── parent EC2 instance ────────────────────────┐
        │                                                                     │
        │  disclosure service ──AF_VSOCK──▶ ┌──── Nitro Enclave ────┐         │
        │   (assume compromised)            │  custodian            │         │
        │                                   │   approval checks     │         │
        │  vsock-proxy  ◀──AF_VSOCK──────── │   presence checks     │         │
        │      │                            │   spending ledger     │         │
        │      │                            │   blind-index key     │         │
        │      ▼                            │   recipient RSA key   │         │
        │   AWS KMS  ◀──────────────────────┴───────────────────────┘         │
        │   ECC_NIST_P256 / KEY_AGREEMENT, non-exportable                     │
        └─────────────────────────────────────────────────────────────────────┘

        ingest host (separate, holds NO archive) ──▶ its own custodian
```

Two properties define the shape:

- **vsock is the enclave's only channel.** It has no external network and no
  persistent storage, so the parent's vsock-proxy is how it reaches KMS.
- **The parent is in the threat model.** It proxies the KMS traffic and holds
  the transport credential. Neither of those is authorization — see
  `justikey/transport.py`.

---

## 1. Parent instance

An enclave-enabled instance type (at least 4 vCPU, e.g. `m5.xlarge`), with
enclaves turned on at launch.

```bash
aws ec2 run-instances \
  --instance-type m5.xlarge \
  --enclave-options 'Enabled=true' \
  --iam-instance-profile Name=justikey-custodian-parent \
  ...

# on the instance
sudo amazon-linux-extras install aws-nitro-enclaves-cli -y
sudo yum install aws-nitro-enclaves-cli-devel -y
sudo usermod -aG ne $USER && sudo usermod -aG docker $USER
# log out and back in for the groups to take effect
```

Allocate memory and CPU to the enclave. The custodian is small; 512 MB is
ample and 2 vCPU is the practical minimum.

```bash
sudo tee /etc/nitro_enclaves/allocator.yaml >/dev/null <<'YAML'
---
memory_mib: 512
cpu_count: 2
YAML
sudo systemctl enable --now nitro-enclaves-allocator.service
```

---

## 2. The enclave image, and its measurements

The custodian runs from a Docker image converted to an Enclave Image File.
Keep the image minimal: it is measured, and every byte in it is part of what
the KMS key policy will pin.

```dockerfile
# Dockerfile.custodian
FROM public.ecr.aws/amazonlinux/amazonlinux:2023@sha256:PIN_THIS_DIGEST
RUN dnf install -y python3 python3-pip && dnf clean all
RUN pip3 install --no-cache-dir cryptography==41.0.7 boto3
COPY justikey/ /opt/justikey/justikey/
COPY scripts/custodian_server.py /opt/justikey/scripts/
COPY approvers.json requesters.json /opt/justikey/
WORKDIR /opt/justikey

# Acceptance-run configuration, baked in. See the warning below: this is a
# TEST-ONLY arrangement and the values must be throwaway.
ARG CLIENT_SECRET
ARG INDEX_KEY
ARG KMS_KEY_ARN
ARG PUBLIC_KEY
ARG AWS_REGION

# vsock only. The server exits 4 if asked to serve TCP while attested, and
# exits 5 if given an ingest secret while attested.
CMD python3 scripts/custodian_server.py \
      --transport vsock --vsock-port 8091 \
      --attest \
      --kms-key-arn "$KMS_KEY_ARN" --public-key "$PUBLIC_KEY" \
      --region "$AWS_REGION" \
      --client-secret "$CLIENT_SECRET" --index-key "$INDEX_KEY" \
      --approvers approvers.json --requesters requesters.json \
      --presence-mode required \
      --ledger /tmp/custodian-audit.db
```

> **The CMD in an earlier draft of this runbook was incomplete** — it named
> only `--transport vsock --attest`, and an enclave built from it exits
> immediately with `--client-secret is required`. Verified by running it.
> Build from the version above.

```bash
docker build -t justikey-custodian -f Dockerfile.custodian .
nitro-cli build-enclave \
  --docker-uri justikey-custodian:latest \
  --output-file justikey-custodian.eif
```

`build-enclave` prints the measurements. **Record them; they are the thing
the KMS key policy pins.**

```json
{
  "Measurements": {
    "HashAlgorithm": "Sha384 { ... }",
    "PCR0": "<sha384 of the whole image>",
    "PCR1": "<kernel and bootstrap>",
    "PCR2": "<application>"
  }
}
```

`PCR0` is what `kms:RecipientAttestation:ImageSha384` compares against.

> **Reproducibility.** `PCR0` changes if anything in the image changes —
> including a base-image digest that moved under a floating tag. Pin the base
> image by digest and record the EIF's own SHA-256 alongside the PCRs, or the
> next rebuild will not match the key policy and you will not know why.

> **Never run the acceptance gates against a debug enclave.** An enclave
> started with `--debug-mode` or `--attach-console` produces attestation
> documents whose PCRs are **entirely zeroes**, and those documents cannot be
> used for cryptographic attestation at all. A gate run against a debug
> enclave tells you nothing about the enclave you will deploy — and because
> such a call fails, it can look like a passing "denied" result when it is
> really "this was never a real attestation". Gate 1 below records the
> launch flags for exactly this reason.

---

## 3. The KMS key

A P-256 key created for key agreement. X25519 is not available for KMS key
agreement, which is why `jk-seal-v4` uses P-256 — see
[stage-5-key-isolation.md](stage-5-key-isolation.md).

```bash
aws kms create-key \
  --key-spec ECC_NIST_P256 \
  --key-usage KEY_AGREEMENT \
  --description "JustiKey disclosure key agreement (custodian enclave only)" \
  --policy file://custodian-key-policy.json
```

Export the public key; it is what records are sealed to.

```bash
aws kms get-public-key --key-id "$KEY_ARN" \
  --query PublicKey --output text | base64 -d > custodian-public.der
# the envelope stores the raw uncompressed SEC1 point; the last 65 bytes of
# the SPKI are exactly that point
python3 -c "
import sys
der = open('custodian-public.der','rb').read()
point = der[-65:]
assert point[0] == 4, 'not an uncompressed point'
print(point.hex())" > custodian-public.hex
```

### The key policy

This is the control that does not depend on JustiKey's code being correct.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOnlyTheApprovedCustodianEnclave",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/justikey-custodian-parent"},
      "Action": "kms:DeriveSharedSecret",
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:ImageSha384": "PCR0_FROM_STEP_2",
          "kms:RecipientAttestation:PCR1": "PCR1_FROM_STEP_2",
          "kms:RecipientAttestation:PCR2": "PCR2_FROM_STEP_2"
        }
      }
    },
    {
      "Sid": "KeyAdministrationWithoutUse",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/justikey-key-admin"},
      "Action": [
        "kms:Describe*", "kms:Get*", "kms:List*",
        "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"
      ],
      "Resource": "*"
    }
  ]
}
```

Two things about this policy are deliberate:

- **`kms:DeriveSharedSecret` is the only cryptographic action granted.** Not
  `kms:*`. The key can agree and do nothing else.
- **The condition applies to the parent's role**, which is the principal that
  signs the request — the attestation document is what distinguishes an
  enclave call from a parent call using the same credentials.

> **The default key policy will undo this.** If you create the key without
> `--policy`, AWS attaches a default that grants the account root full
> access, and the attestation condition becomes decoration. Create it with
> the policy, and check with `aws kms get-key-policy` afterwards.

### The administration boundary is not in this policy

An earlier draft of this runbook said the administrator statement "grants no
cryptographic use", and concluded that whoever can change the policy cannot
use the key. **That is wrong**, and wrong in a way worth being precise about.

`kms:PutKeyPolicy` is a path to future cryptographic access. A principal that
can rewrite the key policy can write itself a new one — granting
`kms:DeriveSharedSecret` with no attestation condition, and then use the key.
Omitting `DeriveSharedSecret` from the admin role's *present* permissions is
good least privilege; it is not a separation of duties, because the admin
role can grant it to itself at any time. Any control expressed only inside
the document a principal can rewrite is a control that principal holds.

Making the separation real requires something the key-policy holder cannot
edit:

- **Deny `kms:PutKeyPolicy` on this key in a Service Control Policy**, or
  equivalent independent IAM governance, so the prohibition lives above the
  account rather than inside it.

  ```json
  {
    "Sid": "NoPolicyEditsOnTheCustodianKey",
    "Effect": "Deny",
    "Action": ["kms:PutKeyPolicy", "kms:ScheduleKeyDeletion"],
    "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID",
    "Condition": {
      "ArnNotEquals": {
        "aws:PrincipalArn": "arn:aws:iam::ACCOUNT:role/justikey-break-glass"
      }
    }
  }
  ```

- **Alarm on `PutKeyPolicy` for this key**, not merely log it. A CloudTrail
  event nobody reads is not a control. A policy change on the custodian key
  should page someone, because the legitimate rate is a few times a year.

- **Record the policy's digest** alongside the PCRs (gate 1), so a change is
  detectable by comparison rather than by noticing.

This is the same shape as the registry-integrity control in
[threat-model.md](threat-model.md) finding 8, and it has the same honest
limit: it is detection and constraint, not prevention. An organization
administrator who can edit the SCP is above all of this. What it buys is that
changing who may use the archive's key stops being a single principal's
routine action.

### Choosing what to pin

For this first acceptance deployment, pin the **exact build**: `ImageSha384`
(PCR0), `PCR1` and `PCR2`, as in the policy above. It gives the cleanest
possible answer to the one question the deployment exists to answer — *does
this exact enclave build get access, while anything altered does not?* — and
an experiment with one variable is worth more than a flexible configuration.

| PCR | Measures |
|---|---|
| PCR0 (`ImageSha384`) | the enclave image file |
| PCR1 | Linux kernel and bootstrap |
| PCR2 | the application |
| PCR3 | the IAM role attached to the parent instance |
| PCR4 | the parent instance ID |
| PCR8 | the EIF signing certificate |

For later operational deployments, move to **signed EIFs with PCR8 + PCR3**,
which AWS recommends together for flexibility. A controlled signer can then
authorise a new image without every legitimate rebuild becoming an emergency
KMS-policy edit — which matters, because a process that makes routine
rebuilds painful is a process that eventually gets a standing exception.

PCR3 is not emitted by the build; derive it from the parent's role ARN:

```bash
ROLEARN="arn:aws:iam::ACCOUNT:role/justikey-custodian-parent"
python3 -c "import hashlib; h=hashlib.sha384(); h.update(b'\0'*48); \
h.update('$ROLEARN'.encode()); print(h.hexdigest())"
```

PCR8 appears in `build-enclave` output only when `--private-key` and
`--signing-certificate` are given. **Do not make that change before the first
acceptance run.**

---

## 4. vsock-proxy on the parent

The enclave has no network. The proxy on the parent forwards its KMS traffic.

```bash
sudo tee /etc/nitro_enclaves/vsock-proxy.yaml >/dev/null <<'YAML'
allowlist:
- {address: kms.us-east-1.amazonaws.com, port: 443}
YAML

vsock-proxy 8000 kms.us-east-1.amazonaws.com 443 \
  --config /etc/nitro_enclaves/vsock-proxy.yaml &
```

The proxy listens on the parent (CID 3) at port 8000; the enclave connects
there. Keep the allowlist to exactly the KMS endpoint for your Region — it is
the enclave's whole view of the internet, and widening it widens that.

---

## 5. Credentials, registries and keys

### How configuration reaches the enclave — a gap, stated plainly

`nitro-cli run-enclave` takes an EIF, a CPU count, memory and a CID. **It has
no way to pass arguments, environment or files to the application inside.**
An enclave has no persistent storage and no network but vsock. So there are
exactly two ways for the custodian's client secret and index key to reach it:

1. **Baked into the EIF.** They are then part of the measured image — which
   means anyone holding the EIF file can extract them, and the PCRs change
   whenever they rotate.
2. **Sent over vsock after boot**, by a provisioning step the parent runs
   before the custodian begins serving.

(2) is what production needs. **JustiKey does not implement it.** The
runbook previously said configuration arrives "through the enclave's own
configuration mechanism", which described a thing that does not exist. That
is a real gap in the deployment story, not in the crypto core.

**For this disposable acceptance run, use (1) with throwaway values.** The
run is testing whether AWS enforces the attestation boundary, and adding a
provisioning protocol to the same experiment adds a variable without
answering that question. Generate a client secret and index key used nowhere
else, bake them in, destroy the environment afterwards, and record in the
evidence that configuration was baked — because a production EIF built the
same way would be shipping its secrets to anyone who can read the file.

Before production, a vsock bootstrap needs building: the custodian listens,
receives its configuration as its first frame, and only then starts
answering. The transport layer already frames and bounds messages, so it is
a new operation rather than a new mechanism.

### What has to reach it

Move these into the enclave (baked, for the acceptance run):

| Item | Where it comes from | Notes |
|---|---|---|
| approver registry | `manage_keys.py export --approvers` | versioned; the custodian refuses a rollback |
| requester registry | `manage_keys.py export --requesters` | same |
| blind-index key | generated once, never rotated without a reseal | the custodian's, not the application's |
| disclosure client secret | generated per deployment | the parent holds the matching copy |

**Do not give the enclave an ingest secret.** `--ingest-secret` enables
`index`, which mints a scope token for *any* plate — the blind-index key's
entire capability. A component holding both that operation and the archive
maps every row without opening one; measured at 25 of 25 records in 0.44
seconds before the capability was split. The server **refuses to start**
(exit 5) if given one while attested. Ingest runs against its own custodian
on a host that holds no archive.

```bash
nitro-cli run-enclave \
  --eif-path justikey-custodian.eif \
  --memory 512 --cpu-count 2 \
  --enclave-cid 16
```

Note the enclave's CID; the disclosure service connects to it.

```bash
JUSTIKEY_CUSTODIAN_URL=vsock://16:8091 \
JUSTIKEY_CUSTODIAN_CLIENT_SECRET=<disclosure secret> \
JUSTIKEY_DISCLOSURE_PUBLIC_KEY=$(cat custodian-public.hex) \
JUSTIKEY_DISCLOSURE_KEM=P256-ECDH-HKDF-SHA256 \
python3 scripts/run_server.py
```

---

## 6. The acceptance suite

Run one deliberately tiny system. Small enough that every result is
unambiguous, and cheap enough to throw away and rebuild when a gate fails:

```
1 Nitro-capable EC2 parent      1 P-256 KEY_AGREEMENT KMS key
1 EIF (not debug mode)          1 test archive, 10-25 v4 records
1 approver                      1 requester
```

**Do not put real plate data behind this until every gate passes.** A
deployment that passes eleven of twelve is not 92% secure; it has one
specific hole, and you now know which.

Run them in this order. The order matters: each one establishes a fact the
next depends on.

| # | Test | Expected | Evidence |
|---|---|---|---|
| 1 | Known-good enclave + valid authorization | **OPEN** | AWS |
| 2 | Parent calls `DeriveSharedSecret` with **no `Recipient`** | **AWS DENY** | **AWS only** |
| 3 | Parent calls with a **malformed or non-matching** attestation | **AWS DENY** | **AWS only** |
| 4 | Modified EIF | **AWS DENY** | **AWS only** |
| 5 | Valid enclave, wrong PCR configured in policy | **AWS DENY** | **AWS only** |
| 6 | Valid attested operation | `CiphertextForRecipient` present, `SharedSecret` **absent** | **AWS only** |
| 7 | Parent **copies a valid attestation document** and calls KMS itself | a response may return; the parent **cannot recover the secret** | **AWS only** |
| 8 | Ciphertext delivered to the wrong per-operation RSA key | **REFUSE** | local + AWS |
| 9 | One approval against every row | exactly one authorized row | local + AWS |
| 10 | `/index` enumeration from the disclosure side | zero useful tokens | local + AWS |
| 11 | Forged approval to `search-token` | zero tokens | local + AWS |
| 12 | Replay presence / approval | **REFUSE** | local + AWS |
| 13 | Cap race | never exceeds remaining uses | local + AWS |

### Test 7 is not about whether KMS answers

An earlier draft of this runbook had a gate reading *"parent direct call →
KMS denies"*, which conflated two different things and was wrong.

**KMS authorizes the attestation document. It does not authenticate the
network process as "the enclave."** A parent that copies a valid attestation
document out of a request and replays it may well receive a response — and
that is not a failure, because the response is `CiphertextForRecipient`,
encrypted to the recipient public key named *in that document*, whose private
half exists only inside the enclave.

So do not score this test on whether KMS returned something. Score it on the
invariant that actually matters:

- the response carries **no `SharedSecret`**, and
- the parent **cannot decrypt `CiphertextForRecipient`**

Attempt the decryption and record the failure. That is the real test of the
Recipient boundary, and it is why the custodian mints a **fresh RSA keypair
per operation**: a copied document names a key the parent does not hold, and
a captured ciphertext has no later operation to be replayed into.

### Tests 2–7 are the whole point

They are the only results that answer the threat-model question this stage
was opened to settle, and **they have no local equivalent that means
anything**. `tests/fake_kms.py` implements the documented semantics so the
JustiKey side is testable; it proves nothing whatever about AWS, because it
is a program this project wrote to agree with this project.

**Record tests 2–7 separately from the 421 local tests.** They are AWS
evidence. Mixing them into a test-count makes a claim about AWS that a test
count cannot support, which is the failure mode this whole review has been
about.

Tests 8–13 have local equivalents that pass
(`test_custodian.py`, `test_custodian_process.py`, `test_index_oracle.py`,
`test_transport.py`). Running them again on AWS confirms the deployment
wired up what the code does, not that the code does it.

### If a gate fails

- **2, 3 or 5 pass when they should deny** → the key policy is not doing what
  you think. Check for a default policy granting account root (§3), and check
  the condition landed with `aws kms get-key-policy`.
- **7 returns a response** → expected; that alone is not a failure. The
  failure is if the parent can *decrypt* it, or if `SharedSecret` is present.
- **4 passes when it should deny** → the PCRs in the policy are not this
  EIF's, or the enclave is in debug mode and reporting zeroes (§2).
- **6 returns a populated `SharedSecret`** → **stop.** That is not the
  attested path, and the plaintext secret has reached the parent. The
  custodian refuses this case (`custodian.py`), but a deployment where it
  happens is one where the attestation is not being applied at all.

### The evidence package

Keep it permanently. A gate that passed once, against an EIF whose
measurements you did not write down, is a gate you will have to run again and
cannot compare against.

For **each of tests 2–7**, record all seven of these:

| Field | Why it is in the bundle |
|---|---|
| exact EIF and PCR measurements, **and the enclave launch flags** | a `--debug-mode` enclave reports all-zero PCRs, so a denial from it proves nothing; without the flags an all-zero-PCR denial is indistinguishable from the intended policy working |
| KMS key ARN / key id, and the key-policy digest | which policy was actually in force, comparable later |
| SCP version or digest in effect | the administration boundary is not in the key policy (§3); this records whether the thing that makes it independent existed at the time |
| request outcome and timestamp | the result, and when |
| CloudTrail event id for each attempt | the independent record that the outcome came from AWS rather than from anything in this repository |
| on the valid attested path: whether `SharedSecret` was **absent** and `CiphertextForRecipient` **present** | the specific observation that separates a custodian from an expensive proxy |
| on denied paths: the KMS error code and message | that it denied *for the intended reason*, not incidentally |

That last column is the one most easily skipped and most worth having. A
denial for the wrong reason — a malformed request, a missing permission, an
expired signing certificate — looks identical in a pass/fail column to a
denial because the attestation did not match.

And for the run as a whole:

```
run date, operator
local suite: commit, test count, pass/fail
tests 1, 8-13: pass/fail
```

**If tests 2, 3, 4 and 5 deny for the intended reasons, test 6 returns only
`CiphertextForRecipient`, and test 7 shows the parent cannot decrypt what it
receives**, that is the first genuinely external
evidence in this project that the archive-walking oracle is blocked by a
boundary outside JustiKey itself. Everything before it is this repository
agreeing with this repository.

## 7. Migrating the production store

Only after every gate passes. This sequence has one irreversible step and it
is deliberately last.

```
  backup production store
        ↓
  verify the backup            restore it elsewhere and open a record
        ↓
  v3 integrity checks          record count, chain, credentials, sample opens
        ↓
  v3 → v4 ceremony             scripts/seal_store.py reseal-v4 --apply
        ↓
  verify                       counts + chain + credentials + sample opens
        ↓
  prove the X25519 key opens nothing
        ↓
  switch production disclosure to the attested custodian
        ↓
  ─────────────  only now  ─────────────
  destroy the v3 private key
```

```bash
# 3. integrity, before touching anything
python3 scripts/verify_audit.py --db justikey.db
python3 scripts/seal_store.py reseal-v4 --db justikey.db \
    --target-public-key "$CUSTODIAN_PUBLIC_HEX"          # dry run: the count

# 4. the reseal
python3 scripts/seal_store.py reseal-v4 --db justikey.db \
    --target-public-key "$CUSTODIAN_PUBLIC_HEX" --apply

# 5. verify: the same cases return the same records
python3 scripts/verify_audit.py --db justikey.db
```

**Keep the v3 private key available throughout.** The reseal needs it to read
each record once, and the post-migration verification needs it to prove it no
longer opens anything. It is the thing that makes the migration recoverable:
until verification succeeds, an interrupted or wrong reseal is a retry rather
than a loss.

**Destroying it is a separate decision, taken afterwards.** Not part of the
conversion, not automated by the ceremony, and not done on the same day
unless you are certain. `reseal-v4` deliberately does not destroy it: the
tool did not create that key and has no business ending it.

Rehearse the whole sequence on a **clone** of the production store first. The
local rehearsal of this ceremony found two bugs that no unit test had caught
— a missing column on a genuine v3 store, and a configuration precedence
error — and both surfaced only because the fixture was real rather than
constructed.

## 8. Operating it

**Rotating the enclave image.** With exact PCR pinning, a new EIF means a new
PCR0, so the key policy must be updated *before* the new enclave runs or it
cannot call KMS. Deploy in this order: build, record PCRs, add the new
measurement to the policy alongside the old, start the new enclave, verify,
stop the old one, remove the old measurement.

That is four policy edits per rebuild, each of which should be alarming
(§3) — which is exactly the friction that makes signed EIFs with PCR8 + PCR3
worth moving to once the acceptance run is behind you. A controlled signer
then authorises the new image and the key policy does not change at all.
Until then, expect rebuilds to be deliberate events rather than routine ones,
and do not paper over that by loosening the policy.

**Rotating the KMS key.** `recipient_key_id` in each envelope names its key
version, so historical records stay openable by a custodian holding the older
key. Do not delete an old key while records sealed to it exist — the envelope
tells you which are which.

**Losing the key ends the archive.** That is what the guarantee costs, and it
cuts both ways. Key deletion is irreversible after the waiting period; a
custodian key with a pending deletion is an archive with a countdown on it.

**Availability is a safety property.** If the enclave or KMS is unreachable,
lawful access stops. That is correct and deliberate: there is no fallback
path that opens records without the custodian, and the disclosure service
returns `disclosure_unavailable` rather than degrading.

---

## 9. What this runbook cannot promise

Everything above was written against AWS's documented behaviour and a local
test suite of 421 tests. The parts that depend on AWS actually behaving as
documented — tests 2 through 6 — have never been executed by this project.
`tests/fake_kms.py` implements those semantics so the JustiKey side is
testable, and proves nothing whatever about AWS: it is a program this project
wrote to agree with this project.

Run the suite on a throwaway key and a throwaway archive first. If test 3 or
test 6 does not behave as this document says, **stop** and re-read the
current AWS documentation before going further. Those two are the difference
between a custodian and an expensive proxy.

One more thing this runbook cannot do: it cannot tell you that the
administration boundary in §3 is enforced in *your* organization. The SCP
belongs to whoever governs the account, and this document has no way to check
that it exists. Confirm it, and record the answer in the evidence.
