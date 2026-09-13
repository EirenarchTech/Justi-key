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
FROM public.ecr.aws/amazonlinux/amazonlinux:2023
RUN dnf install -y python3 python3-pip && dnf clean all
RUN pip3 install --no-cache-dir cryptography==41.0.7 boto3
COPY justikey/ /opt/justikey/justikey/
COPY scripts/custodian_server.py /opt/justikey/scripts/
WORKDIR /opt/justikey
# vsock only. The server refuses to start a TCP listener when attested.
CMD ["python3", "scripts/custodian_server.py", "--transport", "vsock", "--attest"]
```

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

Three things about this policy are deliberate:

- **`kms:DeriveSharedSecret` is the only cryptographic action granted.** Not
  `kms:*`. The key can agree and do nothing else.
- **The condition applies to the parent's role**, which is the principal that
  signs the request — the attestation document is what distinguishes an
  enclave call from a parent call using the same credentials.
- **The administrator statement grants no cryptographic use.** Whoever can
  change the policy cannot use the key; whoever can use the key cannot change
  the policy. If one role held both, pinning the measurement would be
  advisory.

> **The default key policy will undo this.** If you create the key without
> `--policy`, AWS attaches a default that grants the account root full
> access, and the attestation condition becomes decoration. Create it with
> the policy, and check with `aws kms get-key-policy` afterwards.

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

Move these into the enclave at launch (through the enclave's own
configuration mechanism, not the filesystem — it has none):

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

## 6. Acceptance gates

**Do not put real plate data behind this until every gate passes.** Each one
is a distinct failure mode; a deployment that passes nine of ten is not 90%
secure, it has one specific hole.

| # | Gate | How to check | Expected |
|---|---|---|---|
| 1 | EIF built and PCRs recorded | `nitro-cli build-enclave` output saved with the EIF's SHA-256 | PCR0/1/2 recorded, rebuild reproduces them |
| 2 | KMS policy pinned to the measurement | `aws kms get-key-policy` | condition present; no default policy granting root `kms:*` |
| 3 | Approved EIF succeeds | run a real disclosure end to end | record opens |
| 4 | Modified EIF denied | rebuild with any change, rerun | `AccessDeniedException` from KMS |
| 5 | Parent direct call denied | call `DeriveSharedSecret` from the parent with no `Recipient` | `AccessDeniedException` |
| 6 | Recipient behaviour | inspect a `DeriveSharedSecret` response | `SharedSecret` **empty**, `CiphertextForRecipient` present |
| 7 | Wrong recipient key refused | replay a `CiphertextForRecipient` into a later operation | CMS open refused |
| 8 | Archive walk | one approval, iterate every sealed row | only the approved record opens |
| 9 | No TCP listener | `ss -ltnp` inside the parent; try `--transport http` while attested | no listener; server exits 4 |
| 10 | Scope-token oracle closed | ask the custodian for `index` with the disclosure credential | refused; `search-token` answers only for an approved scope |
| 11 | vsock `/open` succeeds | the end-to-end disclosure in gate 3 | success over AF_VSOCK |
| 12 | Registry rollback refused | restore an older registry file, restart | custodian exits 3 |

Gates 7, 8, 10 and 12 have equivalents in the local suite
(`tests/test_custodian.py`, `test_custodian_process.py`, `test_index_oracle.py`)
that pass against a stand-in implementing the documented KMS semantics.
**Gates 4, 5 and 6 have no local equivalent that means anything** — they are
assertions about AWS, and only AWS can answer them.

### Recording the result

Keep the output. A gate that passed once, on an EIF whose PCRs you did not
write down, is a gate you will have to run again and cannot compare against.

```
date, EIF sha256, PCR0, PCR1, PCR2, key ARN, key policy sha256,
gate 1..12 pass/fail, operator
```

---

## 7. Operating it

**Rotating the enclave image.** New EIF → new PCR0 → update the key policy
*before* replacing the running enclave, or the new one cannot call KMS.
Deploy in this order: build, record PCRs, add the new measurement to the
policy alongside the old, start the new enclave, verify, stop the old one,
remove the old measurement.

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

## 8. What this runbook cannot promise

Everything above was written against AWS's documented behaviour and the local
test suite. The parts that depend on AWS actually behaving as documented —
gates 4, 5 and 6 — have never been executed by this project. `tests/fake_kms.py`
implements those semantics so the JustiKey side is testable, and proves
nothing whatever about AWS.

Run the gates on a throwaway key and a throwaway archive first. If gate 5 or
gate 6 does not behave as this document says, **stop** and re-read the
current AWS documentation before going further: those two gates are the
difference between a custodian and an expensive proxy.
