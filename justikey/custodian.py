"""The custodian: the key holder that protects the *operation*.

Stage 5 of docs/capability-model.md. See docs/stage-5-key-isolation.md for
how this design was arrived at.

WHY A NON-EXPORTABLE KEY IS NOT ENOUGH

The obvious reading of stage 5 is: create a non-exportable key in a KMS, have
the disclosure service call `DeriveSharedSecret` instead of holding the
private half, done. It is not done. A compromised disclosure service still
holds every sealed row -- including each record's `ephemeral_pub` -- and
credentials to call the KMS. It calls once per record, with that record's own
ephemeral key, and receives the secret that opens it. Walk the table; the
archive is gone. The key never left the KMS.

**Raw ECDH is the unrestricted oracle.** Non-exportability stops exfiltration
of the key and does nothing about that, which is why the stated objective has
two clauses and only the first is bought by procurement.

    KMS protects the key.  The custodian protects the operation.

So the operation offered here is deliberately *not*:

    derive_shared_secret(ephemeral_pub)          # the oracle, restated

but:

    open(sealed_record, identity, approval, presence, registry_versions)

and the custodian independently reconstructs and verifies every fact the
disclosure service was also supposed to check -- record identity, the scope
the approver actually signed, the requester's proof of presence, freshness,
single use, remaining capacity, registry versions, key id, suite -- before it
will agree to anything at all. Two principals must both be wrong, in the same
way, for one record to open.

WHAT THE BACKENDS ARE

`LocalAgreement` holds a software private key. It is for development, for
tests, and as the reference the hardware path is checked against; it does not
meet the stage 5 objective and says so.

`KmsAgreement` calls AWS KMS `DeriveSharedSecret` on an `ECC_NIST_P256` key
created with `KeyUsage=KEY_AGREEMENT`. With an attestation provider set it
runs the hardened Nitro sequence, per operation:

    1. generate an RSA-2048 recipient keypair inside the enclave
    2. ask the NSM for an attestation document carrying its public key
    3. call DeriveSharedSecret with the record's ephemeral P-256 key and
       Recipient = that document
    4. require CiphertextForRecipient non-empty AND SharedSecret empty
    5. decrypt the CMS envelope with the recipient private key
    6. HKDF, then AEAD open, erasing what can be erased

The KMS key policy can require a specific enclave measurement
(`kms:RecipientAttestation:ImageSha384` / PCRs), so a call from a compromised
parent process without a matching attestation document is refused by KMS
itself rather than by anything in this file. The NSM signs the attestation
document; it does not decrypt anything -- see justikey/enclave.py.

That last point is the one worth being careful about: it is the only control
here that does not depend on this code being correct.
"""
import hashlib

from . import (approvals, custody, kem, presence, registry, sealing,  # noqa: F401
               timeutil)

CONTEXT_VERSION = 1


class CustodianError(RuntimeError):
    """The custodian refused. Nothing was derived and nothing was opened."""


class AgreementUnavailable(CustodianError):
    """The backend could not be reached. Fails closed, never falls back."""


# ---------------------------------------------------------------------------
# Client: the disclosure service's view of a custodian in another process
# ---------------------------------------------------------------------------

# Operations the custodian offers. Anything else is refused by name, at the
# boundary, before a handler sees it -- the oracle restated as an operation
# is exactly what stage 5 removes.
OPERATIONS = ("index", "open")


class RemoteCustodian:
    """Calls a custodian running as its own process and principal.

    Exposes `open` and `blind_index` and nothing else, because those are the
    only two things the custodian offers. Notably absent is any way to ask for
    key material: there is nothing to add here that the remote end does not
    already refuse, and a convenience method that looked like one would
    misrepresent the boundary.

    Nothing this client sends is trusted by the far end. It re-verifies the
    approval, re-derives scope from its own index key, and spends the nonces
    itself -- so a compromised disclosure service gains nothing by lying here.
    """

    def __init__(self, transport=None, url=None, client_id=None,
                 client_secret=None, timeout=None):
        """Takes a transport, or builds an HTTP one from a URL.

        The transport decides framing and isolation and nothing else. Swapping
        HTTP for vsock must not change a single authorization decision, which
        is why the checks all live on the far side of it.
        """
        from . import transport as _transport

        if transport is None:
            if not url:
                raise CustodianError("a custodian needs a transport or a URL")
            transport = _transport.for_url(url, client_id, client_secret, timeout)
        self.transport = transport
        self._key_info = None

    def _call(self, operation, payload):
        from . import transport as _transport

        try:
            reply, status = self.transport.request(operation, payload)
        except _transport.TransportError as exc:
            # Unreachable is a clean refusal, never "open it anyway".
            raise AgreementUnavailable(f"custodian unreachable: {exc}") from exc
        if status == 200:
            return reply
        detail = str(reply.get("error", reply))[:300]
        if status == 503:
            raise AgreementUnavailable(
                f"the custodian could not reach its key holder: {detail}")
        raise CustodianError(f"the custodian refused ({status}): {detail}")

    def key_info(self):
        if self._key_info is None:
            self._key_info = self._call("publickey", {})
        return self._key_info

    def blind_index(self, plate):
        """A token for an arbitrary plate. Ingest path only.

        Reserved to a credential the disclosure host does not hold: a caller
        with the sealed archive and this operation maps every row without
        opening one. See `search_token` for what the disclosure host uses.
        """
        return self._call("index", {"plate": plate})["plate_index"]

    def search_token(self, statement, signature, registry_versions=None):
        """A token for exactly the plate an approver signed for.

        The custodian verifies the approval before a token exists, so this
        cannot be turned into an enumeration oracle: the only scopes it will
        answer for are ones an approver independently authorised. It spends
        nothing -- `open` remains the single transactional point, so a search
        that finds nothing costs the requester nothing.
        """
        return self._call("search-token", {
            "statement": statement, "signature": signature,
            "registry_versions": registry_versions})["plate_index"]

    def open(self, envelope, identity, statement, signature, requester,
             proof_statement=None, proof=None, registry_versions=None):
        return self._call("open", {
            "envelope": {k: envelope.get(k) for k in ENVELOPE_FIELDS},
            "identity": identity,
            "statement": statement,
            "signature": signature,
            "requester": requester,
            "presence": proof_statement,
            "presence_proof": proof,
            "registry_versions": registry_versions,
        })


ENVELOPE_FIELDS = ("record_uid", "seal_version", "seal_kem", "recipient_key_id",
                   "record_ct", "wrapped_key", "ephemeral_pub")


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

class LocalAgreement:
    """A software private key. Development and reference only."""

    meets_stage_5 = False
    backend = "local"

    def __init__(self, private_hex, kem_name=None):
        self.kem = kem_name or kem.DEFAULT_KEM
        suite = kem.suite(self.kem)
        self._private = suite.private_from_bytes(bytes.fromhex(private_hex))
        self.public_raw = suite.public_bytes(self._private.public_key())
        self.key_id = kem.key_id(self.kem, self.public_raw)
        self.legacy_key_id = sealing.legacy_key_id(self.public_raw.hex())

    def accepts(self, recipient_key_id):
        return recipient_key_id in (self.key_id, self.legacy_key_id)

    def agree(self, peer_public_raw):
        """Validated inside the suite -- an off-curve point never reaches the
        scalar multiplication."""
        return kem.suite(self.kem).agree(self._private, peer_public_raw)


class KmsAgreement:
    """AWS KMS `DeriveSharedSecret` on a non-exportable P-256 agreement key.

    `client` is anything exposing `derive_shared_secret(**kwargs)` -- a boto3
    KMS client in production, and in tests a stand-in that enforces the same
    policy semantics, including refusing a call whose attestation does not
    match.

    `recipient` is the Nitro attestation document plus encryption algorithm.
    When it is set, KMS returns the secret encrypted to the enclave and
    `SharedSecret` comes back empty; `enclave_decrypt` is then what turns
    `CiphertextForRecipient` back into bytes, inside the enclave. A custodian
    configured with a recipient but no way to decrypt for it is a
    misconfiguration, not a degraded mode, and is refused at construction.
    """

    backend = "aws-kms"

    def __init__(self, client, key_arn, public_raw, kem_name=None,
                 recipient=None, enclave_decrypt=None, legacy_key_id=None,
                 attestation=None):
        self.kem = kem_name or kem.P256_ECDH
        if self.kem != kem.P256_ECDH:
            raise CustodianError(
                f"AWS KMS key agreement is NIST ECC only; {self.kem!r} is not "
                f"available. See docs/stage-5-key-isolation.md.")
        if recipient is not None and enclave_decrypt is None and attestation is None:
            raise CustodianError(
                "a recipient attestation was configured but no way to decrypt "
                "for it: KMS will return an empty SharedSecret and nothing here "
                "could use the result")
        self._client = client
        self._recipient = recipient
        self._enclave_decrypt = enclave_decrypt
        # The hardened path: an attestation provider mints a FRESH recipient
        # keypair per operation and asks for a document carrying its public
        # key. A captured CiphertextForRecipient is then useless outside the
        # single operation that requested it.
        self._attestation = attestation
        self.key_arn = key_arn
        self.public_raw = public_raw
        self.key_id = kem.key_id(self.kem, public_raw)
        self.legacy_key_id = legacy_key_id
        # Attested calls are the only configuration that meets the objective:
        # without one, a compromised parent holding the same IAM credentials
        # can make the same call.
        self.meets_stage_5 = recipient is not None or attestation is not None

    def accepts(self, recipient_key_id):
        return recipient_key_id in (self.key_id, self.legacy_key_id)

    def agree(self, peer_public_raw):
        # Validate before the call, not after. An off-curve point is refused
        # here so it never becomes a KMS request at all -- KMS would refuse it
        # too, but a control that depends on someone else's validation is not
        # a control this project can test.
        kem.P256Suite.validate_peer_public(peer_public_raw)
        request = {
            "KeyId": self.key_arn,
            "KeyAgreementAlgorithm": "ECDH",
            "PublicKey": _spki(peer_public_raw),
        }
        # A recipient key that exists only for this call.
        recipient, recipient_key = self._recipient, None
        if self._attestation is not None:
            from . import enclave

            try:
                recipient, recipient_key = enclave.recipient_for(self._attestation)
            except enclave.EnclaveError as exc:
                raise AgreementUnavailable(
                    f"could not prepare an attested request: {exc}") from exc
        if recipient is not None:
            request["Recipient"] = recipient

        try:
            response = self._client.derive_shared_secret(**request)
        except Exception as exc:  # noqa: BLE001 - includes AccessDenied
            raise AgreementUnavailable(
                f"the key custodian refused or could not be reached: {exc}") from exc

        if recipient is not None:
            blob = response.get("CiphertextForRecipient")
            if not blob:
                raise CustodianError(
                    "an attested agreement returned no ciphertext for the enclave; "
                    "refusing rather than falling back to an unattested path")
            if response.get("SharedSecret"):
                # KMS returns an empty SharedSecret for attested calls. A
                # populated one means this is not the attested path we think
                # it is, and the plaintext secret just reached the parent.
                raise CustodianError(
                    "an attested agreement also returned a plaintext shared secret; "
                    "this is not the attested path and must not be trusted")
            if recipient_key is not None:
                from . import enclave

                try:
                    return recipient_key.decrypt(blob)
                except enclave.EnclaveError as exc:
                    # A response encrypted to some other enclave's key, or to
                    # an earlier operation's key, lands here. Binding the
                    # recipient key to one operation is what makes that
                    # detectable rather than merely unlikely.
                    raise CustodianError(
                        f"the KMS response was not encrypted to this operation's "
                        f"recipient key: {exc}") from exc
            return self._enclave_decrypt(blob)

        secret = response.get("SharedSecret")
        if not secret:
            raise CustodianError("the key custodian returned no shared secret")
        return secret


def _spki(public_raw):
    """SubjectPublicKeyInfo DER for an uncompressed P-256 point.

    KMS takes SPKI, the envelope stores the raw SEC1 point, and the
    conversion is a fixed 26-byte prefix for this one curve and encoding --
    so it is written out rather than pulling in a general encoder for a
    single constant.
    """
    kem.P256Suite.validate_peer_public(public_raw)
    prefix = bytes.fromhex(
        "3059301306072a8648ce3d020106082a8648ce3d030107034200")
    return prefix + bytes(public_raw)


# ---------------------------------------------------------------------------
# The operation
# ---------------------------------------------------------------------------

def disclosure_context(envelope, statement, proof_statement, registry_versions):
    """Everything an agreement is bound to, as one canonical value.

    Hashed into the KDF, so a secret derived for one record under one
    approval cannot be reused for any other -- even by a caller who obtained
    it legitimately.
    """
    import json
    return json.dumps({
        "v": CONTEXT_VERSION,
        "record_uid": envelope.get("record_uid"),
        "recipient_key_id": envelope.get("recipient_key_id"),
        "kem": envelope.get("seal_kem") or kem.X25519_ECDH,
        "seal_version": envelope.get("seal_version"),
        "approval_nonce": (statement or {}).get("nonce"),
        "statement_digest": presence.statement_digest(statement) if statement else None,
        "presence_nonce": (proof_statement or {}).get("request_nonce"),
        "registry_versions": registry_versions or {},
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


class Custodian:
    """Verifies the whole disclosure context, then agrees exactly once.

    Constructed with its own copies of the approver and requester registries.
    Taking them from the caller would make the second opinion an echo of the
    first, which is the entire value being added.
    """

    def __init__(self, agreement, approvers=None, requesters=None, usage=None,
                 max_disclosures=None, presence_mode="required",
                 accepted_kems=None, registry_versions=None):
        self.agreement = agreement
        self.approvers = approvers or {}
        self.requesters = requesters or {}
        self.usage = usage
        from . import config
        self.max_disclosures = (config.MAX_DISCLOSURES_PER_AUTHORIZATION
                                if max_disclosures is None else max_disclosures)
        self.presence_mode = presence_mode
        self.accepted_kems = tuple(accepted_kems or (kem.P256_ECDH,))
        self.registry_versions = registry_versions or {}

    # -- the checks, each its own refusal ---------------------------------

    def _check_envelope(self, envelope, identity):
        for field in ("record_uid", "seal_version", "recipient_key_id",
                      "record_ct", "wrapped_key", "ephemeral_pub"):
            if not envelope.get(field):
                raise CustodianError(f"sealed record is missing {field}")

        try:
            suite_name = sealing.envelope_suite(envelope)
        except sealing.SealingError as exc:
            raise CustodianError(str(exc)) from exc
        if suite_name not in self.accepted_kems:
            raise CustodianError(
                f"record names suite {suite_name!r}, which this custodian does "
                f"not accept ({', '.join(self.accepted_kems)})")
        if not self.agreement.accepts(envelope["recipient_key_id"]):
            raise CustodianError(
                f"record was sealed to key {envelope['recipient_key_id']!r}, which "
                f"this custodian does not hold")

        # Validate the peer point here, as part of deciding whether the
        # envelope is well formed at all -- not later, next to the agreement.
        # An off-curve point must never reach a scalar multiplication, and a
        # malformed one must not cost the requester a use of their approval.
        try:
            kem.suite(suite_name).validate_peer_public(
                sealing._unb64(envelope["ephemeral_pub"]))
        except (kem.KemError, ValueError, TypeError) as exc:
            raise CustodianError(
                f"the record's ephemeral key is not usable: {exc}") from exc

        # Identity is supplied separately from the envelope and must agree:
        # the AAD binds them, but checking here means a mismatch is a named
        # refusal rather than an opaque tag failure.
        for field in ("record_uid", "captured_at", "camera_id", "plate_index"):
            if field == "record_uid":
                if identity.get(field) != envelope.get("record_uid"):
                    raise CustodianError("record identity does not match the envelope")
            elif field not in identity:
                raise CustodianError(f"record identity is missing {field}")
        return suite_name

    def _check_registries(self, claimed):
        """Refuse a caller working from registry state older than ours."""
        for role, version in (self.registry_versions or {}).items():
            presented = (claimed or {}).get(role)
            if presented is None:
                raise CustodianError(
                    f"the caller did not state which {role} registry version it used")
            if presented != version:
                raise CustodianError(
                    f"the caller used {role} registry v{presented}; this custodian "
                    f"holds v{version}. Refusing rather than opening a record "
                    f"against policy state one side has not seen.")

    def _approver_key(self, username):
        entry = self.approvers.get(username)
        if entry is None:
            raise CustodianError(f"approver {username!r} is not enrolled with the custodian")
        if entry.get("revoked"):
            raise CustodianError(f"approver {username!r}'s key has been revoked")
        return entry["public_key"]

    def _check_approval(self, statement, signature, requester):
        if not isinstance(statement, dict):
            raise CustodianError("malformed approval statement")
        if statement.get("v") != approvals.STATEMENT_VERSION:
            raise CustodianError(f"unsupported approval schema {statement.get('v')!r}")
        for field in ("authorization_id", "target_plate", "window_start", "window_end",
                      "requester", "approver", "approved_at", "approval_expires_at",
                      "nonce", "approver_key_id"):
            if not statement.get(field):
                raise CustodianError(f"approval statement is missing {field}")

        public_hex = self._approver_key(statement["approver"])
        if approvals.signing_key_id(public_hex) != statement["approver_key_id"]:
            raise CustodianError("approval names a different signing key than the enrolled one")
        if statement["approver"] == statement["requester"]:
            raise CustodianError("self-approval: requester and approver are the same person")
        if statement["requester"] != requester:
            raise CustodianError("this approval belongs to another requester")
        if not approvals.verify_statement(public_hex, statement, signature):
            raise CustodianError("approval signature does not cover this request")

        now = timeutil.now_iso()
        if now > statement["approval_expires_at"]:
            raise CustodianError("approval has expired")
        if statement["approved_at"] > now:
            raise CustodianError("approval is dated in the future")

    def _check_scope(self, envelope, identity, statement, blind_index_of):
        """Re-derive scope. Never accept the caller's claim that a record is
        in scope -- that claim is exactly what a compromised caller forges."""
        target_index = blind_index_of(statement["target_plate"])
        if identity["plate_index"] != target_index:
            raise CustodianError("this record is not the plate the approval covers")
        if not (statement["window_start"] <= identity["captured_at"]
                <= statement["window_end"]):
            raise CustodianError("this record is outside the approved time window")

    def _check_presence(self, statement, requester, proof_statement, proof):
        if self.presence_mode == "off":
            return None
        entry = self.requesters.get(requester)
        if entry is None:
            if self.presence_mode == "required":
                raise CustodianError(
                    f"requester {requester!r} is not enrolled with the custodian, and "
                    f"proof of presence is required")
            return None
        credential = custody.credential_from_registry(entry)
        if not proof_statement or not proof:
            raise CustodianError("this disclosure needs proof that the requester is present")
        try:
            return presence.verify(credential, proof_statement, proof, statement, requester)
        except presence.PresenceError as exc:
            raise CustodianError(str(exc)) from exc

    # -- the one public operation -----------------------------------------

    def open(self, envelope, identity, statement, signature, requester,
             proof_statement=None, proof=None, registry_versions=None,
             blind_index_of=None):
        """Open one record, or refuse. There is no other entry point.

        Note what is absent: no way to ask for an agreement on its own, no way
        to open a record the caller merely asserts is in scope, and no way to
        open more than one record per verified approval-and-presence pair.
        """
        if blind_index_of is None:
            raise CustodianError(
                "the custodian needs its own scope function; accepting the "
                "caller's idea of which records match would restore the oracle")

        self._check_registries(registry_versions)
        suite_name = self._check_envelope(envelope, identity)
        self._check_approval(statement, signature, requester)
        self._check_scope(envelope, identity, statement, blind_index_of)
        proved = self._check_presence(statement, requester, proof_statement, proof)

        # Spend before deriving. A refusal after the agreement would mean the
        # secret existed for a request that was not allowed to have it.
        if self.usage is not None:
            ok, count, reason = self.usage.claim(
                statement["nonce"], statement.get("authorization_id"),
                statement["approval_expires_at"], self.max_disclosures,
                presence_nonce=(proved or {}).get("request_nonce"),
                presence_expires_at=(proof_statement or {}).get("expires_at"))
            if not ok:
                raise CustodianError(reason)
        else:
            count = None

        context = disclosure_context(envelope, statement, proof_statement,
                                     registry_versions)
        try:
            shared = self.agreement.agree(sealing._unb64(envelope["ephemeral_pub"]))
        except kem.KemError as exc:
            raise CustodianError(f"the record's ephemeral key is not usable: {exc}") from exc

        aad = sealing.aad_for(envelope, identity["captured_at"], identity["camera_id"],
                              identity["plate_index"])
        try:
            record_key = sealing.unwrap_record_key(envelope, aad, shared)
            fields = sealing.open_with_record_key(envelope, aad, record_key)
        except Exception as exc:  # noqa: BLE001 - any failure means "do not reveal"
            raise CustodianError(f"could not open the sealed record: {exc!r}") from exc

        return {"fields": fields, "use_count": count,
                "presence": (proved or {}).get("custody", "none"),
                "context_digest": hashlib.sha256(context).hexdigest()[:16],
                "suite": suite_name, "backend": self.agreement.backend}
