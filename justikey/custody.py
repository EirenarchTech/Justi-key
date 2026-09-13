"""Where a private key lives, expressed as one verifiable proof format.

Stage 4 of docs/capability-model.md.

Stages 1-3 have exactly one kind of signature: Ed25519 over a canonical
statement, with the private key wrapped under the signer's password. That is
a real control -- the server can sign only while the person is typing -- and
it has a fixed ceiling: the key passes through this process, so an attacker
already inside gets it at that moment.

Hardware custody removes the ceiling but changes the shape of the evidence. A
WebAuthn authenticator does not sign your document; it signs a challenge,
wrapped in its own attestation of what the user did. So the stored proof is
no longer a bare signature, and verification needs the authenticator data and
client data alongside it.

Rather than fork every call site into "software path" and "hardware path",
both become a **proof envelope** over the same canonical statement:

    {"alg": "ed25519",  "sig": "<hex>"}
    {"alg": "webauthn", "credential_id": ..., "authenticator_data": ...,
                        "client_data_json": ..., "signature": ...}

`verify_proof` dispatches on `alg` and returns the same answer either way, so
a deployment can move one approver at a time onto hardware without a second
verification path -- and, more to the point, without a second set of bugs.

Legacy bare hex signatures are still accepted as `ed25519`, because
approvals written before this module exists are genuine approvals and
refusing them would rewrite history rather than verify it.
"""
import hashlib
import json

from . import sealing, timeutil, webauthn

ALG_ED25519 = "ed25519"
ALG_WEBAUTHN = "webauthn"

try:  # pragma: no cover
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
    CUSTODY_AVAILABLE = True
except ImportError:  # pragma: no cover
    InvalidSignature = Exception
    _ed25519 = None
    CUSTODY_AVAILABLE = False


class CustodyError(RuntimeError):
    """A proof was absent, malformed, or did not verify."""


# ---------------------------------------------------------------------------
# Envelopes
# ---------------------------------------------------------------------------

def ed25519_proof(signature_hex):
    return {"alg": ALG_ED25519, "sig": signature_hex}


def webauthn_proof(assertion):
    return dict(assertion, alg=ALG_WEBAUTHN)


def encode_proof(proof):
    """Serialize for storage in a TEXT column."""
    return json.dumps(proof, sort_keys=True, separators=(",", ":"))


def decode_proof(stored):
    """Parse a stored proof, tolerating the legacy bare-hex form.

    Before this module, an approval's signature column held a hex string and
    nothing else. Those approvals were validly made and must keep verifying,
    so a value that is not a proof envelope is read as what it was.
    """
    if not stored:
        raise CustodyError("no proof was supplied")
    if isinstance(stored, dict):
        proof = stored
    else:
        text = stored.strip()
        if not text.startswith("{"):
            return ed25519_proof(text)
        try:
            proof = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CustodyError(f"malformed proof envelope: {exc}") from exc
    if not isinstance(proof, dict) or "alg" not in proof:
        raise CustodyError("proof envelope names no algorithm")
    return proof


# ---------------------------------------------------------------------------
# Credentials: what a registry stores about a principal's key
# ---------------------------------------------------------------------------

def software_credential(public_hex):
    return {"alg": ALG_ED25519, "public_key": public_hex}


def webauthn_credential(credential_id, public_key, sign_count=0, rp_id=None, origin=None):
    return {"alg": ALG_WEBAUTHN, "credential_id": credential_id,
            "public_key": public_key, "sign_count": sign_count,
            "rp_id": rp_id, "origin": origin}


def credential_from_registry(entry, rp_id=None, origin=None):
    """Read a registry entry into a credential, whichever custody it uses.

    A registry entry is what the *verifier* holds about a principal -- never
    anything the caller supplied with the request. Entries carrying
    `webauthn` describe a key the server has never possessed.
    """
    if not isinstance(entry, dict):
        raise CustodyError("malformed registry entry")
    if entry.get("revoked"):
        raise CustodyError("this signing key has been revoked")

    hardware = entry.get("webauthn")
    if hardware:
        if not hardware.get("credential_id") or not hardware.get("public_key"):
            raise CustodyError("webauthn enrolment is missing its credential")
        return webauthn_credential(
            hardware["credential_id"], hardware["public_key"],
            hardware.get("sign_count") or 0,
            hardware.get("rp_id") or rp_id, hardware.get("origin") or origin)
    if not entry.get("public_key"):
        raise CustodyError("registry entry carries no public key")
    return software_credential(entry["public_key"])


def is_hardware(credential):
    return credential.get("alg") == ALG_WEBAUTHN


def credential_key_id(credential):
    """Short identifier for the key a statement names.

    A statement says which key is expected to have signed it, so that
    swapping in a different enrolled key is a mismatch rather than a silent
    substitution. Software keys keep the identifier they already had, so
    existing approvals keep verifying; hardware credentials are identified by
    their credential id, which is the only stable public handle an
    authenticator gives us.
    """
    if is_hardware(credential):
        return hashlib.sha256(
            b"justikey:webauthn-credential:v1"
            + credential["credential_id"].encode("utf-8")).hexdigest()[:16]
    return sealing.key_id(credential["public_key"])


# ---------------------------------------------------------------------------
# Sign and verify
# ---------------------------------------------------------------------------

def sign(private_key, message):
    """Software signing. Hardware never reaches this function by design."""
    if not CUSTODY_AVAILABLE:
        raise CustodyError("signing requires the 'cryptography' package")
    return ed25519_proof(private_key.sign(message).hex())


def verify_proof(credential, message, proof, require_user_verification=True):
    """Check a proof over `message`. Returns a dict describing what was proved.

    The result carries `custody` ('software' or 'hardware') and, for
    hardware, the sign count the caller must persist. Callers that record who
    authorized something should record which custody it was: an audit trail
    that cannot distinguish a password-wrapped key from a touched security
    key is describing two different events with one word.
    """
    proof = decode_proof(proof)
    algorithm = proof.get("alg")

    if algorithm == ALG_ED25519:
        if is_hardware(credential):
            # Downgrade. The whole point of enrolling hardware is that a
            # software signature is no longer sufficient for this principal.
            raise CustodyError(
                "this principal is enrolled with a hardware authenticator, so a "
                "software signature is not accepted")
        if not CUSTODY_AVAILABLE:
            raise CustodyError("verification requires the 'cryptography' package")
        public_hex, signature_hex = credential.get("public_key"), proof.get("sig")
        if not public_hex or not signature_hex:
            raise CustodyError("proof or credential is missing key material")
        try:
            public = _ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
            public.verify(bytes.fromhex(signature_hex), message)
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise CustodyError("signature does not cover this statement") from exc
        return {"custody": "software", "alg": ALG_ED25519, "verified_at": timeutil.now_iso()}

    if algorithm == ALG_WEBAUTHN:
        if not is_hardware(credential):
            raise CustodyError(
                "this principal has no hardware authenticator enrolled, so a "
                "WebAuthn assertion cannot be checked against a key we hold")
        rp_id, origin = credential.get("rp_id"), credential.get("origin")
        if not rp_id or not origin:
            raise CustodyError(
                "no relying-party id or origin is configured, so an assertion "
                "cannot be bound to this deployment")
        try:
            sign_count = webauthn.verify_assertion(
                credential, proof, webauthn.challenge_for(message), rp_id, origin,
                require_user_verification=require_user_verification)
        except webauthn.WebAuthnError as exc:
            raise CustodyError(str(exc)) from exc
        return {"custody": "hardware", "alg": ALG_WEBAUTHN, "sign_count": sign_count,
                "credential_id": credential["credential_id"],
                "verified_at": timeutil.now_iso()}

    raise CustodyError(f"unsupported proof algorithm {algorithm!r}")
