"""A stand-in for AWS KMS, enforcing the policy semantics we depend on.

Not a simulator of KMS in general -- it implements one operation,
DeriveSharedSecret on an ECC_NIST_P256 KEY_AGREEMENT key, with the specific
behaviours the stage 5 design relies on:

  * the private key never leaves this object, as it never leaves KMS
  * with `Recipient`, the derived secret is returned ONLY as
    CiphertextForRecipient and `SharedSecret` comes back empty
  * the key policy may require an enclave measurement
    (kms:RecipientAttestation:ImageSha384), and a call whose attestation does
    not match is refused with AccessDeniedException -- including an
    unattested call from a parent process holding the same credentials
  * a measurement can be revoked, so a previously-approved image stops working

What this cannot do is prove AWS behaves this way; the documentation says it
does, and the tests here prove JustiKey behaves correctly *given* that. The
boundary between the two is stated in docs/stage-5-key-isolation.md.
"""
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from justikey import kem  # noqa: E402


class AccessDeniedException(Exception):
    """What KMS raises when the key policy refuses the call."""


class FakeKms:
    def __init__(self, allowed_image_sha384=None, key_arn="arn:aws:kms:test:key/agree"):
        suite = kem.P256Suite
        self._private, self.public_raw = suite.generate()
        self.key_arn = key_arn
        # None means "no attestation condition on the key policy": any caller
        # with the IAM permission may call, attested or not.
        self.allowed_image_sha384 = allowed_image_sha384
        self.revoked_images = set()
        self.calls = []

    # -- enclave side ------------------------------------------------------

    @staticmethod
    def attestation(image_sha384):
        """What an enclave presents. Real documents are CBOR/COSE; the only
        property under test here is which image made the call."""
        return {"AttestationDocument": image_sha384.encode("utf-8"),
                "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256"}

    @staticmethod
    def enclave_decrypt(blob):
        """Stands in for decrypting CiphertextForRecipient inside the enclave."""
        if not blob.startswith(b"for-enclave:"):
            raise ValueError("not a ciphertext for this enclave")
        return bytes.fromhex(blob[len(b"for-enclave:"):].decode("ascii"))

    # -- the KMS operation -------------------------------------------------

    def derive_shared_secret(self, KeyId=None, KeyAgreementAlgorithm=None,
                             PublicKey=None, Recipient=None):
        self.calls.append({"key": KeyId, "attested": Recipient is not None})
        if KeyId != self.key_arn:
            raise AccessDeniedException(f"no such key: {KeyId}")
        if KeyAgreementAlgorithm != "ECDH":
            raise AccessDeniedException(
                f"unsupported key agreement algorithm {KeyAgreementAlgorithm!r}")

        image = None
        if Recipient is not None:
            image = Recipient["AttestationDocument"].decode("utf-8")
            if image in self.revoked_images:
                raise AccessDeniedException(
                    "AccessDeniedException: the attested image has been revoked")

        if self.allowed_image_sha384 is not None:
            # kms:RecipientAttestation:ImageSha384 on the key policy.
            if Recipient is None:
                raise AccessDeniedException(
                    "AccessDeniedException: the key policy requires "
                    "kms:RecipientAttestation:ImageSha384 and this call carried "
                    "no attestation document")
            if image != self.allowed_image_sha384:
                raise AccessDeniedException(
                    "AccessDeniedException: attestation image does not match "
                    "kms:RecipientAttestation:ImageSha384")

        peer = kem.P256Suite.validate_peer_public(_from_spki(PublicKey))
        secret = self._private.exchange(_ecdh(), peer)

        if Recipient is not None:
            # KMS encrypts to the enclave and returns no plaintext secret.
            return {"SharedSecret": b"",
                    "CiphertextForRecipient": b"for-enclave:" + secret.hex().encode("ascii"),
                    "KeyId": KeyId}
        return {"SharedSecret": secret, "KeyId": KeyId}


def _ecdh():
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.ECDH()


def _from_spki(der):
    """Recover the raw point from the SPKI the custodian sends."""
    prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
    if not der.startswith(prefix):
        raise AccessDeniedException("public key is not P-256 SubjectPublicKeyInfo")
    return der[len(prefix):]


def image_sha384(label):
    return hashlib.sha384(label.encode("utf-8")).hexdigest()
