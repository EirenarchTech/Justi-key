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
import json
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
    def attestation(image_sha384, public_der=None):
        """What an enclave presents.

        A real document is CBOR/COSE signed by the NSM, carrying the
        enclave's PCRs and the recipient public key. Here it is the image
        measurement plus that public key, because those are the two
        properties the tests actually exercise: which image called, and which
        key KMS must encrypt to.
        """
        document = {"image": image_sha384,
                    "public_key": (public_der or b"").hex()}
        return {"AttestationDocument": json.dumps(document).encode("utf-8"),
                "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256"}

    # -- the KMS operation -------------------------------------------------

    def derive_shared_secret(self, KeyId=None, KeyAgreementAlgorithm=None,
                             PublicKey=None, Recipient=None):
        self.calls.append({"key": KeyId, "attested": Recipient is not None})
        if KeyId != self.key_arn:
            raise AccessDeniedException(f"no such key: {KeyId}")
        if KeyAgreementAlgorithm != "ECDH":
            raise AccessDeniedException(
                f"unsupported key agreement algorithm {KeyAgreementAlgorithm!r}")

        image, recipient_public = None, None
        if Recipient is not None:
            try:
                document = json.loads(Recipient["AttestationDocument"].decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise AccessDeniedException(
                    f"AccessDeniedException: malformed attestation document: {exc}")
            image = document.get("image")
            recipient_public = bytes.fromhex(document.get("public_key") or "")
            if Recipient.get("KeyEncryptionAlgorithm") != "RSAES_OAEP_SHA_256":
                raise AccessDeniedException(
                    "AccessDeniedException: RSAES_OAEP_SHA_256 is the only key "
                    "encryption algorithm supported for Nitro Enclaves")
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
            # KMS re-encrypts to the public key in the attestation document
            # and returns NO plaintext secret.
            if not recipient_public:
                raise AccessDeniedException(
                    "AccessDeniedException: the attestation document carries no "
                    "public key to encrypt the result to")
            return {"SharedSecret": b"",
                    "CiphertextForRecipient": cms_envelope(recipient_public, secret),
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


class EnclaveAttestation:
    """Stands in for the NSM.

    Produces a document carrying the per-operation recipient public key,
    which is the property the hardened sequence depends on: KMS encrypts to
    whatever key the document names, so a document naming a stale key makes
    the response undecryptable by the operation that asked for it.
    """

    available = True

    def __init__(self, image, override_public_der=None):
        self.image = image
        # For the test that feeds a later operation an older ciphertext.
        self.override_public_der = override_public_der
        self.documents = []

    def document_for(self, public_der):
        used = self.override_public_der or public_der
        self.documents.append(used)
        return FakeKms.attestation(self.image, used)["AttestationDocument"]


def image_sha384(label):
    return hashlib.sha384(label.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Genuine RFC 5652 EnvelopedData
# ---------------------------------------------------------------------------
#
# Produced properly rather than faked, so justikey/enclave.py's parser is
# exercised against the format AWS actually returns. A stand-in that emitted
# a bare RSA-OAEP blob would let a parser pass here and fail against KMS,
# which is the exact class of bug a stand-in is supposed to prevent.

def _der(tag, content):
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    length = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + content


def _oid(content_octets):
    return _der(0x06, content_octets)


def cms_envelope(recipient_public_der, plaintext):
    """EnvelopedData: RSA-OAEP-SHA256 over the content key, AES-256-CBC content."""
    import os as _os

    from cryptography.hazmat.primitives import hashes, padding as sym_padding
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    from justikey import enclave

    content_key, iv = _os.urandom(32), _os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(content_key), modes.CBC(iv)).encryptor()
    encrypted_content = encryptor.update(padded) + encryptor.finalize()

    public = load_der_public_key(recipient_public_der)
    encrypted_key = public.encrypt(
        content_key,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=None))

    ktri = _der(0x30,
                _der(0x02, b"\x00")                       # version
                + _der(0x80, b"\x01\x02\x03\x04")         # rid (subjectKeyIdentifier)
                + _der(0x30, _oid(enclave.OID_RSAES_OAEP))  # keyEncryptionAlgorithm
                + _der(0x04, encrypted_key))
    encrypted_content_info = _der(
        0x30,
        _oid(enclave.OID_DATA)
        + _der(0x30, _oid(enclave.OID_AES_256_CBC) + _der(0x04, iv))
        + _der(0x80, encrypted_content))                   # [0] IMPLICIT
    enveloped = _der(0x30,
                     _der(0x02, b"\x00")
                     + _der(0x31, ktri)
                     + encrypted_content_info)
    return _der(0x30, _oid(enclave.OID_ENVELOPED_DATA) + _der(0xA0, enveloped))
