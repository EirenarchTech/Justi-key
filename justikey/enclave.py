"""Enclave-side handling of a KMS `CiphertextForRecipient`.

Stage 5 of docs/capability-model.md.

HOW THE RECIPIENT PATH ACTUALLY WORKS

A common misreading -- one this project held briefly -- is that the Nitro
Security Module decrypts the KMS response. It does not. The NSM's job is to
*produce and sign an attestation document*. The decryption key is an ordinary
RSA keypair the enclave generates for itself:

    1. the enclave generates an RSA-2048 keypair in its own memory
    2. it asks the NSM for an attestation document carrying that public key
    3. KMS is called with Recipient = that attestation document
    4. KMS returns the secret encrypted to that public key, and SharedSecret
       comes back empty
    5. the enclave decrypts with the private key, which never left its memory

So everything here except step 2 is ordinary cryptography that runs and is
tested anywhere. Only the attestation document needs the device.

WHAT `CiphertextForRecipient` IS

Not a bare RSA-OAEP ciphertext. It is a CMS `EnvelopedData` (RFC 5652):

    EnvelopedData
      recipientInfos     KeyTransRecipientInfo
        keyEncryption    RSAES-OAEP with SHA-256
        encryptedKey     the content-encryption key, wrapped to our RSA key
      encryptedContentInfo
        algorithm        AES-256-CBC, IV in the parameters
        encryptedContent the secret itself

An implementation that RSA-decrypts the blob directly works against a
convenient stand-in and fails against AWS. The parser below reads the real
structure, and tests/fake_kms.py produces genuine DER so the parser is
exercised against the format rather than against a shortcut.

A FRESH KEY PER OPERATION

Each KMS agreement generates its own recipient keypair. A captured
`CiphertextForRecipient` is then useless outside the single operation that
asked for it -- there is no longer-lived key it could be replayed against --
and the lifetime story is one sentence rather than a rotation policy. Key
generation is the cost; measure before optimising it away.
"""
import hashlib
import os
import struct

try:  # pragma: no cover
    from cryptography.hazmat.primitives import hashes, padding as sym_padding, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    ENCLAVE_AVAILABLE = True
except ImportError:  # pragma: no cover
    ENCLAVE_AVAILABLE = False

NSM_DEVICE = "/dev/nsm"
RECIPIENT_KEY_BITS = 2048
KEY_ENCRYPTION_ALGORITHM = "RSAES_OAEP_SHA_256"

# RFC 5652 / PKCS#1 object identifiers, as DER content octets.
OID_ENVELOPED_DATA = bytes.fromhex("2a864886f70d010703")
OID_DATA = bytes.fromhex("2a864886f70d010701")
OID_RSAES_OAEP = bytes.fromhex("2a864886f70d010107")
OID_AES_256_CBC = bytes.fromhex("60864801650304012a")


class EnclaveError(RuntimeError):
    """The recipient path could not be completed. Never a partial result."""


# ---------------------------------------------------------------------------
# Minimal DER
# ---------------------------------------------------------------------------

def _read_tlv(data, offset):
    """One DER element: (tag, content, next_offset). Refuses the indefinite
    lengths BER allows, which DER forbids and which are a classic parser
    ambiguity."""
    if offset + 2 > len(data):
        raise EnclaveError("truncated DER element")
    tag = data[offset]
    length_byte = data[offset + 1]
    offset += 2
    if length_byte < 0x80:
        length = length_byte
    elif length_byte == 0x80:
        raise EnclaveError("indefinite-length DER is not accepted")
    else:
        count = length_byte & 0x7F
        if count > 4 or offset + count > len(data):
            raise EnclaveError("unsupported DER length encoding")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    end = offset + length
    if end > len(data):
        raise EnclaveError("DER element runs past the end of the buffer")
    return tag, data[offset:end], end


def _children(content):
    items, offset = [], 0
    while offset < len(content):
        tag, body, offset = _read_tlv(content, offset)
        items.append((tag, body))
    return items


def _expect(items, index, tag, what):
    if index >= len(items) or items[index][0] != tag:
        raise EnclaveError(f"CMS: expected {what}")
    return items[index][1]


def _find(items, tag):
    for item_tag, body in items:
        if item_tag == tag:
            return body
    return None


def parse_enveloped_data(der):
    """Pull the wrapped key, the IV and the ciphertext out of a CMS envelope.

    Deliberately strict: the algorithms are checked rather than read, because
    a parser that accepts whatever algorithm the blob names will happily
    accept one the sender chose.
    """
    tag, content, _ = _read_tlv(der, 0)
    if tag != 0x30:
        raise EnclaveError("CMS: ContentInfo is not a SEQUENCE")
    outer = _children(content)
    content_type = _expect(outer, 0, 0x06, "ContentInfo.contentType OID")
    if content_type != OID_ENVELOPED_DATA:
        raise EnclaveError("CMS: content is not EnvelopedData")
    explicit = _expect(outer, 1, 0xA0, "ContentInfo.content [0]")
    tag, enveloped, _ = _read_tlv(explicit, 0)
    if tag != 0x30:
        raise EnclaveError("CMS: EnvelopedData is not a SEQUENCE")
    fields = _children(enveloped)

    recipient_infos = _find(fields, 0x31)
    if recipient_infos is None:
        raise EnclaveError("CMS: no recipientInfos")
    recipients = _children(recipient_infos)
    if len(recipients) != 1:
        raise EnclaveError(
            f"CMS: expected exactly one recipient, found {len(recipients)}")
    if recipients[0][0] != 0x30:
        raise EnclaveError("CMS: RecipientInfo is not a KeyTransRecipientInfo")
    ktri = _children(recipients[0][1])

    key_algorithm = None
    for item_tag, body in ktri:
        if item_tag == 0x30:
            inner = _children(body)
            if inner and inner[0][0] == 0x06:
                key_algorithm = inner[0][1]
                break
    if key_algorithm != OID_RSAES_OAEP:
        raise EnclaveError(
            "CMS: key encryption is not RSAES-OAEP; refusing rather than "
            "accepting an algorithm the sender chose")
    encrypted_key = _find(ktri, 0x04)
    if encrypted_key is None:
        raise EnclaveError("CMS: no encryptedKey")

    encrypted_content_info = None
    for index, (item_tag, body) in enumerate(fields):
        if item_tag == 0x30 and index > 0:
            encrypted_content_info = _children(body)
    if encrypted_content_info is None:
        raise EnclaveError("CMS: no encryptedContentInfo")

    algorithm = None
    for item_tag, body in encrypted_content_info:
        if item_tag == 0x30:
            algorithm = _children(body)
            break
    if algorithm is None or algorithm[0][0] != 0x06:
        raise EnclaveError("CMS: no contentEncryptionAlgorithm")
    if algorithm[0][1] != OID_AES_256_CBC:
        raise EnclaveError("CMS: content encryption is not AES-256-CBC")
    iv = algorithm[1][1] if len(algorithm) > 1 and algorithm[1][0] == 0x04 else None
    if iv is None or len(iv) != 16:
        raise EnclaveError("CMS: missing or malformed AES-CBC initialisation vector")

    encrypted_content = _find(encrypted_content_info, 0x80)
    if encrypted_content is None:
        encrypted_content = _find(encrypted_content_info, 0xA0)
    if encrypted_content is None:
        raise EnclaveError("CMS: no encryptedContent")
    return {"encrypted_key": encrypted_key, "iv": iv,
            "encrypted_content": encrypted_content}


# ---------------------------------------------------------------------------
# The recipient key
# ---------------------------------------------------------------------------

def _erase(buffer):
    """Best-effort erasure of intermediate key material.

    Honest about its limits: Python's `bytes` are immutable and the runtime
    may have copied them, so this zeroes what it can reach and no more. It is
    a reduction in exposure window, not a guarantee -- claiming otherwise
    would be the kind of overstatement this project exists to avoid.
    """
    if isinstance(buffer, bytearray):
        for index in range(len(buffer)):
            buffer[index] = 0


class RecipientKey:
    """A fresh RSA-2048 keypair for exactly one KMS operation.

    Generated inside the enclave; the private half never leaves it. Fresh per
    operation so a captured CiphertextForRecipient has no later operation it
    could be replayed into.
    """

    def __init__(self):
        if not ENCLAVE_AVAILABLE:
            raise EnclaveError("the recipient path requires the 'cryptography' package")
        self._private = rsa.generate_private_key(public_exponent=65537,
                                                 key_size=RECIPIENT_KEY_BITS)
        self.public_der = self._private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        self.public_fingerprint = hashlib.sha256(self.public_der).hexdigest()[:16]

    def decrypt(self, ciphertext_for_recipient):
        """CMS envelope -> the plaintext KMS produced for this enclave."""
        envelope = parse_enveloped_data(ciphertext_for_recipient)
        try:
            content_key = bytearray(self._private.decrypt(
                envelope["encrypted_key"],
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None)))
        except Exception as exc:  # noqa: BLE001 - any failure means "not ours"
            raise EnclaveError(
                "the CMS content key was not encrypted to this enclave's "
                f"recipient key: {exc!r}") from exc
        if len(content_key) != 32:
            _erase(content_key)
            raise EnclaveError(
                f"CMS content key is {len(content_key)} bytes, not a 256-bit AES key")

        try:
            decryptor = Cipher(algorithms.AES(bytes(content_key)),
                               modes.CBC(envelope["iv"])).decryptor()
            padded = decryptor.update(envelope["encrypted_content"]) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            return unpadder.update(padded) + unpadder.finalize()
        except Exception as exc:  # noqa: BLE001
            raise EnclaveError(f"could not open the CMS content: {exc!r}") from exc
        finally:
            _erase(content_key)


# ---------------------------------------------------------------------------
# Attestation
# ---------------------------------------------------------------------------

class NsmAttestation:
    """Asks the Nitro Security Module for a document carrying our public key.

    This is the one step that needs the device. Outside an enclave there is no
    /dev/nsm, and this raises rather than producing something document-shaped:
    a fabricated attestation would be refused by KMS anyway, and a stand-in
    that looked real would let a development configuration pass for a
    production one.
    """

    available = True

    def __init__(self, device=NSM_DEVICE):
        self.device = device

    def document_for(self, public_der):
        if not os.path.exists(self.device):
            raise EnclaveError(
                f"no Nitro Security Module at {self.device}: attestation documents "
                f"can only be produced inside an enclave. Run the custodian in an "
                f"enclave, or run it unattested and understand that the "
                f"configuration does not meet the stage 5 objective.")
        raise EnclaveError(
            "NSM attestation is not implemented in this build: it needs the "
            "aws-nitro-enclaves NSM API to request a document embedding the "
            "recipient public key. Everything either side of that step -- key "
            "generation and CMS decryption -- is implemented and tested.")


class StaticAttestation:
    """An attestation document supplied out of band, e.g. from a file.

    For a deployment that obtains its document by other means. It cannot
    embed a per-operation public key, so it is only usable where the document
    already carries the key this process will decrypt with.
    """

    available = True

    def __init__(self, document):
        self.document = document

    def document_for(self, public_der):
        return self.document


def recipient_for(attestation_provider):
    """(recipient parameter, key) for one KMS call, or raise.

    Returns the exact `Recipient` shape KMS expects, with a key that exists
    only for this operation.
    """
    key = RecipientKey()
    document = attestation_provider.document_for(key.public_der)
    return ({"AttestationDocument": document,
             "KeyEncryptionAlgorithm": KEY_ENCRYPTION_ALGORITHM}, key)
