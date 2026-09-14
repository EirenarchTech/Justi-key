"""Throwaway certificates for tests that need a real TLS handshake."""
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def issue(common_name, issuer=None, issuer_key=None, ca=False):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(issuer.subject if issuer is not None else subject)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                              critical=True))
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
    return key, builder.sign(issuer_key or key, hashes.SHA256())


def write(directory, name, key=None, certificate=None):
    path = os.path.join(directory, name)
    with open(path, "wb") as handle:
        if certificate is not None:
            handle.write(certificate.public_bytes(serialization.Encoding.PEM))
        if key is not None:
            handle.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
    return path


def der(certificate):
    return certificate.public_bytes(serialization.Encoding.DER)
