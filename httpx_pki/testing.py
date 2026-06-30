"""Helpers for minting throwaway certificates in tests.

``httpx-pki`` underpins other libraries, whose test suites all need a client
certificate to point a :class:`~httpx_pki.PKIClient` at. Rather than re-deriving
the ``cryptography`` boilerplate in every downstream ``conftest.py``, build one
here::

    from httpx_pki import PKIClient
    from httpx_pki.testing import make_client_cert

    bundle = make_client_cert("svc-client")
    with PKIClient(bundle.pkcs12(), password=b"") as client:
        ...

Everything is in-memory and self-signed (or signed by a CA you pass in); none of
it touches the disk. This module imports only ``cryptography`` (already a
dependency), so it carries no test-framework requirement.
"""

from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

__all__ = ["CertBundle", "make_ca", "make_client_cert"]


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


@dataclass(frozen=True)
class CertBundle:
    """A generated private key, its certificate, and an optional issuing CA."""

    key: rsa.RSAPrivateKey
    cert: x509.Certificate
    issuer: CertBundle | None = field(default=None, repr=False)

    @property
    def common_name(self) -> str:
        """The certificate common name"""
        attrs = self.cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        value = attrs[0].value
        return value if isinstance(value, str) else value.decode("utf-8")

    @property
    def cert_pem(self) -> bytes:
        """The certificate in PEM."""
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @property
    def key_pem(self) -> bytes:
        """The unencrypted private key in PKCS#8 PEM."""
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    @property
    def ca_pem(self) -> bytes:
        """The issuing CA certificate in PEM (empty if self-signed)."""
        return self.issuer.cert_pem if self.issuer is not None else b""

    @property
    def pem(self) -> bytes:
        """A single PEM bundle: key, then leaf cert, then the CA chain."""
        return self.key_pem + self.cert_pem + self.ca_pem

    def pkcs12(self, password: bytes | str = b"") -> bytes:
        """Serialize to a PKCS#12 blob, encrypted with *password*.

        An empty password (the default) produces an unencrypted PKCS#12, which
        :class:`~httpx_pki.PKIClient` loads with ``password=b""``.
        """
        pw = password.encode() if isinstance(password, str) else password
        encryption: serialization.KeySerializationEncryption
        if pw:
            encryption = serialization.BestAvailableEncryption(pw)
        else:
            encryption = serialization.NoEncryption()
        cas = [self.issuer.cert] if self.issuer is not None else None
        return pkcs12.serialize_key_and_certificates(
            name=self.common_name.encode(),
            key=self.key,
            cert=self.cert,
            cas=cas,
            encryption_algorithm=encryption,
        )


def make_ca(common_name: str = "httpx-pki test CA") -> CertBundle:
    """Generate a self-signed CA suitable for signing client certificates."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_utcnow() - datetime.timedelta(days=1))
        .not_valid_after(_utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        # keyCertSign/cRLSign are required for a CA: OpenSSL 3.x (Python 3.13+)
        # rejects a trust anchor that signs certs without a KeyUsage extension.
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return CertBundle(key=key, cert=cert)


def make_client_cert(  # pylint: disable=too-many-arguments
    common_name: str = "client",
    *,
    ca: CertBundle | None = None,
    dns_names: list[str] | None = None,
    ip_addresses: list[str] | None = None,
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
    expired: bool = False,
) -> CertBundle:
    """Mint a client certificate.

    Signed by *ca* if given, otherwise self-signed. *dns_names*/*ip_addresses*
    populate the Subject Alternative Name extension. The validity window
    defaults to (yesterday, +365 days); override it with *not_before*/
    *not_after*, or pass ``expired=True`` for a window that has already closed
    (handy for exercising :meth:`PKIClient.check_validity`).
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _utcnow()
    if expired:
        not_before = not_before or now - datetime.timedelta(days=30)
        not_after = not_after or now - datetime.timedelta(days=1)
    else:
        not_before = not_before or now - datetime.timedelta(days=1)
        not_after = not_after or now + datetime.timedelta(days=365)

    issuer = ca.cert.subject if ca is not None else None
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer if issuer is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                (ca.key if ca is not None else key).public_key()
            ),
            critical=False,
        )
    )

    sans: list[x509.GeneralName] = [x509.DNSName(n) for n in (dns_names or [])]
    sans += [x509.IPAddress(ipaddress.ip_address(a)) for a in (ip_addresses or [])]
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans), critical=False
        )

    signing_key = ca.key if ca is not None else key
    cert = builder.sign(signing_key, hashes.SHA256())
    return CertBundle(key=key, cert=cert, issuer=ca)
