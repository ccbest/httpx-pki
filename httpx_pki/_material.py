"""Loading and normalizing certificate material.

Every construction path funnels into one canonical in-memory representation:
:class:`Material`, a triple of decrypted PEM byte strings (private key,
client certificate, and any CA/intermediate certificates). Both the SSL context
build (:mod:`httpx_pki._ssl`) and pickling derive from this, so the PKCS#12 and
key-pair entry points share the same downstream code.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12

from ._exceptions import CertificateLoadError

# A source of bytes: either the raw bytes themselves, or a filesystem path
# (``str`` or :class:`pathlib.Path`) to read them from.
CertSource = bytes | str | Path
Password = bytes | str | None


@dataclass(frozen=True)
class Material:
    """Canonical, decrypted certificate material as PEM byte strings."""

    key_pem: bytes
    cert_pem: bytes
    ca_pems: list[bytes] = field(default_factory=list)


@dataclass(frozen=True)
class CertInfo:
    """Human-readable summary of a client certificate."""

    common_name: str | None
    distinguished_name: str
    not_before: datetime.datetime
    not_after: datetime.datetime
    subject_alt_names: list[str]


def read_source(src: CertSource) -> bytes:
    """Return the bytes for *src*, reading from disk if it is a path."""
    if isinstance(src, bytes):
        return src
    if isinstance(src, (str, Path)):
        try:
            return Path(src).read_bytes()
        except OSError as exc:
            raise CertificateLoadError(f"could not read {src!r}: {exc}") from exc
    raise TypeError(
        f"expected bytes, str, or pathlib.Path, got {type(src).__name__}"
    )


def encode_password(password: Password) -> bytes | None:
    """Normalize a password to bytes (or ``None``)."""
    if password is None:
        return None
    if isinstance(password, bytes):
        return password
    if isinstance(password, str):
        return password.encode("utf-8")
    raise TypeError(
        f"password must be str, bytes, or None, got {type(password).__name__}"
    )


def parse_pkcs12(data: bytes, password: bytes | None) -> Material:
    """Extract decrypted PEM material from a PKCS#12 blob."""
    try:
        key, cert, additional = pkcs12.load_key_and_certificates(data, password)
    except (ValueError, TypeError) as exc:
        raise CertificateLoadError(
            "invalid PKCS#12 data or wrong password"
        ) from exc

    if key is None:
        raise CertificateLoadError("PKCS#12 data contains no private key")
    if cert is None:
        raise CertificateLoadError("PKCS#12 data contains no certificate")

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    ca_pems = [c.public_bytes(serialization.Encoding.PEM) for c in additional]
    return Material(key_pem=key_pem, cert_pem=cert_pem, ca_pems=ca_pems)


# A single PEM block: -----BEGIN <LABEL>----- ... -----END <LABEL>-----
_PEM_BLOCK = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+?)-----.+?-----END \1-----", re.DOTALL
)


def parse_pem_bundle(data: bytes, password: bytes | None) -> Material:
    """Extract material from a PEM blob holding a key and one or more certs.

    The blocks may appear in any order; the first ``CERTIFICATE`` is treated as
    the client (leaf) certificate and the rest as the CA chain. The private key
    may be PKCS#1, PKCS#8, EC, or encrypted (decrypted with *password*).
    """
    key_block: bytes | None = None
    cert_blocks: list[bytes] = []
    for match in _PEM_BLOCK.finditer(data):
        label = match.group(1)
        if b"PRIVATE KEY" in label:
            if key_block is None:
                key_block = match.group(0)
        elif label == b"CERTIFICATE":
            cert_blocks.append(match.group(0))

    if key_block is None:
        raise CertificateLoadError("no private key found in PEM data")
    if not cert_blocks:
        raise CertificateLoadError("no certificate found in PEM data")

    key = _load_private_key(key_block, password)
    leaf = _load_certificate(cert_blocks[0])
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = leaf.public_bytes(serialization.Encoding.PEM)
    ca_pems = [
        _load_certificate(block).public_bytes(serialization.Encoding.PEM)
        for block in cert_blocks[1:]
    ]
    return Material(key_pem=key_pem, cert_pem=cert_pem, ca_pems=ca_pems)


def load_material(data: bytes, password: bytes | None) -> Material:
    """Load material from a single source, detecting the encoding by content.

    PEM (text, recognized by its ``-----BEGIN`` armor) is parsed as a bundle;
    anything else is treated as binary PKCS#12. The file *extension* is
    irrelevant -- only the bytes matter.
    """
    if b"-----BEGIN" in data:
        return parse_pem_bundle(data, password)
    return parse_pkcs12(data, password)


def _load_certificate(data: bytes) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        try:
            return x509.load_der_x509_certificate(data)
        except ValueError as exc:
            raise CertificateLoadError("could not parse certificate") from exc


def _load_private_key(
    data: bytes, password: bytes | None
) -> PrivateKeyTypes:
    try:
        return serialization.load_pem_private_key(data, password)
    except (ValueError, TypeError):
        try:
            return serialization.load_der_private_key(data, password)
        except (ValueError, TypeError) as exc:
            raise CertificateLoadError(
                "could not parse private key (wrong password?)"
            ) from exc


def normalize_pem(
    certificate: CertSource,
    private_key: CertSource,
    key_password: Password = None,
    ca: CertSource | list[CertSource] | None = None,
) -> Material:
    """Build canonical material from a separate certificate and private key."""
    cert = _load_certificate(read_source(certificate))
    key = _load_private_key(read_source(private_key), encode_password(key_password))

    ca_sources: list[CertSource]
    if ca is None:
        ca_sources = []
    elif isinstance(ca, list):
        ca_sources = ca
    else:
        ca_sources = [ca]

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    ca_pems = [
        _load_certificate(read_source(c)).public_bytes(serialization.Encoding.PEM)
        for c in ca_sources
    ]
    return Material(key_pem=key_pem, cert_pem=cert_pem, ca_pems=ca_pems)


def cert_info(cert_pem: bytes) -> CertInfo:
    """Summarize the subject, validity window, and SANs of a certificate."""
    cert = _load_certificate(cert_pem)

    common_name: str | None = None
    cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if cn_attrs:
        value = cn_attrs[0].value
        common_name = value if isinstance(value, str) else value.decode("utf-8")

    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    return CertInfo(
        common_name=common_name,
        distinguished_name=cert.subject.rfc4514_string(),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        subject_alt_names=sans,
    )
