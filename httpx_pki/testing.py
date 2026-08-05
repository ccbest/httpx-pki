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

:func:`make_pkcs12` additionally writes **multi-identity** PKCS#12 bundles --
one file holding two key pairs for the same subject, as a CA that escrows the
encryption key but not the signing key issues. Neither ``cryptography`` nor the
``openssl`` command line can write one (both keep a single key), so the DER is
assembled here; it is the only way to exercise the identity selection in
:func:`~httpx_pki.list_pkcs12_identities` and the session constructors.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import ipaddress
import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ._select import (
    eku_object_identifier,
    normalize_extended_key_usages,
    normalize_key_usages,
)

__all__ = ["CertBundle", "make_ca", "make_client_cert", "make_pkcs12"]


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


def _key_usage_extension(usages: Iterable[str] | None) -> x509.KeyUsage:
    """A KeyUsage asserting exactly *usages* (the client-cert default if None)."""
    if usages is None:
        names = ["digital_signature", "key_encipherment"]
    else:
        names = normalize_key_usages(usages)
    return x509.KeyUsage(
        digital_signature="digital_signature" in names,
        content_commitment="content_commitment" in names,
        key_encipherment="key_encipherment" in names,
        data_encipherment="data_encipherment" in names,
        key_agreement="key_agreement" in names,
        key_cert_sign="key_cert_sign" in names,
        crl_sign="crl_sign" in names,
        encipher_only="encipher_only" in names,
        decipher_only="decipher_only" in names,
    )


def make_client_cert(  # pylint: disable=too-many-arguments,too-many-locals
    common_name: str = "client",
    *,
    ca: CertBundle | None = None,
    dns_names: list[str] | None = None,
    ip_addresses: list[str] | None = None,
    not_valid_before: datetime.datetime | None = None,
    not_valid_after: datetime.datetime | None = None,
    expired: bool = False,
    key_usage: Iterable[str] | None = None,
    extended_key_usage: Iterable[str] | None = None,
) -> CertBundle:
    """Mint a client certificate.

    Signed by *ca* if given, otherwise self-signed. *dns_names*/*ip_addresses*
    populate the Subject Alternative Name extension. The validity window
    defaults to (yesterday, +365 days); override it with *not_valid_before*/
    *not_valid_after*, or pass ``expired=True`` for a window that has already
    closed (handy for exercising :meth:`httpx_pki.PKIClient.check_validity`).

    The certificate carries the extensions a real client certificate would:
    a KeyUsage of digitalSignature + keyEncipherment and an ExtendedKeyUsage
    of clientAuth, so servers that enforce EKU accept it. Override either with
    *key_usage* / *extended_key_usage*, naming the usages the way
    :class:`~httpx_pki.CertInfo` reports them -- which is how the two halves of
    a dual key pair are minted::

        signing = make_client_cert("me", key_usage=["digital_signature"])
        encryption = make_client_cert("me", key_usage=["key_encipherment"])
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _utcnow()
    if expired:
        not_valid_before = not_valid_before or now - datetime.timedelta(days=30)
        not_valid_after = not_valid_after or now - datetime.timedelta(days=1)
    else:
        not_valid_before = not_valid_before or now - datetime.timedelta(days=1)
        not_valid_after = not_valid_after or now + datetime.timedelta(days=365)

    issuer = ca.cert.subject if ca is not None else None
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer if issuer is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                (ca.key if ca is not None else key).public_key()
            ),
            critical=False,
        )
        # The extensions a CA would put on a real client certificate; strict
        # servers reject a client cert whose EKU does not include clientAuth.
        .add_extension(_key_usage_extension(key_usage), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH]
                if extended_key_usage is None
                else [
                    eku_object_identifier(name)
                    for name in normalize_extended_key_usages(extended_key_usage)
                ]
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


# -- PKCS#12 writing --------------------------------------------------------
#
# cryptography's serialize_key_and_certificates writes exactly one key, so a
# file with two identities has to be assembled from its DER parts (RFC 7292).
# The layout mirrors what OpenSSL and Windows produce: the certificates in a
# PBES2-encrypted encryptedData, each key in its own shrouded bag inside a
# plaintext SafeContents, paired by localKeyID, with an HMAC over the whole
# authenticated safe.

_OID_DATA = "1.2.840.113549.1.7.1"
_OID_ENCRYPTED_DATA = "1.2.840.113549.1.7.6"
_OID_KEY_BAG = "1.2.840.113549.1.12.10.1.1"
_OID_SHROUDED_KEY_BAG = "1.2.840.113549.1.12.10.1.2"
_OID_CERT_BAG = "1.2.840.113549.1.12.10.1.3"
_OID_X509_CERTIFICATE = "1.2.840.113549.1.9.22.1"
_OID_FRIENDLY_NAME = "1.2.840.113549.1.9.20"
_OID_LOCAL_KEY_ID = "1.2.840.113549.1.9.21"
_OID_PBES2 = "1.2.840.113549.1.5.13"
_OID_PBKDF2 = "1.2.840.113549.1.5.12"
_OID_HMAC_SHA256 = "1.2.840.113549.2.9"
_OID_AES_256_CBC = "2.16.840.1.101.3.4.1.42"
_OID_SHA256 = "2.16.840.1.101.3.4.2.1"

_ITERATIONS = 2048


def _tlv(tag: int, contents: bytes) -> bytes:
    length = len(contents)
    if length < 0x80:
        return bytes([tag, length]) + contents
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(body)]) + body + contents


def _seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def _set(*parts: bytes) -> bytes:
    return _tlv(0x31, b"".join(parts))


def _integer(value: int) -> bytes:
    # One extra leading byte keeps a high bit from reading as a sign bit.
    return _tlv(0x02, value.to_bytes((value.bit_length() + 8) // 8 or 1, "big"))


def _octets(value: bytes) -> bytes:
    return _tlv(0x04, value)


def _explicit(contents: bytes) -> bytes:
    """``[0] EXPLICIT`` -- the tagging PKCS#12 uses for bag and content values."""
    return _tlv(0xA0, contents)


def _null() -> bytes:
    return _tlv(0x05, b"")


def _oid(dotted: str) -> bytes:
    numbers = [int(part) for part in dotted.split(".")]
    body = bytes([numbers[0] * 40 + numbers[1]])
    for number in numbers[2:]:
        chunk = [number & 0x7F]
        number >>= 7
        while number:
            chunk.append((number & 0x7F) | 0x80)
            number >>= 7
        body += bytes(reversed(chunk))
    return _tlv(0x06, body)


def _bmp_string(text: str) -> bytes:
    return _tlv(0x1E, text.encode("utf-16-be"))


def _bag_attributes(local_key_id: bytes | None, friendly_name: str | None) -> bytes:
    attributes = []
    if local_key_id is not None:
        attributes.append(_seq(_oid(_OID_LOCAL_KEY_ID), _set(_octets(local_key_id))))
    if friendly_name is not None:
        attributes.append(
            _seq(_oid(_OID_FRIENDLY_NAME), _set(_bmp_string(friendly_name)))
        )
    return _set(*attributes) if attributes else b""


def _cert_bag(
    cert: x509.Certificate,
    local_key_id: bytes | None = None,
    friendly_name: str | None = None,
) -> bytes:
    value = _seq(
        _oid(_OID_X509_CERTIFICATE),
        _explicit(_octets(cert.public_bytes(serialization.Encoding.DER))),
    )
    return _seq(
        _oid(_OID_CERT_BAG),
        _explicit(value),
        _bag_attributes(local_key_id, friendly_name),
    )


def _key_bag(
    key: rsa.RSAPrivateKey,
    password: bytes,
    local_key_id: bytes,
    friendly_name: str | None,
) -> bytes:
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    value = key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, encryption
    )
    return _seq(
        _oid(_OID_SHROUDED_KEY_BAG if password else _OID_KEY_BAG),
        _explicit(value),
        _bag_attributes(local_key_id, friendly_name),
    )


def _data_content_info(payload: bytes) -> bytes:
    return _seq(_oid(_OID_DATA), _explicit(_octets(payload)))


def _encrypted_content_info(payload: bytes, password: bytes) -> bytes:
    """*payload* inside a PBES2 (PBKDF2 + AES-256-CBC) encryptedData."""
    salt, iv = os.urandom(16), os.urandom(16)
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_ITERATIONS
    ).derive(password)
    block_padding = padding.PKCS7(128).padder()
    padded = block_padding.update(payload) + block_padding.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()

    algorithm = _seq(
        _oid(_OID_PBES2),
        _seq(
            _seq(
                _oid(_OID_PBKDF2),
                _seq(
                    _octets(salt),
                    _integer(_ITERATIONS),
                    _seq(_oid(_OID_HMAC_SHA256), _null()),
                ),
            ),
            _seq(_oid(_OID_AES_256_CBC), _octets(iv)),
        ),
    )
    return _seq(
        _oid(_OID_ENCRYPTED_DATA),
        _explicit(
            _seq(
                _integer(0),
                # encryptedContent is [0] IMPLICIT, so the octets are inline.
                _seq(_oid(_OID_DATA), algorithm, _tlv(0x80, encrypted)),
            )
        ),
    )


def _pkcs12_key(  # pylint: disable=too-many-arguments
    password: bytes,
    salt: bytes,
    purpose: int,
    length: int,
    iterations: int = _ITERATIONS,
) -> bytes:
    """The RFC 7292 Appendix B.2 key derivation, over SHA-256.

    Needed only for the MAC key: everything else in the file is encrypted with
    PBES2, which ``cryptography`` derives for us.
    """
    block = 64  # SHA-256's block size, "v" in the RFC
    # The password is a BMPString including its terminating NUL (B.1).
    text = (
        password.decode("utf-8").encode("utf-16-be") + b"\x00\x00"
        if password
        else b""
    )
    diversifier = bytes([purpose]) * block
    buffer = _repeat(salt, block) + _repeat(text, block)
    output = b""
    while len(output) < length:
        digest = hashlib.sha256(diversifier + buffer).digest()
        for _ in range(iterations - 1):
            digest = hashlib.sha256(digest).digest()
        addend = int.from_bytes(_repeat(digest, block), "big") + 1
        modulus = 1 << (block * 8)
        buffer = b"".join(
            ((int.from_bytes(chunk, "big") + addend) % modulus).to_bytes(block, "big")
            for chunk in (
                buffer[at : at + block] for at in range(0, len(buffer), block)
            )
        )
        output += digest
    return output[:length]


def _repeat(data: bytes, block: int) -> bytes:
    """*data* repeated to fill a whole number of *block*-sized blocks."""
    if not data:
        return b""
    size = -(-len(data) // block) * block
    return (data * (size // len(data) + 1))[:size]


def _mac_data(authenticated_safe: bytes, password: bytes, strict_der: bool) -> bytes:
    """The authenticated safe's HMAC, with its iteration count.

    ``MacData.iterations`` carries ``DEFAULT 1``, and DER requires a field
    equal to its default to be omitted. Writing it anyway is valid BER but not
    DER -- the shape some platform exporters emit, and what makes
    ``cryptography`` fall back to a BER parse with a warning. *strict_der*
    ``False`` reproduces it.
    """
    salt = os.urandom(8)
    iterations = _ITERATIONS if strict_der else 1
    key = _pkcs12_key(password, salt, purpose=3, length=32, iterations=iterations)
    digest = hmac.new(key, authenticated_safe, hashlib.sha256).digest()
    return _seq(
        _seq(_seq(_oid(_OID_SHA256), _null()), _octets(digest)),
        _octets(salt),
        _integer(iterations),
    )


def make_pkcs12(  # pylint: disable=too-many-locals,too-many-arguments
    identities: Sequence[CertBundle | tuple[CertBundle, str | None]],
    *,
    password: bytes | str = b"",
    encrypt_certs: bool = True,
    mac: bool = True,
    keys_in_encrypted_safe: bool = False,
    strict_der: bool = True,
) -> bytes:
    """Serialize one or more identities into a single PKCS#12 blob.

    Each entry is a :class:`CertBundle`, or a ``(bundle, friendly_name)`` pair
    to label it; the bundle's issuing CA (and its issuers) are added as chain
    certificates. Unlike ``cryptography``'s
    ``serialize_key_and_certificates``, **every** key is written, so this can
    produce the dual key pair a CA issues when it escrows the encryption key::

        ca = make_ca()
        signing = make_client_cert("me", ca=ca, key_usage=["digital_signature"])
        encryption = make_client_cert("me", ca=ca, key_usage=["key_encipherment"])
        blob = make_pkcs12(
            [(signing, "Signature"), (encryption, "Encryption")],
            password="secret",
        )

    An empty *password* (the default) writes an unencrypted, unauthenticated
    bundle -- there is nothing to derive a key from -- so *encrypt_certs* and
    *mac* only take effect when a password is given. Set *encrypt_certs* to
    ``False`` for a plaintext bundle with a password, and
    *keys_in_encrypted_safe* to hide the key bags inside the encrypted portion
    (the one layout in which identities cannot be enumerated, which is what
    makes it worth testing).

    *strict_der* ``False`` writes the MAC iteration count even though its
    ASN.1 default already implies it -- valid BER, but not the DER PKCS#12
    calls for. Some platform exporters (the macOS Security framework among
    them) emit exactly that, which makes ``cryptography`` re-parse the bundle
    as BER and warn about it; pass ``False`` to test how your code copes. Only
    takes effect together with a password, since an unauthenticated bundle has
    no MAC to encode.
    """
    secret = password.encode() if isinstance(password, str) else password
    if keys_in_encrypted_safe and not secret:
        raise ValueError("keys_in_encrypted_safe requires a password")
    if not identities:
        raise ValueError("make_pkcs12 needs at least one identity")

    cert_bags: list[bytes] = []
    key_bags: list[bytes] = []
    chain: dict[bytes, x509.Certificate] = {}
    for index, entry in enumerate(identities):
        bundle, name = entry if isinstance(entry, tuple) else (entry, None)
        local_key_id = bytes([index + 1])
        friendly_name = bundle.common_name if name is None else name
        cert_bags.append(_cert_bag(bundle.cert, local_key_id, friendly_name))
        key_bags.append(_key_bag(bundle.key, secret, local_key_id, friendly_name))
        issuer = bundle.issuer
        while issuer is not None:
            chain.setdefault(
                issuer.cert.public_bytes(serialization.Encoding.DER), issuer.cert
            )
            issuer = issuer.issuer
    cert_bags += [_cert_bag(cert) for cert in chain.values()]

    if keys_in_encrypted_safe:
        safes = [_encrypted_content_info(_seq(*cert_bags, *key_bags), secret)]
    elif encrypt_certs and secret:
        safes = [
            _encrypted_content_info(_seq(*cert_bags), secret),
            _data_content_info(_seq(*key_bags)),
        ]
    else:
        safes = [
            _data_content_info(_seq(*cert_bags)),
            _data_content_info(_seq(*key_bags)),
        ]

    authenticated_safe = _seq(*safes)
    elements = [_integer(3), _data_content_info(authenticated_safe)]
    if mac and secret:
        elements.append(_mac_data(authenticated_safe, secret, strict_der))
    return _seq(*elements)
