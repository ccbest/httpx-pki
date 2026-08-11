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
from collections.abc import Collection, Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID

from ._exceptions import CertificateLoadError

if TYPE_CHECKING:  # imported for typing only -- see parse_pkcs12
    from ._pkcs12 import IdentitySelector, P12Identity
    from ._select import UsageSelector

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


def build_material(
    key: PrivateKeyTypes,
    leaf: x509.Certificate,
    chain: Iterable[x509.Certificate],
    *,
    exclude: Collection[bytes] = (),
) -> Material:
    """Canonical material for one chosen identity.

    The tail every loading path shares, whatever it had to do to get here:
    serialize the private key to unencrypted PKCS#8 PEM, the leaf certificate
    to PEM, and whichever of *chain* belongs on the wire.

    *exclude* holds DER encodings to keep out of the chain -- the **other**
    identities' leaf certificates, in a source that holds several. Those are
    leaves of their own, not intermediates on the way to a CA, and presenting
    them can make a strict server reject the chain. A source with a single
    identity passes nothing and pays for nothing: the DER is only re-encoded
    when there is something to compare it against.
    """
    kept = (
        chain
        if not exclude
        else [
            cert
            for cert in chain
            if cert.public_bytes(serialization.Encoding.DER) not in exclude
        ]
    )
    return Material(
        key_pem=key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        cert_pem=leaf.public_bytes(serialization.Encoding.PEM),
        ca_pems=[cert.public_bytes(serialization.Encoding.PEM) for cert in kept],
    )


@dataclass(frozen=True)
class CertInfo:  # pylint: disable=too-many-instance-attributes
    """Human-readable summary of a client certificate.

    ``subject_alt_names`` carries every Subject Alternative Name entry as a
    string (DNS names, IP addresses, email addresses, and URIs); ``dns_names``
    is just the dNSName subset, for the common case of hostname checks.

    The fingerprints are uppercase hex with no separators.
    ``fingerprint_sha1`` uses the same format as the platform stores'
    thumbprints (:class:`~httpx_pki.WinCert` / :class:`~httpx_pki.MacCert`),
    so it can be compared against ``list_windows_certificates()`` /
    ``list_macos_certificates()`` output or passed to a ``thumbprint=``
    selector; ``fingerprint_sha256`` is the modern identifier for logs.

    ``key_usage`` holds the asserted KeyUsage bits under the
    :class:`cryptography.x509.KeyUsage` attribute names (``digital_signature``,
    ``key_encipherment``, ...) and ``extended_key_usage`` the ExtendedKeyUsage
    entries as lowercase names (``client_auth``, ``email_protection``, ...),
    falling back to a dotted OID string for OIDs ``cryptography`` doesn't name.
    Both are empty when the certificate carries no such extension. They are
    what tells the two identities of a dual-key-pair PKCS#12 apart; see
    :func:`~httpx_pki.list_pkcs12_identities`.
    """

    common_name: str | None
    distinguished_name: str
    issuer_common_name: str | None
    issuer_distinguished_name: str
    serial_number: int
    not_valid_before: datetime.datetime
    not_valid_after: datetime.datetime
    fingerprint_sha256: str
    fingerprint_sha1: str
    subject_alt_names: list[str]
    dns_names: list[str] = field(default_factory=list)
    key_usage: frozenset[str] = frozenset()
    extended_key_usage: list[str] = field(default_factory=list)

    @property
    def serial_number_hex(self) -> str:
        """The serial number as uppercase hex, zero-padded to whole bytes."""
        text = format(self.serial_number, "X")
        return text.zfill(len(text) + len(text) % 2)


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


def parse_pkcs12(
    data: bytes,
    password: bytes | None,
    *,
    identity: IdentitySelector | None = None,
    key_usage: UsageSelector | None = None,
    extended_key_usage: UsageSelector | None = None,
) -> Material:
    """Extract decrypted PEM material for one identity in a PKCS#12 blob.

    A bundle may hold several identities (see :mod:`httpx_pki._pkcs12`); the
    selectors pick which one to present, and are required when there is more
    than one.
    """
    # Deferred: _pkcs12 builds on this module's helpers, so importing it here
    # rather than at module scope keeps the dependency one-way.
    from ._pkcs12 import pkcs12_material

    return pkcs12_material(
        data,
        password,
        identity=identity,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
    )


def _pkcs12_failure_message(data: bytes) -> str:
    """Diagnose why *data* failed to parse as PKCS#12.

    A bare DER certificate or a certs-only PKCS#7 bundle (.p7b) is
    indistinguishable from PKCS#12 by content sniffing (all are DER), so a user
    who passes one as the single source lands here -- point them at the right
    entry point instead of blaming the password.
    """
    try:
        x509.load_der_x509_certificate(data)
    except ValueError:
        pass
    else:
        return (
            "the data is a DER certificate with no private key; pass it to "
            "from_key_pair(certificate=..., private_key=...)"
        )
    if _maybe_pkcs7_certificates(data) is not None:
        return (
            "the data is a certificate-only PKCS#7 bundle with no private "
            "key; use it as chain= in from_key_pair or as a verify= CA bundle"
        )
    return "invalid PKCS#12 data or wrong password"


# A single PEM block: -----BEGIN <LABEL>----- ... -----END <LABEL>-----
_PEM_BLOCK = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+?)-----.+?-----END \1-----", re.DOTALL
)


def parse_pem_bundle(
    data: bytes,
    password: bytes | None,
    *,
    identity: IdentitySelector | None = None,
    key_usage: UsageSelector | None = None,
    extended_key_usage: UsageSelector | None = None,
) -> Material:
    """Extract material for one identity from a PEM blob.

    The blocks may appear in any order; each certificate matching a private
    key (paired by public key) is an *identity*, and the certificates matching
    none are the CA chain. Certificates may also arrive inside a ``PKCS7``
    block (a certs-only ``.p7b`` re-encoded as PEM), whose contents are
    expanded in place. Keys may be PKCS#1, PKCS#8, EC, or encrypted (decrypted
    with *password*).

    A bundle usually holds exactly one identity, which is presented without
    further ado. It may hold several -- two key+cert pairs concatenated, or a
    renewed certificate alongside the one it replaces over a single key pair
    -- and then the selectors choose which to present, exactly as for a
    PKCS#12 bundle (:class:`~httpx_pki.AmbiguousCertificateError` is raised
    without one). Every key must match a certificate: an unmatched key means
    the bundle was assembled from the wrong pieces, and is rejected rather
    than silently dropped.
    """
    # Deferred: _pkcs12 builds on this module's helpers, so importing it here
    # rather than at module scope keeps the dependency one-way.
    from ._pkcs12 import select_identity

    pairs, certs = _pem_pairs(data, password)
    chosen = select_identity(
        _identities_from_pairs(pairs),
        identity=identity,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
        source_kind="PEM data",
    )
    # The other identities' certificates are leaves of their own, not
    # intermediates on the way to a CA -- keep them out of the chain, exactly
    # as the PKCS#12 path does.
    return build_material(
        pairs[chosen.index][0],
        chosen.certificate,
        certs,
        exclude={
            cert.public_bytes(serialization.Encoding.DER) for _key, cert in pairs
        },
    )


def _pem_pairs(
    data: bytes, password: bytes | None
) -> tuple[list[tuple[PrivateKeyTypes, x509.Certificate]], list[x509.Certificate]]:
    """The identities (key + matching certificate) and all certs in a PEM blob.

    Identities are ordered by key appearance, then certificate appearance.
    Byte-duplicated keys and duplicate (key, certificate) pairings collapse to
    one; a key matching several distinct certificates -- what renewing without
    rekeying produces -- yields one identity per certificate, mirroring the
    PKCS#12 walk (:func:`~httpx_pki._pkcs12.load_bundle`).
    """
    key_blocks, certs = _pem_blocks(data)
    if not key_blocks:
        raise CertificateLoadError("no private key found in PEM data")
    if not certs:
        raise CertificateLoadError("no certificate found in PEM data")

    # Keyed by SPKI: the same key pasted twice (or once as PKCS#1 and once as
    # PKCS#8) is one key, not an assembly mistake.
    keys: dict[bytes, PrivateKeyTypes] = {}
    for block in key_blocks:
        key = _load_private_key(block, password)
        keys.setdefault(_spki(key.public_key()), key)

    pairs: list[tuple[PrivateKeyTypes, x509.Certificate]] = []
    for spki, key in keys.items():
        seen: set[bytes] = set()
        for cert in certs:
            if _spki(cert.public_key()) != spki:
                continue
            der = cert.public_bytes(serialization.Encoding.DER)
            if der in seen:
                continue
            seen.add(der)
            pairs.append((key, cert))
        if not seen:
            raise CertificateLoadError(
                "private key does not match any certificate in the PEM data"
            )
    return pairs, certs


def _pem_blocks(
    data: bytes,
) -> tuple[list[bytes], list[x509.Certificate]]:
    """The private-key blocks and certificates in a PEM blob, in file order.

    Certificates inside a ``PKCS7`` block (a certs-only ``.p7b`` re-encoded as
    PEM) are expanded in place.
    """
    key_blocks: list[bytes] = []
    certs: list[x509.Certificate] = []
    for match in _PEM_BLOCK.finditer(data):
        label = match.group(1)
        if b"PRIVATE KEY" in label:
            key_blocks.append(match.group(0))
        elif label == b"CERTIFICATE":
            certs.append(_load_certificate(match.group(0)))
        elif label == b"PKCS7":
            try:
                certs.extend(pkcs7.load_pem_pkcs7_certificates(match.group(0)))
            except ValueError as exc:
                raise CertificateLoadError(
                    "could not parse PKCS#7 block in PEM data"
                ) from exc
    return key_blocks, certs


def _identities_from_pairs(
    pairs: list[tuple[PrivateKeyTypes, x509.Certificate]],
) -> list[P12Identity]:
    """The pairs as selectable identities (indexed in pair order)."""
    from ._pkcs12 import P12Identity

    return [
        P12Identity(
            index=index,
            friendly_name=None,  # PEM bags carry no label
            certificate=cert,
            info=certificate_info(cert),
        )
        for index, (_key, cert) in enumerate(pairs)
    ]


def pem_identities(data: bytes, password: bytes | None) -> list[P12Identity]:
    """Every identity in a PEM blob, for :func:`~httpx_pki.list_identities`."""
    pairs, _certs = _pem_pairs(data, password)
    return _identities_from_pairs(pairs)


def load_material(
    data: bytes,
    password: bytes | None,
    *,
    identity: IdentitySelector | None = None,
    key_usage: UsageSelector | None = None,
    extended_key_usage: UsageSelector | None = None,
) -> Material:
    """Load material from a single source, detecting the encoding by content.

    PEM (text, recognized by its ``-----BEGIN`` armor) is parsed as a bundle;
    anything else is treated as binary PKCS#12. The file *extension* is
    irrelevant -- only the bytes matter.

    The identity selectors work for both encodings: a bundle holding several
    identities requires one, and a selector that doesn't match anything raises
    rather than being quietly ignored.
    """
    if b"-----BEGIN" in data:
        return parse_pem_bundle(
            data,
            password,
            identity=identity,
            key_usage=key_usage,
            extended_key_usage=extended_key_usage,
        )
    return parse_pkcs12(
        data,
        password,
        identity=identity,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
    )


def _spki(public_key: PublicKeyTypes) -> bytes:
    """DER-encoded SubjectPublicKeyInfo, the type-agnostic public-key identity.

    Comparing these encodings matches a key to a certificate uniformly across
    RSA, EC, and the Ed25519/Ed448 key types.
    """
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _split_leaf_and_chain(
    key: PrivateKeyTypes, certs: list[x509.Certificate]
) -> tuple[x509.Certificate, list[x509.Certificate]]:
    """Identify the leaf among *certs* as the one matching *key*.

    A PEM bundle may list its certificates in any order, so the leaf is the
    certificate whose public key matches the private key -- not simply the
    first. The remaining certificates (in their original order) are the chain.
    Raising on *which* cert is the leaf, rather than assuming position, keeps a
    correctly-keyed-but-out-of-order bundle from failing with a misleading
    "key does not match" error.
    """
    key_spki = _spki(key.public_key())
    for i, cert in enumerate(certs):
        if _spki(cert.public_key()) == key_spki:
            return cert, certs[:i] + certs[i + 1 :]
    raise CertificateLoadError(
        "private key does not match any certificate in the PEM data"
    )


def _load_certificate(data: bytes) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        try:
            return x509.load_der_x509_certificate(data)
        except ValueError as exc:
            raise CertificateLoadError("could not parse certificate") from exc


def _maybe_pkcs7_certificates(data: bytes) -> list[x509.Certificate] | None:
    """Parse *data* as a certs-only PKCS#7 bundle, or ``None`` if it isn't one.

    PKCS#7 (``.p7b``/``.p7c``) is how Windows CAs commonly export certificate
    chains -- DER or PEM, never holding a private key.
    """
    try:
        if b"-----BEGIN PKCS7-----" in data:
            certs = pkcs7.load_pem_pkcs7_certificates(data)
        elif b"-----BEGIN" not in data:
            certs = pkcs7.load_der_pkcs7_certificates(data)
        else:
            return None
    except ValueError:
        return None
    if not certs:
        raise CertificateLoadError("PKCS#7 bundle contains no certificates")
    return certs


def _load_certificates(data: bytes) -> list[x509.Certificate]:
    """Load every certificate in *data* (PEM may hold several; DER holds one;
    a certs-only PKCS#7 bundle may hold several)."""
    pkcs7_certs = _maybe_pkcs7_certificates(data)
    if pkcs7_certs is not None:
        return pkcs7_certs
    if b"-----BEGIN" in data:
        try:
            certs = x509.load_pem_x509_certificates(data)
        except ValueError as exc:
            raise CertificateLoadError("could not parse certificate(s)") from exc
        if not certs:
            raise CertificateLoadError("no certificate found")
        return certs
    return [_load_certificate(data)]


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


def chain_sources(
    chain: CertSource | list[CertSource] | None,
) -> list[CertSource]:
    """*chain* as a list: one source, several, or none."""
    if chain is None:
        return []
    if isinstance(chain, list):
        return chain
    return [chain]


def resolve_chain(
    material: Material,
    chain: CertSource | list[CertSource] | None = None,
    *,
    prune: bool = False,
) -> Material:
    """*material* with its presented chain finalized.

    The single place the chain a session presents is decided, shared by the
    session constructors, :func:`~httpx_pki.build_ssl_context`, ``from_env``,
    and the reload path. ``chain`` appends intermediates a source arrived
    without; ``prune`` drops the ones that are not on the path from the leaf,
    for material whose chain the caller cannot edit.

    Both directions are here because they are one decision -- pruning must see
    the certificates ``chain`` added, or completing a bundle and tidying it
    would depend on the order they were applied in.
    """
    sources = chain_sources(chain)
    if sources:
        extra: list[bytes] = []
        for source in sources:
            # Each source may itself hold several certificates (a concatenated
            # PEM, or a certs-only PKCS#7); PEM-encode every one of them.
            extra.extend(
                c.public_bytes(serialization.Encoding.PEM)
                for c in _load_certificates(read_source(source))
            )
        material = replace(material, ca_pems=[*material.ca_pems, *extra])
    if not prune or not material.ca_pems:
        return material
    return _pruned(material)


def _pruned(material: Material) -> Material:
    """*material* without the chain certificates that are not on its path.

    Deferred import: :mod:`~httpx_pki._audit` builds on this module, so the
    dependency stays one-way -- the same arrangement :func:`parse_pkcs12` uses.
    """
    from ._audit import prune_off_path

    try:
        leaf = _load_certificate(material.cert_pem)
        certs = [_load_certificate(pem) for pem in material.ca_pems]
    except CertificateLoadError:
        return material  # nothing to reason about; leave it exactly as it was
    keep, dropped = prune_off_path(leaf, certs)
    if not dropped:
        return material
    if not keep:
        # Nothing was on the path, so pruning would leave a bare leaf and the
        # material would look like the ordinary "root not included" shape --
        # silencing chain.disconnected while the handshake still fails for
        # exactly the reason it named. Subtraction cannot fix an absence: leave
        # the certificates alone so the diagnosis survives.
        return material
    return replace(
        material,
        ca_pems=[c.public_bytes(serialization.Encoding.PEM) for c in keep],
    )


def normalize_pem(
    certificate: CertSource,
    private_key: CertSource,
    password: Password = None,
    chain: CertSource | list[CertSource] | None = None,
) -> Material:
    """Build canonical material from a separate certificate and private key.

    *certificate* holds the client (leaf) certificate; if it concatenates
    several PEM certs (a leaf-plus-intermediates bundle), the leaf is
    identified by matching the private key and the others are kept as chain.
    *chain* carries any further intermediate certificates to present to the
    server: a single source (which may itself concatenate several PEM certs)
    or a list of sources.

    *password* decrypts *private_key* only. An X.509 certificate is public data
    and is never encrypted in PEM, DER, or certs-only PKCS#7, so there is no
    corresponding certificate password anywhere in this path.
    """
    certs = _load_certificates(read_source(certificate))
    key = _load_private_key(read_source(private_key), encode_password(password))
    if len(certs) == 1:
        leaf = certs[0]
        # A mismatched key and certificate -- common when a .pem is assembled
        # by hand from the wrong pieces -- otherwise surfaces only as an
        # inscrutable OpenSSL handshake error.
        if _spki(key.public_key()) != _spki(leaf.public_key()):
            raise CertificateLoadError(
                "private key does not match certificate (their public keys differ)"
            )
        intermediates: list[x509.Certificate] = []
    else:
        leaf, intermediates = _split_leaf_and_chain(key, certs)

    for source in chain_sources(chain):
        intermediates.extend(_load_certificates(read_source(source)))

    return build_material(key, leaf, intermediates)


# The KeyUsage bits, under the cryptography attribute names, in RFC 5280 order.
KEY_USAGE_NAMES = (
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
    "encipher_only",
    "decipher_only",
)

# OID -> lowercase name, for the extended key usages cryptography names.
_EKU_NAMES: dict[x509.ObjectIdentifier, str] = {
    getattr(ExtendedKeyUsageOID, attr): attr.lower()
    for attr in dir(ExtendedKeyUsageOID)
    if not attr.startswith("_")
}


def _key_usage_names(cert: x509.Certificate) -> frozenset[str]:
    """The asserted KeyUsage bits as attribute names (empty if no extension)."""
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return frozenset()
    # encipher_only/decipher_only are only defined when keyAgreement is set --
    # cryptography raises ValueError rather than returning False otherwise.
    names = {name for name in KEY_USAGE_NAMES[:7] if getattr(usage, name)}
    if usage.key_agreement:
        names |= {
            name for name in KEY_USAGE_NAMES[7:] if getattr(usage, name)
        }
    return frozenset(names)


def _extended_key_usage_names(cert: x509.Certificate) -> list[str]:
    """The ExtendedKeyUsage entries as names, dotted OIDs when unnamed."""
    try:
        usages = cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
    except x509.ExtensionNotFound:
        return []
    return [_EKU_NAMES.get(oid, oid.dotted_string) for oid in usages]


def _name_cn(name: x509.Name) -> str | None:
    """The Common Name attribute of an x509 name (``None`` if absent)."""
    cn_attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not cn_attrs:
        return None
    value = cn_attrs[0].value
    return value if isinstance(value, str) else value.decode("utf-8")


def cert_info(cert_pem: bytes) -> CertInfo:
    """Summarize subject, issuer, validity, serial, fingerprints, and SANs."""
    return certificate_info(_load_certificate(cert_pem))


def certificate_info(cert: x509.Certificate) -> CertInfo:
    """:func:`cert_info` for an already-parsed certificate."""
    dns_names: list[str] = []
    sans: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        pass
    else:
        dns_names = san.get_values_for_type(x509.DNSName)
        # DNS first (the common case), then the other name types as strings.
        sans = list(dns_names)
        sans += [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
        sans += san.get_values_for_type(x509.RFC822Name)
        sans += san.get_values_for_type(x509.UniformResourceIdentifier)

    return CertInfo(
        common_name=_name_cn(cert.subject),
        distinguished_name=cert.subject.rfc4514_string(),
        issuer_common_name=_name_cn(cert.issuer),
        issuer_distinguished_name=cert.issuer.rfc4514_string(),
        serial_number=cert.serial_number,
        not_valid_before=cert.not_valid_before_utc,
        not_valid_after=cert.not_valid_after_utc,
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex().upper(),
        fingerprint_sha1=cert.fingerprint(hashes.SHA1()).hex().upper(),
        subject_alt_names=sans,
        dns_names=dns_names,
        key_usage=_key_usage_names(cert),
        extended_key_usage=_extended_key_usage_names(cert),
    )
