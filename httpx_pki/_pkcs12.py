"""Reading the identities out of a PKCS#12 bundle.

A PKCS#12 file may hold more than one *identity* -- a private key together with
its certificate. Two identities for the same subject is routine wherever a CA
escrows the encryption key but not the signing key (Entrust dual key pairs,
PIV/CAC, S/MIME key archival, several national eID schemes): one key pair is
marked ``keyEncipherment``, the other ``digitalSignature``, and only the key
usage tells them apart.

``cryptography`` cannot express that. ``load_key_and_certificates`` returns the
**first** private key in the file, pairs it with its certificate, and discards
every other key -- leaving the other identities' certificates indistinguishable
from CA chain certificates, which the session would then present as its chain.

So we read the structure ourselves, but only as far as the key bags.
Certificates (and their friendly names) still come from ``cryptography``, which
decrypts the file's encrypted portions for us. The key bags themselves sit in
plaintext ``SafeContents`` in every layout OpenSSL, Windows, and Java produce
(certificates go in an ``encryptedData``; keys are individually shrouded), and a
shrouded bag's value is an ``EncryptedPrivateKeyInfo`` that
:func:`~cryptography.hazmat.primitives.serialization.load_der_private_key`
decrypts -- so no password-based decryption is implemented here. Keys are then
paired to certificates by public key, the same rule the PEM path uses
(:func:`~httpx_pki._material._split_leaf_and_chain`).

A file whose key bags are *not* readable that way (an unfamiliar layout, or keys
hidden inside an ``encryptedData``) falls back to ``cryptography``'s single
identity -- exactly the behavior of earlier releases.
"""

from __future__ import annotations

import warnings
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12

from ._exceptions import (
    AmbiguousCertificateError,
    CertificateLoadError,
    CertificateNotFoundError,
)
from ._material import (
    CertInfo,
    CertSource,
    Material,
    Password,
    _pkcs12_failure_message,
    _spki,
    certificate_info,
    encode_password,
    pem_identities,
    read_source,
)
from ._select import (
    UsageSelector,
    _CertDetails,
    _narrowed,
    matches_usages,
    normalize_thumbprint,
)


@dataclass(frozen=True)
class P12Identity(_CertDetails):
    """One private key and its certificate inside a PKCS#12 or PEM bundle.

    ``index`` is the identity's position in the file -- for PKCS#12, ``0`` is
    the one every reader picks when asked for "the" key, including this
    library before identity selection existed. ``friendly_name`` is the label
    the exporting tool attached (``localKeyID``/``friendlyName`` bag
    attributes), often the only human hint about which identity is which; it
    is frequently absent -- and always ``None`` for PEM, which has no labels
    -- so prefer ``info.key_usage`` to tell a signing identity from an
    encryption one.

    The private key is deliberately *not* exposed here: listing what a file
    holds should not hand out its keys. Select the identity and build a session
    from it to use the key.
    """

    index: int
    friendly_name: str | None
    certificate: x509.Certificate
    # Excluded from __eq__/__hash__: it is derived from `certificate`, and the
    # lists it holds would make identities unhashable (so no set() of them).
    info: CertInfo = field(compare=False)

    @property
    def subject_cn(self) -> str | None:
        """The certificate's subject common name (``None`` if absent)."""
        return self.info.common_name

    @property
    def thumbprint(self) -> str:
        """The certificate's SHA-1 fingerprint, uppercase hex, no separators.

        The same format as the platform stores' thumbprints, so it can be fed
        straight back as an ``identity=`` selector.
        """
        return self.info.fingerprint_sha1


# How a caller names the identity they want: its file position, a name (a
# case-insensitive substring of the friendly name, common name, or full
# subject; or an exact SHA-1/SHA-256 fingerprint), or a predicate.
IdentitySelector = int | str | Callable[[P12Identity], bool]


@dataclass(frozen=True)
class _Loaded:
    """An identity plus the private key backing it (kept internal)."""

    identity: P12Identity
    key: PrivateKeyTypes


@dataclass(frozen=True)
class _Bundle:
    """Everything a PKCS#12 blob holds: its identities and all certificates."""

    identities: list[_Loaded] = field(default_factory=list)
    certificates: list[x509.Certificate] = field(default_factory=list)


# -- structure walking ------------------------------------------------------

_OID_DATA = "1.2.840.113549.1.7.1"
_OID_KEY_BAG = "1.2.840.113549.1.12.10.1.1"
_OID_SHROUDED_KEY_BAG = "1.2.840.113549.1.12.10.1.2"
_OID_FRIENDLY_NAME = "1.2.840.113549.1.9.20"

_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31
_TAG_OID = 0x06
_TAG_OCTET_STRING = 0x04
_TAG_BMP_STRING = 0x1E
_TAG_CONTEXT_0 = 0xA0


class _MalformedDER(Exception):
    """The bytes don't match the DER shape we expect; give up on the walk."""


@dataclass(frozen=True)
class _KeyBag:
    """A key bag found in the plaintext part of a PKCS#12 file."""

    value: bytes  # PrivateKeyInfo, or EncryptedPrivateKeyInfo when shrouded
    shrouded: bool
    friendly_name: str | None


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Return ``(tag, contents, next_offset)`` for the TLV at *offset*."""
    try:
        tag = data[offset]
        length = data[offset + 1]
    except IndexError as exc:
        raise _MalformedDER("truncated") from exc
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        # 0x80 is BER's indefinite length: legal in BER, not in the DER
        # PKCS#12 mandates, and not worth supporting -- bail to the fallback.
        if count == 0 or count > 4:
            raise _MalformedDER("unsupported length encoding")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    end = offset + length
    if end > len(data):
        raise _MalformedDER("length runs past the end of the data")
    return tag, data[offset:end], end


def _elements(body: bytes) -> Iterator[tuple[int, bytes]]:
    """Iterate the TLVs packed in *body* (the contents of a SEQUENCE/SET)."""
    offset = 0
    while offset < len(body):
        tag, contents, offset = _read_tlv(body, offset)
        yield tag, contents


def _expect(body: bytes, tag: int) -> bytes:
    """The contents of the single TLV in *body*, which must carry *tag*."""
    found, contents, end = _read_tlv(body, 0)
    if found != tag or end != len(body):
        raise _MalformedDER(f"expected tag {tag:#x}, got {found:#x}")
    return contents


def _read_oid(body: bytes) -> str:
    """Decode an OBJECT IDENTIFIER's contents to dotted form."""
    if not body:
        raise _MalformedDER("empty OID")
    parts = [str(body[0] // 40), str(body[0] % 40)]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _bag_friendly_name(attributes: bytes) -> str | None:
    """The friendlyName from a bag's attribute SET, if it carries one."""
    for tag, attribute in _elements(attributes):
        if tag != _TAG_SEQUENCE:
            continue
        items = list(_elements(attribute))
        if len(items) != 2 or items[0][0] != _TAG_OID:
            continue
        if _read_oid(items[0][1]) != _OID_FRIENDLY_NAME:
            continue
        for value_tag, value in _elements(items[1][1]):
            if value_tag == _TAG_BMP_STRING:
                return value.decode("utf-16-be", errors="replace")
    return None


def _safe_contents_key_bags(safe_contents: bytes) -> Iterator[_KeyBag]:
    """Yield the key bags in one (already plaintext) SafeContents."""
    for tag, bag in _elements(safe_contents):
        if tag != _TAG_SEQUENCE:
            continue
        items = list(_elements(bag))
        if len(items) < 2 or items[0][0] != _TAG_OID:
            continue
        bag_id = _read_oid(items[0][1])
        if bag_id not in (_OID_KEY_BAG, _OID_SHROUDED_KEY_BAG):
            continue
        if items[1][0] != _TAG_CONTEXT_0:
            continue
        # bagValue is [0] EXPLICIT, so its contents are the key structure
        # itself -- re-encode it as the standalone DER cryptography expects.
        inner_tag, inner, _ = _read_tlv(items[1][1], 0)
        if inner_tag != _TAG_SEQUENCE:
            continue
        attributes = items[2][1] if len(items) > 2 and items[2][0] == _TAG_SET else b""
        yield _KeyBag(
            value=_reencode(inner_tag, inner),
            shrouded=bag_id == _OID_SHROUDED_KEY_BAG,
            friendly_name=_bag_friendly_name(attributes) if attributes else None,
        )


def _reencode(tag: int, contents: bytes) -> bytes:
    """Wrap *contents* back up in its tag and DER length."""
    length = len(contents)
    if length < 0x80:
        header = bytes([tag, length])
    else:
        body = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([tag, 0x80 | len(body)]) + body
    return header + contents


def _walk_key_bags(data: bytes) -> list[_KeyBag]:
    """Every key bag in the plaintext SafeContents of a PKCS#12 blob.

    Returns an empty list for anything that doesn't parse as the expected
    structure -- the caller falls back to ``cryptography``'s view rather than
    failing a load that used to work.
    """
    try:
        pfx = _expect(data, _TAG_SEQUENCE)
        elements = list(_elements(pfx))
        if len(elements) < 2:
            raise _MalformedDER("PFX has no authSafe")
        authsafe = _content_info_data(elements[1][1])
        if authsafe is None:
            raise _MalformedDER("authSafe is not a data ContentInfo")
        bags: list[_KeyBag] = []
        for tag, content_info in _elements(_expect(authsafe, _TAG_SEQUENCE)):
            if tag != _TAG_SEQUENCE:
                continue
            # An encryptedData ContentInfo holds the certificates; its bags are
            # opaque without decrypting, and we get those certs from
            # cryptography anyway.
            safe_contents = _content_info_data(content_info)
            if safe_contents is None:
                continue
            bags.extend(
                _safe_contents_key_bags(_expect(safe_contents, _TAG_SEQUENCE))
            )
        return bags
    except _MalformedDER:
        return []


def _content_info_data(content_info: bytes) -> bytes | None:
    """The octets of a ``data`` ContentInfo; ``None`` for any other type."""
    items = list(_elements(content_info))
    if len(items) < 2 or items[0][0] != _TAG_OID:
        return None
    if _read_oid(items[0][1]) != _OID_DATA:
        return None
    if items[1][0] != _TAG_CONTEXT_0:
        return None
    # [0] EXPLICIT OCTET STRING; a constructed (segmented) octet string is BER,
    # which we don't handle -- _expect rejects it via the tag check.
    return _expect(items[1][1], _TAG_OCTET_STRING)


# -- enumeration ------------------------------------------------------------


def _load_bag_key(bag: _KeyBag, password: bytes | None) -> PrivateKeyTypes | None:
    """Decrypt one key bag, or ``None`` if it can't be read.

    An unreadable bag is skipped rather than fatal: the rest of the file is
    still usable, and the identity it would have produced simply isn't offered.
    """
    # An "empty password" PKCS#12 is written with b"" by some tools and with no
    # password at all by others, and a bag's encryption doesn't have to agree
    # with the file's MAC -- so try the alternatives before giving up.
    candidates: list[bytes | None] = [password, None if password else b"", None]
    for candidate in dict.fromkeys(candidates):
        try:
            return serialization.load_der_private_key(
                bag.value, candidate if bag.shrouded else None
            )
        except (ValueError, TypeError):
            continue
    return None


def _friendly_name(name: bytes | None) -> str | None:
    return None if name is None else name.decode("utf-8", errors="replace")


def load_bundle(data: bytes, password: bytes | None) -> _Bundle:
    """Every identity and certificate in a PKCS#12 blob, in file order."""
    try:
        parsed = pkcs12.load_pkcs12(data, password)
    except (ValueError, TypeError) as exc:
        raise CertificateLoadError(_pkcs12_failure_message(data)) from exc

    entries = list(parsed.additional_certs)
    if parsed.cert is not None:
        # cryptography hands back the cert paired with the first key first;
        # keeping that order makes single-identity material byte-identical to
        # what earlier releases produced.
        entries.insert(0, parsed.cert)
    certificates = [entry.certificate for entry in entries]
    # Keyed by the certificate's own bytes: two certificates can share a public
    # key (a renewal keeps the key pair), and they may be labeled differently.
    names = {
        entry.certificate.public_bytes(serialization.Encoding.DER): _friendly_name(
            entry.friendly_name
        )
        for entry in entries
    }

    identities: list[_Loaded] = []
    seen: set[tuple[bytes, bytes]] = set()  # (key SPKI, certificate DER)
    for bag in _walk_key_bags(data):
        key = _load_bag_key(bag, password)
        if key is None:
            continue
        spki = _spki(key.public_key())
        # One identity per certificate the key belongs to, not per key: a
        # renewed certificate is commonly stored alongside the one it replaces
        # under the *same* key pair, and those are two identities to choose
        # between -- not one identity plus a stray chain certificate.
        for certificate in certificates:
            if _spki(certificate.public_key()) != spki:
                continue
            der = certificate.public_bytes(serialization.Encoding.DER)
            if (spki, der) in seen:
                continue
            seen.add((spki, der))
            identities.append(
                _make_identity(
                    len(identities),
                    certificate,
                    names.get(der) or bag.friendly_name,
                    key,
                )
            )

    # Whatever cryptography itself found must always be offered, even if the
    # walk missed its bag (hidden inside an encryptedData, or an exotic
    # layout): it is by definition the first key in the file.
    if parsed.key is not None and parsed.cert is not None:
        spki = _spki(parsed.key.public_key())
        if spki not in {key_spki for key_spki, _ in seen}:
            identities.insert(
                0,
                _make_identity(
                    0,
                    parsed.cert.certificate,
                    _friendly_name(parsed.cert.friendly_name),
                    parsed.key,
                ),
            )
            identities = [
                _Loaded(_renumber(loaded.identity, i), loaded.key)
                for i, loaded in enumerate(identities)
            ]
    return _Bundle(identities=identities, certificates=certificates)


def _make_identity(
    index: int,
    certificate: x509.Certificate,
    friendly_name: str | None,
    key: PrivateKeyTypes,
) -> _Loaded:
    return _Loaded(
        identity=P12Identity(
            index=index,
            friendly_name=friendly_name,
            certificate=certificate,
            info=certificate_info(certificate),
        ),
        key=key,
    )


def _renumber(identity: P12Identity, index: int) -> P12Identity:
    if identity.index == index:
        return identity
    return P12Identity(
        index=index,
        friendly_name=identity.friendly_name,
        certificate=identity.certificate,
        info=identity.info,
    )


def list_pkcs12_identities(
    source: CertSource, password: Password = None
) -> list[P12Identity]:
    """List the identities (key + certificate pairs) in a PKCS#12 bundle.

    *source* is a path or the bytes themselves, exactly like a session
    constructor's certificate argument. Use it to find out whether a file holds
    more than one identity, and to see what distinguishes them::

        for identity in list_pkcs12_identities("corp.p12", password="secret"):
            print(identity.index, identity.info.common_name,
                  sorted(identity.info.key_usage))

    The private keys are not returned -- pass a selector to a session
    constructor (``identity=``, ``key_usage=``, ``extended_key_usage=``) to
    actually use one.

    Raises :class:`~httpx_pki.CertificateLoadError` if the data isn't a
    readable PKCS#12 bundle (a wrong password lands here too). For a source
    that may be PEM instead, see :func:`~httpx_pki.list_identities`.
    """
    bundle = load_bundle(read_source(source), encode_password(password))
    return [loaded.identity for loaded in bundle.identities]


def list_identities(
    source: CertSource, password: Password = None
) -> list[P12Identity]:
    """List the identities in a certificate source, PKCS#12 or PEM.

    The content-detecting sibling of :func:`~httpx_pki.list_pkcs12_identities`:
    it accepts exactly what a session constructor's certificate source accepts
    -- a path or bytes, PEM recognized by its ``-----BEGIN`` armor, anything
    else read as PKCS#12 -- and reports what the file holds without exposing
    any private key. A PEM identity is a private key block paired with the
    certificate matching its public key; PEM carries no labels, so
    ``friendly_name`` is always ``None`` there.
    """
    data = read_source(source)
    encoded = encode_password(password)
    if b"-----BEGIN" in data:
        return pem_identities(data, encoded)
    bundle = load_bundle(data, encoded)
    return [loaded.identity for loaded in bundle.identities]


# -- selection --------------------------------------------------------------


def _matches_name(identity: P12Identity, needle: str) -> bool:
    """Fingerprint equality for a hex digest, else a case-insensitive substring."""
    target = normalize_thumbprint(needle)
    if len(target) in (40, 64) and all(c in "0123456789ABCDEF" for c in target):
        return target in (
            identity.info.fingerprint_sha1,
            identity.info.fingerprint_sha256,
        )
    lowered = needle.lower()
    return any(
        alias is not None and lowered in alias.lower()
        for alias in (
            identity.friendly_name,
            identity.info.common_name,
            identity.info.distinguished_name,
        )
    )


def select_identity(
    identities: list[P12Identity],
    *,
    identity: IdentitySelector | None = None,
    key_usage: UsageSelector | None = None,
    extended_key_usage: UsageSelector | None = None,
    source_kind: str = "PKCS#12 data",
) -> P12Identity:
    """Choose one identity from *identities*.

    Every given selector must match (they intersect): ``identity`` picks by
    file position, name, fingerprint, or predicate, while ``key_usage`` and
    ``extended_key_usage`` require the named usages to be present -- the usual
    way to separate a signing identity from an encryption one.
    ``identity=currently_valid`` picks the identity whose validity window
    contains now, preferring the renewed one during a renewal overlap.
    *source_kind* names the container in error messages (the same selection
    serves PKCS#12 and multi-identity PEM bundles).

    Raises :class:`~httpx_pki.CertificateNotFoundError` if nothing matches and
    :class:`~httpx_pki.AmbiguousCertificateError` if more than one does --
    including the no-selector case, where picking the file's first identity
    would be an arbitrary choice between real alternatives.
    """
    matches = list(identities)
    described: list[str] = []

    if identity is not None:
        described.append(f"identity={identity!r}")
        matches = _apply_identity_selector(matches, identity, len(identities))
    if key_usage is not None:
        described.append(f"key_usage={key_usage!r}")
    if extended_key_usage is not None:
        described.append(f"extended_key_usage={extended_key_usage!r}")
    if key_usage is not None or extended_key_usage is not None:
        # Shared with the platform stores so the two never drift; it also
        # validates the names, so a typo raises here rather than matching
        # nothing.
        matches = [
            i for i in matches if matches_usages(i, key_usage, extended_key_usage)
        ]
    if identity is not None:
        # After every filter has intersected: a selector carrying a tie-break
        # (currently_valid) must never override an explicit usage selector.
        matches = _narrowed(identity, matches)

    selector = " + ".join(described)
    if not matches:
        raise CertificateNotFoundError(
            f"{selector} matched no identity in the {source_kind}, which holds:"
            f"\n{_listing(identities)}"
        )
    if len(matches) > 1:
        if not selector:
            raise AmbiguousCertificateError(
                f"this {source_kind} holds {len(matches)} identities:"
                f"\n{_listing(matches)}\n"
                "Pick one with identity= (index, name, or fingerprint), "
                "key_usage=, or extended_key_usage=."
            )
        raise AmbiguousCertificateError(
            f"{selector} matched {len(matches)} identities:"
            f"\n{_listing(matches)}\n"
            "Narrow it with a more specific selector, or an exact "
            "index or fingerprint."
        )
    return matches[0]


def _apply_identity_selector(
    matches: list[P12Identity], selector: IdentitySelector, total: int
) -> list[P12Identity]:
    if isinstance(selector, bool):
        # bool is an int; True meaning "index 1" would be nobody's intent.
        raise TypeError("identity must be an int, a string, or a callable")
    if isinstance(selector, int):
        wanted = selector if selector >= 0 else total + selector
        return [i for i in matches if i.index == wanted]
    if isinstance(selector, str):
        return [i for i in matches if _matches_name(i, selector)]
    if callable(selector):
        return [i for i in matches if selector(i)]
    raise TypeError(
        "identity must be an int (file position), a string (name or "
        "fingerprint), or a callable, got "
        f"{type(selector).__name__}"
    )


def _listing(identities: list[P12Identity]) -> str:
    """The identities as one indented line each, for an error message.

    Everything that plausibly distinguishes two identities is on the line: the
    usage separates a dual key pair, and the expiry separates a renewed
    certificate from the one it replaces (which share everything else). The
    extended usage appears when any identity carries one, since that is what
    :data:`~httpx_pki.for_mtls` filters on and therefore what explains a miss.
    """
    lines = []
    show_eku = any(i.info.extended_key_usage for i in identities)
    for i in identities:
        parts = [f"  [{i.index}] {i.info.common_name or '<no CN>'}"]
        if i.friendly_name:
            parts.append(f"({i.friendly_name})")
        parts.append(f"key_usage={','.join(sorted(i.info.key_usage)) or '<none>'}")
        if show_eku:
            eku = ",".join(i.info.extended_key_usage) or "<none>"
            parts.append(f"ext_key_usage={eku}")
        parts.append(f"expires={i.info.not_valid_after:%Y-%m-%d}")
        parts.append(i.info.fingerprint_sha1)
        lines.append(" ".join(parts))
    return "\n".join(lines)


# -- material ---------------------------------------------------------------


def material_from_store_export(
    data: bytes, password: bytes | None, thumbprint: str
) -> Material:
    """Material for the certificate a platform store just exported.

    The export holds the one identity we selected, so pinning its thumbprint is
    normally a formality -- but it keeps a store that exports more than we asked
    for from tripping the ambiguity guard, which the caller could do nothing
    about.

    If the pin matches nothing, the export didn't contain the certificate we
    picked. No platform should do that, and guessing is better than failing on a
    selector the caller never wrote: fall back to the unpinned load so the real
    problem surfaces as itself.

    Platform exports are also not always strict DER -- the macOS Security
    framework writes a field whose ASN.1 DEFAULT already implies it, so
    ``cryptography`` warns and re-parses as BER. The caller cannot influence
    bytes the operating system generated and this code consumed, so that
    warning is silenced here; it is left in place for caller-supplied files,
    where re-exporting the file is a real fix.
    """
    with warnings.catch_warnings():
        # Narrow by message as well as category: this must not mask any other
        # warning cryptography raises about the material.
        warnings.filterwarnings(
            "ignore",
            message=".*could not be parsed as DER.*",
            category=UserWarning,
        )
        try:
            return pkcs12_material(data, password, identity=thumbprint)
        except CertificateNotFoundError:
            return pkcs12_material(data, password)
        except CertificateLoadError as exc:
            # cryptography warns today that the BER fallback "may become an
            # exception". If it ever does, the generic message ("invalid
            # PKCS#12 data or wrong password") would send someone hunting a
            # password that this library generated itself.
            raise CertificateLoadError(
                "the certificate exported by the platform store could not be "
                "parsed. Platform exports are not always strict DER, which "
                "cryptography has warned about and may have stopped accepting"
            ) from exc


def pkcs12_material(
    data: bytes,
    password: bytes | None,
    *,
    identity: IdentitySelector | None = None,
    key_usage: UsageSelector | None = None,
    extended_key_usage: UsageSelector | None = None,
) -> Material:
    """Extract decrypted PEM material for one identity in a PKCS#12 blob.

    With no selector a single-identity file loads as it always has; a file
    holding several raises :class:`~httpx_pki.AmbiguousCertificateError` rather
    than presenting whichever identity happens to be stored first.

    The certificates belonging to the *other* identities are excluded from the
    chain -- they are leaf certificates of their own, not intermediates on the
    way to a CA, and presenting them can make a strict server reject the chain.
    """
    bundle = load_bundle(data, password)
    if not bundle.identities:
        if not bundle.certificates:
            raise CertificateLoadError("PKCS#12 data contains no certificate")
        raise CertificateLoadError("PKCS#12 data contains no private key")

    chosen = select_identity(
        [loaded.identity for loaded in bundle.identities],
        identity=identity,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
    )
    selected = bundle.identities[chosen.index]
    leaves = {
        loaded.identity.certificate.public_bytes(serialization.Encoding.DER)
        for loaded in bundle.identities
    }

    key_pem = selected.key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = chosen.certificate.public_bytes(serialization.Encoding.PEM)
    ca_pems = [
        cert.public_bytes(serialization.Encoding.PEM)
        for cert in bundle.certificates
        if cert.public_bytes(serialization.Encoding.DER) not in leaves
    ]
    return Material(key_pem=key_pem, cert_pem=cert_pem, ca_pems=ca_pems)
