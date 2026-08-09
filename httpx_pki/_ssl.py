"""Turn canonical certificate material into an ``ssl.SSLContext``.

Server trust (which CAs we accept for the *server*) and the client certificate
we present are configured independently. ``verify`` controls the former exactly
like httpx; the client cert from :class:`~httpx_pki._material.Material` is always
loaded on top.
"""

from __future__ import annotations

import contextlib
import os
import ssl
import sys
import tempfile
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ._audit import (
    Problem,
    TrustSourceCerts,
    analyze_certificate,
    analyze_presented_chain,
    analyze_trust_sources,
    emit_warnings,
)
from ._exceptions import CertificateLoadError, TLSConfigWarning
from ._keychain import MacPredicate
from ._material import (
    CertSource,
    Material,
    Password,
    _load_certificate,
    _load_certificates,
    encode_password,
    load_material,
    read_source,
    resolve_chain,
)
from ._pkcs12 import IdentitySelector, material_from_store_export
from ._select import UsageSelector
from ._winstore import Predicate

# One source of server trust: ``True`` (the OS trust store, the default since
# 0.8 -- matching httpx2), the literal string ``"system"`` (a synonym of
# ``True``, kept from when the OS store was opt-in), the literal string
# ``"certifi"`` (the certifi CA bundle, which was the default through 0.7), or
# a path to a CA bundle (PEM, DER, or certs-only PKCS#7) or to a directory of
# them.
TrustSource = bool | str | Path

# Accepted values for ``verify``: one :data:`TrustSource`, several of them as a
# list (their anchors are combined), ``False`` (no server verification), or a
# ready-made SSLContext.
VerifyTypes = (
    TrustSource | ssl.SSLContext | list[TrustSource] | tuple[TrustSource, ...]
)


def build_ssl_context(  # pylint: disable=too-many-arguments
    source: CertSource,
    password: Password = None,
    *,
    verify: VerifyTypes = True,
    identity: IdentitySelector | None = None,
    key_usage: UsageSelector | None = None,
    extended_key_usage: UsageSelector | None = None,
    chain: CertSource | list[CertSource] | None = None,
    prune_chain: bool = False,
) -> ssl.SSLContext:
    """Build a client-certificate ``ssl.SSLContext`` from a cert source.

    A convenience for callers who want the SSL context without the
    :class:`~httpx_pki.PKIClient` wrapper -- to mount on a plain
    :class:`httpx.Client`, an httpx transport, or any library that accepts an
    ``ssl.SSLContext``. *source* is a PKCS#12 or PEM source (path or bytes; the
    encoding is detected from the content) and *verify* configures server trust
    exactly like httpx2 -- ``True``, the default, verifies against the OS trust
    store -- plus two httpx-pki literals: ``"system"`` (a synonym of ``True``)
    and ``"certifi"`` (the certifi CA bundle, the default through 0.7).

        ctx = build_ssl_context("client.p12", password="secret")
        client = httpx.Client(verify=ctx)

    Several trust sources combine -- ``verify=["system", "internal-ca.pem"]``
    verifies against the OS store *and* a private root, which naming a bundle
    on its own would replace rather than extend. An entry may also be a
    directory of certificates.

    ``identity`` / ``key_usage`` / ``extended_key_usage`` choose between the
    identities of a multi-identity PKCS#12 or PEM bundle, exactly as on
    :meth:`~httpx_pki.PKIClient.from_pkcs12`. ``chain`` presents further
    intermediate certificates alongside the client certificate, for a source
    that does not carry its own; ``prune_chain`` drops the ones that are not on
    its path, for a source whose chain you cannot edit.
    """
    material = resolve_chain(
        load_material(
            read_source(source),
            encode_password(password),
            identity=identity,
            key_usage=key_usage,
            extended_key_usage=extended_key_usage,
        ),
        chain,
        prune=prune_chain,
    )
    return _context_from_material(material, verify)


def build_windows_ssl_context(  # pylint: disable=too-many-arguments
    name: str | None = None,
    *,
    thumbprint: str | None = None,
    identity: str | Predicate | None = None,
    key_usage: UsageSelector | None = None,
    extended_key_usage: UsageSelector | None = None,
    store: str = "MY",
    location: str = "CurrentUser",
    verify: VerifyTypes = True,
) -> ssl.SSLContext:
    """Build a client-certificate ``ssl.SSLContext`` from the Windows store.

    The :func:`build_ssl_context` counterpart of
    :meth:`~httpx_pki.PKIClient.from_windows_cert_store`: it selects an
    exportable certificate from the store -- by ``name`` (case-insensitive
    substring of the subject common name or friendly name), ``thumbprint``, a
    ``identity`` (name substring, fingerprint, or predicate callable), or the
    ``key_usage`` / ``extended_key_usage`` it
    must assert -- and returns the ``ssl.SSLContext`` presenting it, with
    server trust configured by *verify* exactly like httpx2 (``True``, the
    default, is the OS trust store; the literal ``"certifi"`` pins the certifi
    bundle).

    Use it to mount a store certificate on a transport or a routing layer
    without building a whole :class:`~httpx_pki.PKIClient` just to read its
    ``ssl_context``. Windows only; see
    :meth:`~httpx_pki.PKIClient.from_windows_cert_store` for the errors
    raised::

        ctx = build_windows_ssl_context(
            identity=lambda c: "Internal" in (c.friendly_name or "")
        )
        transport = httpx.HTTPTransport(verify=ctx)
    """
    from ._winstore import load_windows_pkcs12

    pfx, password, chosen = load_windows_pkcs12(
        name=name,
        thumbprint=thumbprint,
        identity=identity,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
        store=store,
        location=location,
    )
    return _context_from_material(
        material_from_store_export(pfx, password, chosen), verify
    )


def build_macos_ssl_context(  # pylint: disable=too-many-arguments
    name: str | None = None,
    *,
    thumbprint: str | None = None,
    identity: str | MacPredicate | None = None,
    key_usage: UsageSelector | None = None,
    extended_key_usage: UsageSelector | None = None,
    verify: VerifyTypes = True,
) -> ssl.SSLContext:
    """Build a client-certificate ``ssl.SSLContext`` from the macOS keychain.

    The :func:`build_ssl_context` counterpart of
    :meth:`~httpx_pki.PKIClient.from_macos_keychain`: it selects an exportable
    identity from the default keychain search list -- by ``name``
    (case-insensitive substring of the subject common name or keychain label),
    ``thumbprint``, an ``identity`` (name substring, fingerprint, or
    predicate callable), or the ``key_usage`` /
    ``extended_key_usage`` it must assert -- and returns the
    ``ssl.SSLContext`` presenting it, with server trust configured by *verify*
    exactly like httpx2 (``True``, the default, is the OS trust store; the
    literal ``"certifi"`` pins the certifi bundle).

    macOS only; see :meth:`~httpx_pki.PKIClient.from_macos_keychain` for the
    errors raised.

        ctx = build_macos_ssl_context(name="ACME Client")
        transport = httpx.HTTPTransport(verify=ctx)
    """
    from ._keychain import load_macos_pkcs12

    pfx, password, chosen = load_macos_pkcs12(
        name=name,
        thumbprint=thumbprint,
        identity=identity,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
    )
    return _context_from_material(
        material_from_store_export(pfx, password, chosen), verify
    )


def _context_from_material(
    material: Material, verify: VerifyTypes = True
) -> ssl.SSLContext:
    """Create an SSL context that verifies the server per *verify* and presents
    the client certificate held in *material*."""
    ctx, trust_sources = _server_trust(verify)
    _load_client_cert(ctx, material)
    _offer_post_handshake_auth(ctx)
    _audit(material, trust_sources)
    return ctx


def _audit(material: Material, trust_sources: list[TrustSourceCerts]) -> None:
    """Run the advisory checks over what was just mounted.

    Placed on the one path every constructor funnels through, and wrapped so
    that nothing here can turn a working client into a failing one: the audit
    exists to explain a handshake that would have failed anyway, and a bug in
    it must not be the reason a load stops working. Warnings it does raise are
    ordinary :class:`~httpx_pki.TLSConfigWarning`\\ s and can be filtered.
    """
    try:
        emit_warnings(analyze(material, trust_sources))
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def analyze(
    material: Material, trust_sources: list[TrustSourceCerts]
) -> list[Problem]:
    """Every problem with *material* and the trust sources it will be used with.

    Shared by the construction-path warnings and :func:`~httpx_pki.explain`, so
    a report can never contradict the warning that sent someone to it.
    """
    client_cert = _load_certificate(material.cert_pem)
    chain = [_load_certificate(pem) for pem in material.ca_pems]
    return [
        *analyze_certificate(client_cert),
        *analyze_trust_sources(trust_sources, client_cert),
        *analyze_presented_chain(client_cert, chain),
    ]


def _offer_post_handshake_auth(ctx: ssl.SSLContext) -> None:
    """Offer TLS 1.3 post-handshake authentication (RFC 8446 section 4.6.2).

    A server that wants the client certificate only on *some* routes cannot
    know which route was asked for until it has read the request -- which is
    after the handshake. Through TLS 1.2 it got the certificate by
    renegotiating; TLS 1.3 removed renegotiation and replaced it, for this
    case, with a bare ``CertificateRequest`` the server may send once the
    handshake is done. Kestrel's ``ClientCertificateMode.DelayCertificate``,
    mod_ssl's per-``<Location>`` ``SSLVerifyClient``, and IIS's per-path
    negotiate-client-certificate all land here on a TLS 1.3 connection.

    A server may only ask a client that advertised willingness in its
    ClientHello, so this has to be decided before the connection carries
    anything -- there is nothing to negotiate per-request. A server that asks
    one which did not gets ``EXTENSION_NOT_RECEIVED`` and drops the
    connection, which reaches the caller as an unexplained EOF on a handshake
    that appeared to succeed. Since every context built here exists to present
    a client certificate, and already presents it unasked during the
    handshake, offering to present it later too costs nothing.

    The attribute is compiled in only when the interpreter's OpenSSL has TLS
    1.3, so it is set defensively: where it is missing there is no
    post-handshake auth to offer in the first place.
    """
    try:
        ctx.post_handshake_auth = True
    except (AttributeError, NotImplementedError):  # pragma: no cover
        pass


def _is_system(source: TrustSource) -> bool:
    """Whether *source* names the OS trust store."""
    return source is True or (isinstance(source, str) and source == "system")


def _normalize_trust_sources(verify: VerifyTypes) -> list[TrustSource]:
    """The trust sources in *verify* as a list, rejecting what cannot combine.

    A scalar becomes a one-element list, so a single source and a list of one
    take exactly the same path. ``False`` and a pre-built ``SSLContext`` are
    handled before this and are errors inside a list: neither can be merged
    with anything -- one turns verification off and the other is already a
    finished decision.
    """
    if not isinstance(verify, (list, tuple)):
        # ``False`` and a pre-built context are handled by the caller before
        # this point, so what is left is a single trust source.
        return [cast(TrustSource, verify)]
    if not verify:
        raise TypeError(
            "verify=[] has no trust sources. Pass at least one, or "
            "verify=False to disable verification."
        )
    for source in verify:
        if source is False:
            raise TypeError(
                "verify=False cannot be combined with other trust sources; "
                "pass it on its own."
            )
        if isinstance(source, ssl.SSLContext):
            raise TypeError(
                "a pre-built ssl.SSLContext cannot be combined with other "
                "trust sources; pass it on its own, or load the extra CAs into "
                "it yourself."
            )
        if not isinstance(source, (bool, str, Path)):
            raise TypeError(
                'each entry in a verify= list must be True, "system", '
                '"certifi", or a path to a CA bundle or directory, got '
                f"{type(source).__name__}"
            )
    return list(verify)


def _trust_cadata(source: TrustSource) -> tuple[str, list[x509.Certificate]]:
    """The PEM text *source* contributes, and its certificates for the audit.

    Everything is funnelled through ``cadata`` rather than ``cafile``: it is
    the one form that takes several sources, a directory, and the DER and
    PKCS#7 encodings OpenSSL will not read from a file, and it is what the
    platform verifiers see. truststore hands macOS and Windows the extra
    anchors via ``SSLContext.get_ca_certs()``, which reports what came from
    ``cafile``/``cadata`` but **not** from ``capath`` -- OpenSSL resolves a
    ``capath`` lazily by hashed filename and never enumerates it. A directory
    passed as ``capath`` would therefore contribute nothing on macOS and
    Windows while working on Linux, so directories are read here instead.
    Reading them also makes the common shape work at all: a directory mounted
    from a Kubernetes ConfigMap holds ``internal-ca.crt``, not the
    ``c_rehash``-style hashed names ``capath`` requires.

    The parsed certificates are returned for :mod:`httpx_pki._audit` only.
    Parsing is best-effort and never gates the load: PEM text is passed through
    as it was read, so a bundle OpenSSL accepts and ``cryptography`` does not
    keeps working and is merely not audited.
    """
    if isinstance(source, str) and source == "certifi":
        # The literal "certifi" pins the certifi CA bundle by name -- the
        # default trust through 0.7, for callers who want the bundled public
        # CAs regardless of what the OS store holds. Like "system", a
        # CA-bundle file named "certifi" can still be selected as
        # Path("certifi"). Not audited: it is curated, and parsing it is both
        # the most expensive thing here and the least likely to find anything.
        return Path(certifi.where()).read_text(encoding="ascii"), []

    path = Path(os.fspath(source))  # type: ignore[arg-type]
    if path.is_dir():
        return _trust_cadata_from_directory(path)

    try:
        data = read_source(path)
    except CertificateLoadError as exc:
        raise CertificateLoadError(f"could not load CA bundle {source!r}") from exc

    if b"-----BEGIN CERTIFICATE" in data:
        text = data.decode("ascii", errors="replace")
        try:
            return text, _load_certificates(data)
        except CertificateLoadError:
            return text, []  # OpenSSL's problem to accept or reject, not ours
    # DER, or a certs-only PKCS#7 (.p7b -- the usual Windows-CA chain export):
    # neither is readable as cafile, so normalize to PEM here.
    try:
        certificates = _load_certificates(data)
    except CertificateLoadError as exc:
        raise CertificateLoadError(
            f"could not load CA bundle {source!r}: not PEM, DER, or PKCS#7"
        ) from exc
    return _pem_text(certificates), certificates


def _trust_cadata_from_directory(
    path: Path,
) -> tuple[str, list[x509.Certificate]]:
    """Every certificate in *path*, one level deep.

    Files that do not parse as certificates are skipped rather than fatal: a
    CA directory routinely carries a ``README``, an OpenSSL hash symlink, or a
    CRL alongside the certificates. A directory that yields nothing at all is
    an error -- it is the one case that is certainly a mistake.
    """
    certificates: list[x509.Certificate] = []
    seen: set[bytes] = set()
    for entry in sorted(path.iterdir()):
        if not entry.is_file():
            continue
        try:
            found = _load_certificates(entry.read_bytes())
        except (CertificateLoadError, OSError):
            continue
        for cert in found:
            # Debian's /etc/ssl/certs holds both the hashed symlinks and the
            # concatenated ca-certificates.crt, so the same certificate turns
            # up several times.
            der = cert.public_bytes(serialization.Encoding.DER)
            if der not in seen:
                seen.add(der)
                certificates.append(cert)
    if not certificates:
        raise CertificateLoadError(
            f"CA directory {str(path)!r} contains no certificates"
        )
    return _pem_text(certificates), certificates


def _pem_text(certificates: list[x509.Certificate]) -> str:
    return b"".join(
        cert.public_bytes(serialization.Encoding.PEM) for cert in certificates
    ).decode("ascii")


def _truststore_context() -> ssl.SSLContext:
    """A context backed by the OS trust store.

    Windows CryptoAPI, the macOS Security framework, OpenSSL's system CA paths
    on Linux -- where group-policy/MDM-distributed private CAs live, which
    certifi never carries.
    """
    try:
        import truststore
    except ImportError as exc:
        raise ImportError(
            "the truststore package is required for verify=True and "
            'verify="system" (it is a dependency of httpx-pki since 0.8 '
            "-- a missing truststore means a broken install; reinstall "
            "httpx-pki)"
        ) from exc
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # create_default_context applies SSLKEYLOGFILE itself; truststore's
    # constructor does not, so apply it here to keep key logging uniform.
    keylog = os.environ.get("SSLKEYLOGFILE")
    if keylog:
        ctx.keylog_filename = keylog
    return ctx


def _server_trust(
    verify: VerifyTypes,
) -> tuple[ssl.SSLContext, list[TrustSourceCerts]]:
    """Create a context per the *verify* policy, plus what to audit.

    Every context built here honors the ``SSLKEYLOGFILE`` environment variable
    (TLS session keys are logged to that file, for Wireshark-style handshake
    debugging) -- via :func:`ssl.create_default_context`, or applied manually
    for the truststore-backed OS-store mode (``True`` / ``"system"``). A
    caller-supplied context is returned as-is -- key logging on it is the
    caller's decision.

    Several sources combine into one set of anchors. With ``system`` among
    them the base is a truststore context and the rest are loaded on top;
    truststore hands them to the platform verifier alongside the system
    anchors, so a private root verifies without displacing the public ones.
    (On Windows that is two sequential attempts rather than one union -- the
    system chain engine first, then one restricted to the extra anchors -- so
    a path that mixes anchors from both sets can fail there while succeeding
    on Linux and macOS. Nothing in reach of this library can change that.)
    """
    if isinstance(verify, ssl.SSLContext):
        warnings.warn(
            "verify= was given a pre-built ssl.SSLContext; httpx-pki loads the "
            "client certificate into it in place. Do not share this context with "
            "other clients -- use verify=True or a CA-bundle path (letting "
            "httpx-pki build a dedicated context) if it must stay cert-free.",
            TLSConfigWarning,
            stacklevel=4,
        )
        return verify, []
    if verify is False:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        warnings.warn(
            "verify=False disables server certificate verification; "
            "connections are vulnerable to man-in-the-middle attacks.",
            TLSConfigWarning,
            stacklevel=4,
        )
        return ctx, []

    sources = _normalize_trust_sources(verify)
    described: list[TrustSourceCerts] = []
    parts: list[str] = []
    use_system = False
    for source in sources:
        if _is_system(source):
            use_system = True
            described.append(
                TrustSourceCerts(label="system", kind="system")
            )
            continue
        text, certs = _trust_cadata(source)
        parts.append(text)
        described.append(
            TrustSourceCerts(
                label=_label(source), kind=_kind(source), certificates=certs
            )
        )
    cadata = "".join(parts)

    if use_system:
        ctx = _truststore_context()
        if cadata:
            ctx.load_verify_locations(cadata=cadata)
        return ctx, described
    # Passing cadata is also what keeps create_default_context from mixing in
    # the OS default CAs, which is the whole point of naming a bundle.
    return ssl.create_default_context(cadata=cadata), described


def _label(source: TrustSource) -> str:
    return source if isinstance(source, str) else str(source)


def _kind(source: TrustSource) -> str:
    """How a non-system trust source will be read, for the report."""
    if isinstance(source, str) and source == "certifi":
        return "certifi"
    try:
        if Path(os.fspath(source)).is_dir():  # type: ignore[arg-type]
            return "directory"
    except TypeError:
        pass
    return "bundle"


@contextlib.contextmanager
def _pem_chain_path(material: Material) -> Iterator[str]:
    """Yield a path OpenSSL can read the key + cert chain PEM from.

    On Linux the bytes are staged in an anonymous in-memory file (memfd),
    exposed as ``/proc/self/fd/N`` -- the decrypted key never touches disk,
    and closing the fd is the whole cleanup. Elsewhere (or in a Linux sandbox
    where memfd or procfs is unavailable) they land in a 0600 temp file
    (mkstemp default) that is deleted as soon as OpenSSL has read it.
    """
    pem = material.key_pem + material.cert_pem + b"".join(material.ca_pems)
    # os.memfd_create exists only if the interpreter was BUILT against a glibc
    # that has it -- some redistributed Linux builds (e.g. older
    # python-build-standalone) omit it entirely, so probe the attribute rather
    # than trusting sys.platform.
    memfd_create = getattr(os, "memfd_create", None)
    if sys.platform == "linux" and memfd_create is not None:
        try:
            # MFD_CLOEXEC keeps the fd from leaking into subprocesses; the
            # name is what shows up in /proc for debugging. The constant is
            # looked up defensively for the same build-variance reason (its
            # kernel ABI value is 1).
            # The `is not None` guard makes this callable; pylint cannot see
            # that when analyzed on an interpreter build lacking the symbol.
            # pylint: disable-next=not-callable
            memfd = memfd_create(
                "httpx-pki-client-cert", getattr(os, "MFD_CLOEXEC", 1)
            )
        except OSError:
            # e.g. blocked by a seccomp profile -- use the temp file below.
            memfd = -1
        if memfd != -1:
            try:
                proc_path = f"/proc/self/fd/{memfd}"
                # os.write may be partial; the buffered wrapper writes fully.
                # closefd=False: the fd must outlive this block -- OpenSSL
                # reopens proc_path (at offset 0) while load_cert_chain runs.
                with os.fdopen(memfd, "wb", closefd=False) as handle:
                    handle.write(pem)
                if os.path.exists(proc_path):  # no procfs -> temp file
                    yield proc_path
                    return
            finally:
                os.close(memfd)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem)
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _load_client_cert(ctx: ssl.SSLContext, material: Material) -> None:
    # stdlib ssl can only load a cert chain from a file path; _pem_chain_path
    # provides one while keeping the decrypted key off disk where possible.
    with _pem_chain_path(material) as path:
        try:
            ctx.load_cert_chain(path)
        except ssl.SSLError as exc:
            raise CertificateLoadError(
                f"could not load client certificate chain: {exc}"
            ) from exc
