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

import certifi

from ._exceptions import CertificateLoadError, TLSConfigWarning
from ._keychain import MacPredicate
from ._material import (
    CertSource,
    Material,
    Password,
    encode_password,
    load_material,
    parse_pkcs12,
    read_source,
)
from ._winstore import Predicate

# Accepted values for ``verify``: ``True`` (default CA bundle), ``False``
# (no server verification), the literal string ``"system"`` (the OS trust
# store, via the optional truststore package), a path to a CA bundle, or a
# ready-made SSLContext.
VerifyTypes = bool | str | Path | ssl.SSLContext


def build_ssl_context(
    cert: CertSource,
    password: Password = None,
    *,
    verify: VerifyTypes = True,
) -> ssl.SSLContext:
    """Build a client-certificate ``ssl.SSLContext`` from a cert source.

    A convenience for callers who want the SSL context without the
    :class:`~httpx_pki.PKIClient` wrapper -- to mount on a plain
    :class:`httpx.Client`, an httpx transport, or any library that accepts an
    ``ssl.SSLContext``. *cert* is a PKCS#12 or PEM source (path or bytes; the
    encoding is detected from the content) and *verify* configures server trust
    exactly like httpx, plus the literal ``"system"`` for the OS trust store
    (requires the ``httpx-pki[system]`` extra).

        ctx = build_ssl_context("client.p12", password="secret")
        client = httpx.Client(verify=ctx)
    """
    material = load_material(read_source(cert), encode_password(password))
    return _context_from_material(material, verify)


def build_windows_ssl_context(  # pylint: disable=too-many-arguments
    name: str | None = None,
    *,
    thumbprint: str | None = None,
    predicate: Predicate | None = None,
    store: str = "MY",
    location: str = "CurrentUser",
    verify: VerifyTypes = True,
) -> ssl.SSLContext:
    """Build a client-certificate ``ssl.SSLContext`` from the Windows store.

    The :func:`build_ssl_context` counterpart of
    :meth:`~httpx_pki.PKIClient.from_windows_cert_store`: it selects an
    exportable certificate from the store -- by ``name`` (case-insensitive
    substring of the subject common name or friendly name), ``thumbprint``, or a
    ``predicate`` callable -- and returns the ``ssl.SSLContext`` presenting it,
    with server trust configured by *verify* exactly like httpx (plus the
    literal ``"system"`` for the OS trust store).

    Use it to mount a store certificate on a transport or a routing layer
    without building a whole :class:`~httpx_pki.PKIClient` just to read its
    ``ssl_context``. Windows only; see
    :meth:`~httpx_pki.PKIClient.from_windows_cert_store` for the errors raised.

        ctx = build_windows_ssl_context(
            predicate=lambda c: "Internal" in (c.friendly_name or "")
        )
        transport = httpx.HTTPTransport(verify=ctx)
    """
    from ._winstore import load_windows_pkcs12

    pfx, password = load_windows_pkcs12(
        name=name,
        thumbprint=thumbprint,
        predicate=predicate,
        store=store,
        location=location,
    )
    return _context_from_material(parse_pkcs12(pfx, password), verify)


def build_macos_ssl_context(
    name: str | None = None,
    *,
    thumbprint: str | None = None,
    predicate: MacPredicate | None = None,
    verify: VerifyTypes = True,
) -> ssl.SSLContext:
    """Build a client-certificate ``ssl.SSLContext`` from the macOS keychain.

    The :func:`build_ssl_context` counterpart of
    :meth:`~httpx_pki.PKIClient.from_macos_keychain`: it selects an exportable
    identity from the default keychain search list -- by ``name``
    (case-insensitive substring of the subject common name or keychain label),
    ``thumbprint``, or a ``predicate`` callable -- and returns the
    ``ssl.SSLContext`` presenting it, with server trust configured by *verify*
    exactly like httpx (plus the literal ``"system"`` for the OS trust store).

    macOS only; see :meth:`~httpx_pki.PKIClient.from_macos_keychain` for the
    errors raised.

        ctx = build_macos_ssl_context(name="ACME Client")
        transport = httpx.HTTPTransport(verify=ctx)
    """
    from ._keychain import load_macos_pkcs12

    pfx, password = load_macos_pkcs12(
        name=name, thumbprint=thumbprint, predicate=predicate
    )
    return _context_from_material(parse_pkcs12(pfx, password), verify)


def _context_from_material(
    material: Material, verify: VerifyTypes = True
) -> ssl.SSLContext:
    """Create an SSL context that verifies the server per *verify* and presents
    the client certificate held in *material*."""
    ctx = _server_trust_context(verify)
    _load_client_cert(ctx, material)
    return ctx


def _server_trust_context(verify: VerifyTypes) -> ssl.SSLContext:
    """Create a context per the *verify* policy.

    Every context built here honors the ``SSLKEYLOGFILE`` environment variable
    (TLS session keys are logged to that file, for Wireshark-style handshake
    debugging) -- via :func:`ssl.create_default_context`, or applied manually
    for the truststore-backed ``"system"`` mode. A caller-supplied context is
    returned as-is -- key logging on it is the caller's decision.
    """
    if isinstance(verify, ssl.SSLContext):
        warnings.warn(
            "verify= was given a pre-built ssl.SSLContext; httpx-pki loads the "
            "client certificate into it in place. Do not share this context with "
            "other clients -- use verify=True or a CA-bundle path (letting "
            "httpx-pki build a dedicated context) if it must stay cert-free.",
            TLSConfigWarning,
            stacklevel=3,
        )
        return verify
    if verify is True:
        return ssl.create_default_context(cafile=certifi.where())
    if verify == "system":
        # The literal str selects the OS trust store (Windows CryptoAPI, macOS
        # Security framework, OpenSSL's system CA paths on Linux) -- where
        # group-policy/MDM-distributed private CAs live, which certifi never
        # carries. A CA-bundle file that happens to be named "system" can
        # still be selected as Path("system").
        try:
            import truststore
        except ImportError as exc:
            raise ImportError(
                'verify="system" requires the truststore package; '
                "install it with: pip install httpx-pki[system]"
            ) from exc
        system_ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # create_default_context applies SSLKEYLOGFILE itself; truststore's
        # constructor does not, so apply it here to keep key logging uniform.
        keylog = os.environ.get("SSLKEYLOGFILE")
        if keylog:
            system_ctx.keylog_filename = keylog
        return system_ctx
    if verify is False:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        warnings.warn(
            "verify=False disables server certificate verification; "
            "connections are vulnerable to man-in-the-middle attacks.",
            TLSConfigWarning,
            stacklevel=3,
        )
        return ctx
    if isinstance(verify, (str, Path)):
        try:
            return ssl.create_default_context(cafile=os.fspath(verify))
        except OSError as exc:
            raise CertificateLoadError(
                f"could not load CA bundle {verify!r}: {exc}"
            ) from exc
    raise TypeError(
        'verify must be a bool, "system", a path, or an ssl.SSLContext, '
        f"got {type(verify).__name__}"
    )


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
