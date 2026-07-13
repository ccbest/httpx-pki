"""Turn canonical certificate material into an ``ssl.SSLContext``.

Server trust (which CAs we accept for the *server*) and the client certificate
we present are configured independently. ``verify`` controls the former exactly
like httpx; the client cert from :class:`~httpx_pki._material.Material` is always
loaded on top.
"""

from __future__ import annotations

import os
import ssl
import tempfile
import warnings
from pathlib import Path

import certifi

from ._exceptions import CertificateLoadError
from ._winstore import Predicate
from ._material import (
    CertSource,
    Material,
    Password,
    encode_password,
    load_material,
    parse_pkcs12,
    read_source,
)

# Accepted values for ``verify``: ``True`` (default CA bundle), ``False``
# (no server verification), a path to a CA bundle, or a ready-made SSLContext.
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
    exactly like httpx.

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
    with server trust configured by *verify* exactly like httpx.

    Use it to mount a store certificate on a transport or a routing layer
    without building a whole :class:`~httpx_pki.PKIClient` just to read its
    ``ssl_context``. Windows only; see
    :meth:`~httpx_pki.PKIClient.from_windows_cert_store` for the errors raised.

        ctx = build_windows_ssl_context(predicate=lambda c: "Internal" in (c.friendly_name or ""))
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


def _context_from_material(
    material: Material, verify: VerifyTypes = True
) -> ssl.SSLContext:
    """Create an SSL context that verifies the server per *verify* and presents
    the client certificate held in *material*."""
    ctx = _server_trust_context(verify)
    _load_client_cert(ctx, material)
    return ctx


def _server_trust_context(verify: VerifyTypes) -> ssl.SSLContext:
    if isinstance(verify, ssl.SSLContext):
        warnings.warn(
            "verify= was given a pre-built ssl.SSLContext; httpx-pki loads the "
            "client certificate into it in place. Do not share this context with "
            "other clients -- use verify=True or a CA-bundle path (letting "
            "httpx-pki build a dedicated context) if it must stay cert-free.",
            stacklevel=3,
        )
        return verify
    if verify is True:
        return ssl.create_default_context(cafile=certifi.where())
    if verify is False:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        warnings.warn(
            "verify=False disables server certificate verification; "
            "connections are vulnerable to man-in-the-middle attacks.",
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
        "verify must be a bool, a path, or an ssl.SSLContext, "
        f"got {type(verify).__name__}"
    )


def _load_client_cert(ctx: ssl.SSLContext, material: Material) -> None:
    # stdlib ssl can only load a cert chain from a file path, so the decrypted
    # key briefly lands in a 0600 temp file (mkstemp default) that we delete as
    # soon as OpenSSL has read it.
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(material.key_pem)
            handle.write(material.cert_pem)
            for ca_pem in material.ca_pems:
                handle.write(ca_pem)
        ctx.load_cert_chain(path)
    except ssl.SSLError as exc:
        raise CertificateLoadError(
            f"could not load client certificate chain: {exc}"
        ) from exc
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
