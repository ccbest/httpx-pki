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
from ._material import Material

# Accepted values for ``verify``: ``True`` (default CA bundle), ``False``
# (no server verification), a path to a CA bundle, or a ready-made SSLContext.
VerifyTypes = bool | str | Path | ssl.SSLContext


def build_ssl_context(material: Material, verify: VerifyTypes = True) -> ssl.SSLContext:
    """Create an SSL context that verifies the server per *verify* and presents
    the client certificate held in *material*."""
    ctx = _server_trust_context(verify)
    _load_client_cert(ctx, material)
    return ctx


def _server_trust_context(verify: VerifyTypes) -> ssl.SSLContext:
    if isinstance(verify, ssl.SSLContext):
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
