"""Public session classes with a PKCS#12 client certificate mounted.

Both classes are thin: ``__init__``, the ``from_*`` alternate constructors, and
all certificate behavior live on :class:`~httpx_pki._mixin._PKIMixin`. Each
class contributes only the binding to its httpx base (:meth:`_httpx_init`) and
the per-request preflight hook in :meth:`send`.
"""

from __future__ import annotations

import ssl
from typing import Any

import httpx

from ._mixin import _PKIMixin


class PKIClient(_PKIMixin, httpx.Client):
    """
    A synchronous :class:`httpx.Client` that presents a client certificate.

    Construct it from a PKCS#12 bundle (``.p12``/``.pfx``) or a PEM file -- the
    encoding is detected from the bytes, not the file extension -- with an
    optional password::

        with PKIClient("client.p12", password="secret") as client:
            client.get("https://mtls.example.com/")

    Subclass it to layer on your own behavior, use it as a context manager, and
    pickle it (the pickle embeds the decrypted private key -- treat it as a
    secret). Any extra keyword arguments are passed straight to
    :class:`httpx.Client` (``base_url``, ``headers``, ``timeout``, ``http2`` ...).

    Every constructor also accepts ``warn_if_expires_within`` (warn about a
    certificate that is about to roll over) and ``strict_validity`` (run
    :meth:`check_validity` before every request, so an expired certificate
    fails loudly instead of as an OpenSSL handshake error). The file-based
    constructors additionally accept ``auto_reload`` (``True`` or a
    ``timedelta`` throttle -- watch the source files and pick up a rotated
    certificate automatically; see :meth:`reload`); the Windows-store and
    macOS-keychain constructors have no file to watch, but :meth:`reload`
    still re-exports from the store on demand.
    """

    def _httpx_init(self, *, verify: ssl.SSLContext, **kwargs: Any) -> None:
        httpx.Client.__init__(self, verify=verify, **kwargs)

    def send(self, request: httpx.Request, **kwargs: Any) -> httpx.Response:
        """Send the request, after the rotation / validity preflight."""
        self._preflight()
        return super().send(request, **kwargs)


class AsyncPKIClient(_PKIMixin, httpx.AsyncClient):
    """
    An asynchronous :class:`httpx.AsyncClient` that presents a client cert.

    The async counterpart of :class:`PKIClient`; the certificate, pickle,
    rotation, and alternate-constructor behavior are identical::

        async with AsyncPKIClient("client.p12", password="secret") as client:
            await client.get("https://mtls.example.com/")
    """

    def _httpx_init(self, *, verify: ssl.SSLContext, **kwargs: Any) -> None:
        httpx.AsyncClient.__init__(self, verify=verify, **kwargs)

    async def send(self, request: httpx.Request, **kwargs: Any) -> httpx.Response:
        """Send the request, after the rotation / validity preflight."""
        self._preflight()
        return await super().send(request, **kwargs)
