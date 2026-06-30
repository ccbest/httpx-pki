"""Public session classes with a PKCS#12 client certificate mounted."""

from __future__ import annotations

import datetime
import ssl
from typing import Any

import httpx

from ._env import resolve_env_material
from ._material import (
    CertSource,
    Password,
    encode_password,
    load_material,
    normalize_pem,
    parse_pem_bundle,
    parse_pkcs12,
    read_source,
)
from ._mixin import _PKIMixin
from ._ssl import VerifyTypes
from ._winstore import Predicate


class PKCSession(_PKIMixin, httpx.Client):
    """
    A synchronous :class:`httpx.Client` that presents a client certificate.

    Construct it from a PKCS#12 bundle (``.p12``/``.pfx``) or a PEM file -- the
    encoding is detected from the bytes, not the file extension -- with an
    optional password::

        with PKCSession("client.p12", password="secret") as client:
            client.get("https://mtls.example.com/")

    Subclass it to layer on your own behavior, use it as a context manager, and
    pickle it (the pickle embeds the decrypted private key -- treat it as a
    secret). Any extra keyword arguments are passed straight to
    :class:`httpx.Client` (``base_url``, ``headers``, ``timeout``, ``http2`` ...).
    """

    def __init__(  # pylint: disable=W0231
        self,
        cert: CertSource,
        password: Password = None,
        *,
        verify: VerifyTypes = True,
        warn_if_expires_within: datetime.timedelta | None = None,
        **kwargs: Any,
    ) -> None:
        material = load_material(read_source(cert), encode_password(password))
        self._apply_material(
            material,
            verify=verify,
            warn_if_expires_within=warn_if_expires_within,
            **kwargs,
        )

    def _httpx_init(self, *, verify: ssl.SSLContext, **kwargs: Any) -> None:
        httpx.Client.__init__(self, verify=verify, **kwargs)

    @classmethod
    def from_env(
        cls,
        prefix: str = "HTTPX_PKI_",
        *,
        verify: VerifyTypes | None = None,
        **kwargs: Any,
    ) -> PKCSession:
        """Build a session from ``{prefix}*`` environment variables.

        Reads ``{prefix}CERT`` (required), ``{prefix}PASSWORD``, ``{prefix}KEY``
        (switches to a separate cert+key), and ``{prefix}CA`` (server-trust
        bundle). An explicit *verify* overrides ``{prefix}CA``.
        """
        material, env_verify = resolve_env_material(prefix)
        return cls._from_material(
            material, verify=env_verify if verify is None else verify, **kwargs
        )

    @classmethod
    def from_pkcs12(
        cls,
        cert: CertSource,
        password: Password = None,
        *,
        verify: VerifyTypes = True,
        **kwargs: Any,
    ) -> PKCSession:
        """Build a session from a PKCS#12 bundle (path or bytes)."""
        material = parse_pkcs12(read_source(cert), encode_password(password))
        return cls._from_material(material, verify=verify, **kwargs)

    @classmethod
    def from_pem(
        cls,
        source: CertSource,
        password: Password = None,
        *,
        verify: VerifyTypes = True,
        **kwargs: Any,
    ) -> PKCSession:
        """Build a session from a single PEM blob holding the key and cert(s)."""
        material = parse_pem_bundle(read_source(source), encode_password(password))
        return cls._from_material(material, verify=verify, **kwargs)

    @classmethod
    def from_key_pair(
        cls,
        certificate: CertSource,
        private_key: CertSource,
        *,
        key_password: Password = None,
        ca: CertSource | list[CertSource] | None = None,
        verify: VerifyTypes = True,
        **kwargs: Any,
    ) -> PKCSession:
        """Build a session from a separate certificate and private key."""
        material = normalize_pem(certificate, private_key, key_password, ca)
        return cls._from_material(material, verify=verify, **kwargs)

    @classmethod
    def from_windows_cert_store(  # pylint: disable=too-many-arguments
        cls,
        name: str | None = None,
        *,
        thumbprint: str | None = None,
        predicate: Predicate | None = None,
        store: str = "MY",
        location: str = "CurrentUser",
        verify: VerifyTypes = True,
        **kwargs: Any,
    ) -> PKCSession:
        """Build a session from an exportable certificate in the Windows store.

        Windows only. Selects the certificate by ``name`` (case-insensitive
        substring of the subject common name or friendly name), or unambiguously
        by ``thumbprint`` or a ``predicate`` callable. The matching certificate's
        private key must be marked exportable.

        Raises :class:`~httpx_pki.UnsupportedPlatformError` off Windows,
        :class:`~httpx_pki.CertificateNotFoundError` if nothing matches, and
        :class:`~httpx_pki.AmbiguousCertificateError` if several do.
        """
        from ._winstore import load_windows_pkcs12

        pfx, password = load_windows_pkcs12(
            name=name,
            thumbprint=thumbprint,
            predicate=predicate,
            store=store,
            location=location,
        )
        return cls._from_material(parse_pkcs12(pfx, password), verify=verify, **kwargs)


class AsyncPKCSession(_PKIMixin, httpx.AsyncClient):
    """
    An asynchronous :class:`httpx.AsyncClient` that presents a client cert.

    The async counterpart of :class:`PKCSession`; the certificate, pickle, and
    alternate-constructor behavior are identical::

        async with AsyncPKCSession("client.p12", password="secret") as client:
            await client.get("https://mtls.example.com/")
    """

    def __init__(  # pylint: disable=W0231
        self,
        cert: CertSource,
        password: Password = None,
        *,
        verify: VerifyTypes = True,
        warn_if_expires_within: datetime.timedelta | None = None,
        **kwargs: Any,
    ) -> None:
        material = load_material(read_source(cert), encode_password(password))
        self._apply_material(
            material,
            verify=verify,
            warn_if_expires_within=warn_if_expires_within,
            **kwargs,
        )

    def _httpx_init(self, *, verify: ssl.SSLContext, **kwargs: Any) -> None:
        httpx.AsyncClient.__init__(self, verify=verify, **kwargs)

    @classmethod
    def from_env(
        cls,
        prefix: str = "HTTPX_PKI_",
        *,
        verify: VerifyTypes | None = None,
        **kwargs: Any,
    ) -> AsyncPKCSession:
        """Async counterpart of :meth:`PKCSession.from_env`."""
        material, env_verify = resolve_env_material(prefix)
        return cls._from_material(
            material, verify=env_verify if verify is None else verify, **kwargs
        )

    @classmethod
    def from_pkcs12(
        cls,
        cert: CertSource,
        password: Password = None,
        *,
        verify: VerifyTypes = True,
        **kwargs: Any,
    ) -> AsyncPKCSession:
        """Build a session from a PKCS#12 bundle (path or bytes)."""
        material = parse_pkcs12(read_source(cert), encode_password(password))
        return cls._from_material(material, verify=verify, **kwargs)

    @classmethod
    def from_pem(
        cls,
        source: CertSource,
        password: Password = None,
        *,
        verify: VerifyTypes = True,
        **kwargs: Any,
    ) -> AsyncPKCSession:
        """Build a session from a single PEM blob holding the key and cert(s)."""
        material = parse_pem_bundle(read_source(source), encode_password(password))
        return cls._from_material(material, verify=verify, **kwargs)

    @classmethod
    def from_key_pair(
        cls,
        certificate: CertSource,
        private_key: CertSource,
        *,
        key_password: Password = None,
        ca: CertSource | list[CertSource] | None = None,
        verify: VerifyTypes = True,
        **kwargs: Any,
    ) -> AsyncPKCSession:
        """Build a session from a separate certificate and private key."""
        material = normalize_pem(certificate, private_key, key_password, ca)
        return cls._from_material(material, verify=verify, **kwargs)

    @classmethod
    def from_windows_cert_store(  # pylint: disable=too-many-arguments
        cls,
        name: str | None = None,
        *,
        thumbprint: str | None = None,
        predicate: Predicate | None = None,
        store: str = "MY",
        location: str = "CurrentUser",
        verify: VerifyTypes = True,
        **kwargs: Any,
    ) -> AsyncPKCSession:
        """Async counterpart of :meth:`PKCSession.from_windows_cert_store`."""
        from ._winstore import load_windows_pkcs12

        pfx, password = load_windows_pkcs12(
            name=name,
            thumbprint=thumbprint,
            predicate=predicate,
            store=store,
            location=location,
        )
        return cls._from_material(parse_pkcs12(pfx, password), verify=verify, **kwargs)
