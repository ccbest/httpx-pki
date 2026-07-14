"""Shared certificate, pickle, and repr behavior for the session classes.

The mixin owns the canonical :class:`~httpx_pki._material.Material` and the
``verify`` policy. It never calls ``super().__init__`` directly; instead each
concrete client implements :meth:`_httpx_init` to forward to the right httpx
base class. This keeps the sync and async clients in lockstep and lets
:meth:`__setstate__` rebuild a client without re-running ``__init__``.
"""

from __future__ import annotations

import datetime
import pickle
import ssl
import threading
import time
import warnings
from pathlib import Path
from typing import Any, TypeVar

from cryptography import x509

from ._exceptions import CertificateExpiredError, CertificateNotYetValidError
from ._material import (
    CertInfo,
    Material,
    Password,
    _load_certificate,
    cert_info,
    encode_password,
)
from ._source import (
    SourceRef,
    WatchSignature,
    is_reloadable,
    resolve_source,
    stat_signature,
    watch_paths,
)
from ._ssl import VerifyTypes, _context_from_material, _load_client_cert

_S = TypeVar("_S", bound="_PKIMixin")

# Throttle for auto_reload=True: how often (at most) the source files are
# stat'ed before a request.
_DEFAULT_RELOAD_INTERVAL = datetime.timedelta(seconds=1)


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _mount_shadows_tls(pattern: object) -> bool:
    """Whether an httpx mount pattern would handle https traffic.

    httpx mount keys look like ``"all://"``, ``"https://"``, or
    ``"https://example.com"``. A mount shadows the client certificate only if it
    intercepts https -- i.e. its scheme is ``https`` or the ``all`` wildcard.
    """
    scheme = str(pattern).split("://", 1)[0].lower()
    return scheme in ("", "all", "https")


class _PKIMixin:  # pylint: disable=too-many-instance-attributes
    _material: Material
    _verify_policy: VerifyTypes
    _httpx_kwargs: dict[str, Any]
    # Parsed once from _material.cert_pem in _apply_material. Parsing is pure, so
    # caching it is invisible (the time-dependent checks recompute "now"
    # separately) and spares every cn/dn/validity access a fresh PEM parse.
    _certinfo: CertInfo
    # The client-certificate SSL context mounted on the default transport, kept
    # so ssl_context hands back the very object in use rather than a rebuild.
    # reload() mutates this object in place (load_cert_chain replaces the cert
    # for future handshakes), which is what propagates a rotated certificate to
    # every transport holding the context.
    _ssl_context: ssl.SSLContext
    # Rotation state: where the material came from (None only for pre-0.4
    # pickles), the auto-reload throttle (None = disabled), and the stat
    # fingerprint of the watched source files.
    _source: SourceRef | None
    _auto_reload: datetime.timedelta | None
    _strict_validity: bool
    _reload_lock: threading.Lock
    _watch_paths: list[Path]
    _watch_sig: WatchSignature
    _next_check: float

    def _httpx_init(self, *, verify: ssl.SSLContext, **kwargs: Any) -> None:
        """Forward to the concrete httpx base class. Overridden per client."""
        raise NotImplementedError

    def _apply_material(  # pylint: disable=too-many-arguments
        self,
        material: Material,
        *,
        verify: VerifyTypes = True,
        warn_if_expires_within: datetime.timedelta | None = None,
        source: SourceRef | None = None,
        auto_reload: bool | datetime.timedelta = False,
        strict_validity: bool = False,
        **kwargs: Any,
    ) -> None:
        if "cert" in kwargs:
            raise TypeError(
                "pass the client certificate to the constructor's cert source, "
                "not via httpx's cert= keyword: httpx deprecated cert= in 0.28, "
                "and it would collide with the SSL context httpx-pki mounts on "
                "verify=."
            )
        # timedelta(0) means "check on every request", so test identity/type,
        # not truthiness (bool(timedelta(0)) is False).
        if isinstance(auto_reload, datetime.timedelta):
            interval: datetime.timedelta | None = auto_reload
        elif auto_reload is True:
            interval = _DEFAULT_RELOAD_INTERVAL
        elif auto_reload is False:
            interval = None
        else:
            raise TypeError(
                "auto_reload must be a bool or datetime.timedelta, "
                f"got {type(auto_reload).__name__}"
            )
        if interval is not None:
            if source is None or not watch_paths(source):
                raise TypeError(
                    "auto_reload requires a filesystem-path certificate source "
                    "to watch; this client was built from in-memory bytes or "
                    "a platform certificate store (Windows / macOS keychain)"
                )
        elif source is not None and source.password is not None:
            # Only an unattended auto-reload justifies retaining the password;
            # a manual reload() can be handed one explicitly.
            source = SourceRef(kind=source.kind, args=source.args, password=None)

        self._material = material
        self._verify_policy = verify
        self._httpx_kwargs = kwargs
        self._certinfo = cert_info(material.cert_pem)
        self._source = source
        self._auto_reload = interval
        self._strict_validity = strict_validity
        self._reload_lock = threading.Lock()
        self._watch_paths = watch_paths(source) if source is not None else []
        self._watch_sig = stat_signature(self._watch_paths)
        self._next_check = (
            time.monotonic() + interval.total_seconds()
            if interval is not None
            else 0.0
        )
        self._warn_on_ignored_tls(kwargs)
        self._warn_on_validity(warn_if_expires_within)
        self._ssl_context = _context_from_material(material, verify)
        self._httpx_init(verify=self._ssl_context, **kwargs)

    @classmethod
    def _from_material(  # pylint: disable=too-many-arguments
        cls: type[_S],
        material: Material,
        *,
        verify: VerifyTypes = True,
        warn_if_expires_within: datetime.timedelta | None = None,
        source: SourceRef | None = None,
        auto_reload: bool | datetime.timedelta = False,
        strict_validity: bool = False,
        **kwargs: Any,
    ) -> _S:
        """Build an instance from ready material, bypassing ``__init__``.

        Shared by every alternate constructor (:meth:`from_key_pair`,
        :meth:`from_windows_cert_store`, ...).
        """
        self = cls.__new__(cls)
        self._apply_material(
            material,
            verify=verify,
            warn_if_expires_within=warn_if_expires_within,
            source=source,
            auto_reload=auto_reload,
            strict_validity=strict_validity,
            **kwargs,
        )
        return self

    # -- validity -----------------------------------------------------------

    @property
    def not_valid_before(self) -> datetime.datetime:
        """Start of the client certificate's validity window (UTC)."""
        return self._certinfo.not_before

    @property
    def not_valid_after(self) -> datetime.datetime:
        """End of the client certificate's validity window (UTC)."""
        return self._certinfo.not_after

    @property
    def is_expired(self) -> bool:
        """``True`` if the client certificate's validity window has ended."""
        return _utcnow() > self.not_valid_after

    @property
    def is_not_yet_valid(self) -> bool:
        """``True`` if the client certificate's validity window has not begun."""
        return _utcnow() < self.not_valid_before

    @property
    def expires_in(self) -> datetime.timedelta:
        """Time until the client certificate expires (negative if expired)."""
        return self.not_valid_after - _utcnow()

    def check_validity(
        self, *, within: datetime.timedelta | None = None
    ) -> None:
        """Raise if the client certificate is not currently usable.

        Raises :class:`~httpx_pki.CertificateNotYetValidError` before the
        validity window opens and :class:`~httpx_pki.CertificateExpiredError`
        once it has closed. If *within* is given, also raise
        ``CertificateExpiredError`` when the certificate will expire inside that
        window -- a one-call preflight for "is this good for the next N days?".
        """
        info = self._certinfo
        now = _utcnow()
        not_before = f"{info.not_before:%Y-%m-%d %H:%M UTC}"
        not_after = f"{info.not_after:%Y-%m-%d %H:%M UTC}"
        if now < info.not_before:
            raise CertificateNotYetValidError(
                f"client certificate is not valid until {not_before}"
            )
        if now > info.not_after:
            raise CertificateExpiredError(
                f"client certificate expired on {not_after}"
            )
        if within is not None and info.not_after - now <= within:
            raise CertificateExpiredError(
                f"client certificate expires on {not_after}, within {within}"
            )

    # -- rotation -------------------------------------------------------------

    def reload(self, *, password: Password = None) -> None:
        """Re-read the certificate source and present the current certificate.

        Re-runs the loading path the constructor used (re-reading files,
        re-resolving ``from_env`` variables, or re-exporting from the Windows
        store) and loads the fresh certificate into the mounted SSL context
        **in place** -- new handshakes present it immediately, on every
        transport sharing the context. Connections already established keep
        their old certificate until they close.

        The swap is atomic: if the new material cannot be loaded
        (:class:`~httpx_pki.CertificateLoadError`), the client keeps serving
        the previous certificate. Pass *password* if the source is encrypted
        and the client was not built with ``auto_reload`` (which is the only
        mode that retains the password). Raises :class:`TypeError` for a
        client built from in-memory bytes -- there is no source to re-read.
        """
        if self._source is None or not is_reloadable(self._source):
            raise TypeError(
                "this client was built from in-memory bytes; there is no "
                "certificate source to reload from"
            )
        with self._reload_lock:
            # Fingerprint the watched files BEFORE reading them: if another
            # rotation lands between the read and the fingerprint, recording
            # the pre-read signature makes the next preflight see a mismatch
            # and reload again, instead of silently absorbing that rotation.
            sig_before = stat_signature(self._watch_paths)
            material = resolve_source(self._source, encode_password(password))
            _load_client_cert(self._ssl_context, material)
            self._material = material
            self._certinfo = cert_info(material.cert_pem)
            self._watch_sig = sig_before
            self._warn_on_validity(None)

    def _preflight(self) -> None:
        """Per-request hook run by ``send()``: auto-reload, then validity.

        The auto-reload check is throttled (at most one ``stat()`` sweep per
        interval) and only triggers a reload when the watched files' stat
        fingerprint changed. Concurrent senders that both observe a change
        serialize on the reload lock; the loser re-reads the same fresh file,
        which is wasteful but harmless. A reload failure raises on the
        triggering request and leaves the old fingerprint in place, so the
        next request retries.
        """
        interval = self._auto_reload
        if interval is not None:
            now = time.monotonic()
            if now >= self._next_check:
                self._next_check = now + interval.total_seconds()
                if stat_signature(self._watch_paths) != self._watch_sig:
                    self.reload()
        if self._strict_validity:
            self.check_validity()

    def _warn_on_ignored_tls(self, kwargs: dict[str, Any]) -> None:
        """Warn that a custom transport makes httpx ignore the client cert.

        When ``transport=`` is supplied, httpx uses that transport as-is and
        never consults the client-level ``verify=`` we mount the certificate on
        -- so the cert is silently dropped and the mTLS handshake fails far from
        here. ``mounts=`` does the same, but only for the patterns it actually
        handles: an ``http://``-only mount leaves the default https transport
        (which *does* honor ``verify=``) in place, so we warn for a mount only
        when it would shadow https traffic. The fix is to put the SSL context on
        the inner transport (see :func:`~httpx_pki.build_ssl_context`).
        """
        mounts = kwargs.get("mounts") or {}
        shadows_tls = any(_mount_shadows_tls(pattern) for pattern in mounts)
        if kwargs.get("transport") is not None or shadows_tls:
            warnings.warn(
                "a custom transport=/mounts= makes httpx ignore verify=, so the "
                "client certificate is NOT mounted on this session. Build the "
                "context with build_ssl_context() and put it on the inner "
                "transport instead, e.g. httpx.HTTPTransport(verify=ctx).",
                stacklevel=3,
            )

    def _warn_on_validity(
        self, warn_if_expires_within: datetime.timedelta | None
    ) -> None:
        info = self._certinfo
        now = _utcnow()
        if now > info.not_after:
            warnings.warn(
                f"client certificate expired on {info.not_after:%Y-%m-%d}; "
                "mTLS handshakes will fail.",
                stacklevel=3,
            )
        elif now < info.not_before:
            warnings.warn(
                f"client certificate is not valid until {info.not_before:%Y-%m-%d}; "
                "mTLS handshakes will fail until then.",
                stacklevel=3,
            )
        elif (
            warn_if_expires_within is not None
            and info.not_after - now <= warn_if_expires_within
        ):
            days = (info.not_after - now).days
            warnings.warn(
                f"client certificate expires on {info.not_after:%Y-%m-%d} "
                f"(in {days} day(s)).",
                stacklevel=3,
            )

    def cert_info(self) -> CertInfo:
        """Return subject, validity window, and SANs of the client certificate."""
        return self._certinfo

    @property
    def certificate(self) -> x509.Certificate:
        """The client (leaf) certificate as a :class:`cryptography.x509.Certificate`.

        Use this for anything :meth:`cert_info` doesn't summarize -- most often
        reading extensions, e.g.::

            ku = client.certificate.extensions.get_extension_for_class(
                x509.KeyUsage
            ).value
            if ku.digital_signature or ku.key_encipherment:
                ...

        A fresh object is parsed from the stored PEM on each access.
        """
        return _load_certificate(self._material.cert_pem)

    @property
    def ssl_context(self) -> ssl.SSLContext:
        """The client-certificate :class:`ssl.SSLContext` mounted on this session.

        This is the exact context httpx-pki built from the certificate material
        and the ``verify`` policy, and mounted on the default transport -- not a
        copy. Reuse it when building your own httpx transports so they present
        the same client certificate, e.g. a per-proxy transport::

            transport = httpx.HTTPTransport(verify=client.ssl_context, proxy=url)

        A transport built without it silently drops the client cert and the mTLS
        handshake fails.
        """
        return self._ssl_context

    @property
    def cn(self) -> str | None:
        """The client certificate's subject Common Name (``None`` if absent)."""
        return self._certinfo.common_name

    @property
    def dn(self) -> str:
        """The client certificate's full subject Distinguished Name (RFC 4514)."""
        return self._certinfo.distinguished_name

    # -- pickling -----------------------------------------------------------
    #
    # Neither ssl.SSLContext nor httpx's live connection pool can be pickled, so
    # we serialize only the canonical material plus the construction config and
    # rebuild a fresh client on load. The pickle therefore contains the
    # decrypted private key -- store and transmit it as the secret it is.

    def __getstate__(self) -> dict[str, Any]:
        verify = self._verify_policy
        if isinstance(verify, ssl.SSLContext):
            warnings.warn(
                "a custom ssl.SSLContext passed as verify= cannot be pickled; "
                "the unpickled client falls back to default server verification.",
                stacklevel=2,
            )
            verify = True
        source = self._source
        auto_reload: bool | datetime.timedelta = (
            self._auto_reload if self._auto_reload is not None else False
        )
        if source is not None:
            try:
                pickle.dumps(source)
            except (pickle.PicklingError, TypeError, AttributeError):
                # e.g. a Windows-store lambda predicate. Drop the source (and
                # the auto-reload that depends on it) rather than failing the
                # whole pickle; mirrors the SSLContext-verify fallback above.
                warnings.warn(
                    "the certificate source cannot be pickled; the unpickled "
                    "client will not be reloadable.",
                    stacklevel=2,
                )
                source = None
                auto_reload = False
        return {
            "material": self._material,
            "verify": verify,
            "httpx_kwargs": self._httpx_kwargs,
            "source": source,
            "auto_reload": auto_reload,
            "strict_validity": self._strict_validity,
        }

    def __setstate__(self, state: dict[str, Any]) -> None:
        # .get() defaults keep pickles from before the rotation feature loading.
        self._apply_material(
            state["material"],
            verify=state["verify"],
            source=state.get("source"),
            auto_reload=state.get("auto_reload", False),
            strict_validity=state.get("strict_validity", False),
            **state["httpx_kwargs"],
        )

    def __repr__(self) -> str:
        info = self._certinfo
        return (
            f"<{type(self).__name__} "
            f"cn={info.common_name!r} "
            f"expires={info.not_after:%Y-%m-%d}>"
        )
