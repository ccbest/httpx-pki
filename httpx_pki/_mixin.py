"""Shared construction, certificate, pickle, and repr behavior for the sessions.

The mixin owns the canonical :class:`~httpx_pki._material.Material`, the
``verify`` policy, and every constructor -- ``__init__`` and the ``from_*``
alternates, which are identical for the sync and async clients. It never calls
``super().__init__`` directly; instead each concrete client implements
:meth:`_httpx_init` to forward to the right httpx base class. This keeps the
sync and async clients in lockstep and lets :meth:`__setstate__` rebuild a
client without re-running ``__init__``.
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

from ._env import resolve_env_material
from ._exceptions import (
    CertificateExpiredError,
    CertificateNotYetValidError,
    CertificateValidityWarning,
    PicklingWarning,
    TLSConfigWarning,
)
from ._keychain import MacPredicate
from ._material import (
    CertInfo,
    CertSource,
    Material,
    Password,
    _load_certificate,
    cert_info,
    encode_password,
    load_material,
    normalize_pem,
    parse_pem_bundle,
    parse_pkcs12,
    read_source,
    with_extra_chain,
)
from ._pkcs12 import IdentitySelector, material_from_store_export
from ._select import UsageSelector
from ._source import (
    SourceRef,
    WatchSignature,
    is_reloadable,
    resolve_source,
    stat_signature,
    watch_paths,
)
from ._ssl import VerifyTypes, _context_from_material, _load_client_cert
from ._winstore import Predicate

# Bound TypeVar keeps the alternate constructors subclass-aware: calling
# MySession.from_pkcs12(...) types as MySession, not the base class. (This
# becomes typing.Self once 3.10 support is dropped.)
_S = TypeVar("_S", bound="_PKIMixin")

# Throttle for auto_reload=True: how often (at most) the source files are
# stat'ed before a request.
_DEFAULT_RELOAD_INTERVAL = datetime.timedelta(seconds=1)


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# Source kinds whose material is not decrypted with a caller-supplied
# password: ``env`` reads its own password variable along with the rest of the
# configuration, and the platform stores export under an internally generated
# single-use password. Passing one to reload() for these is always a mistake,
# so it is refused rather than silently discarded.
_PASSWORDLESS_SOURCES = ("env", "winstore", "macos_keychain")


def _no_password_message(source: SourceRef) -> str:
    """Why ``reload(password=...)`` cannot apply to *source*.

    The two cases fail for different reasons and have different fixes, so the
    message says which one the caller is in rather than only that the password
    was not used.
    """
    if source.kind == "env":
        prefix = source.args.get("prefix", "HTTPX_PKI_")
        return (
            "reload(password=...) does not apply to a from_env() client: the "
            f"password is read from {prefix}PASSWORD along with the rest of "
            "the configuration. Set that variable instead of passing one here."
        )
    store = (
        "the Windows certificate store"
        if source.kind == "winstore"
        else "the macOS keychain"
    )
    return (
        f"reload(password=...) does not apply to a client built from {store}: "
        "the certificate is exported under an internally generated single-use "
        "password, so there is none to supply. Drop the argument."
    )


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
    # Snapshot of the constructor's extra keywords taken BEFORE _init_state
    # pops subclass extras -- so it may hold more than httpx keywords. It is
    # serialized as-is by __getstate__, and __setstate__ replays it through
    # _apply_material (re-running the hook); snapshotting post-pop would
    # silently break subclass pickling.
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
    # The warn_if_expires_within window, retained so a rotated certificate is
    # judged against the same threshold the client was built with -- reload()
    # re-evaluates it, and it is carried across pickling. None disables it.
    _warn_within: datetime.timedelta | None
    _reload_lock: threading.Lock
    _watch_paths: list[Path]
    _watch_sig: WatchSignature
    _next_check: float

    def _httpx_init(self, *, verify: ssl.SSLContext, **kwargs: Any) -> None:
        """Forward to the concrete httpx base class. Overridden per client."""
        raise NotImplementedError

    def __init__(  # pylint: disable=too-many-arguments
        self,
        source: CertSource,
        password: Password = None,
        *,
        verify: VerifyTypes = True,
        identity: IdentitySelector | None = None,
        key_usage: UsageSelector | None = None,
        extended_key_usage: UsageSelector | None = None,
        chain: CertSource | list[CertSource] | None = None,
        warn_if_expires_within: datetime.timedelta | None = None,
        auto_reload: bool | datetime.timedelta = False,
        strict_validity: bool = False,
        **kwargs: Any,
    ) -> None:
        encoded = encode_password(password)
        selectors: dict[str, Any] = {
            "identity": identity,
            "key_usage": key_usage,
            "extended_key_usage": extended_key_usage,
        }
        material = with_extra_chain(
            load_material(read_source(source), encoded, **selectors), chain
        )
        self._apply_material(
            material,
            verify=verify,
            warn_if_expires_within=warn_if_expires_within,
            source=SourceRef(
                "auto", {"source": source, **selectors, "chain": chain}, encoded
            ),
            auto_reload=auto_reload,
            strict_validity=strict_validity,
            **kwargs,
        )

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
        """The shared in-place constructor body.

        Runs exactly once for every path that builds a client -- ``__init__``,
        ``_from_material`` (behind every ``from_*`` alternate constructor),
        and ``__setstate__`` -- validating the config, initializing all mixin
        state (including the :meth:`_init_state` subclass hook), and forwarding
        the leftover *kwargs* to the httpx base class via ``_httpx_init``.
        :meth:`reload` never calls this; it swaps certificate material into
        the mounted SSL context in place.
        """
        if "cert" in kwargs:
            raise TypeError(
                "pass the client certificate as the constructor's source= "
                "argument, not via httpx's cert= keyword: httpx deprecated "
                "cert= in 0.28, and it would collide with the SSL context "
                "httpx-pki mounts on verify=."
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
        # Snapshot BEFORE _init_state pops its extras -- see the _httpx_kwargs
        # annotation for why the pre-pop set is the one pickled.
        self._httpx_kwargs = dict(kwargs)
        self._init_state(kwargs)
        self._certinfo = cert_info(material.cert_pem)
        self._source = source
        self._auto_reload = interval
        self._strict_validity = strict_validity
        self._warn_within = warn_if_expires_within
        self._reload_lock = threading.Lock()
        self._watch_paths = watch_paths(source) if source is not None else []
        self._watch_sig = stat_signature(self._watch_paths)
        self._next_check = (
            time.monotonic() + interval.total_seconds()
            if interval is not None
            else 0.0
        )
        self._warn_on_ignored_tls(kwargs)
        self._warn_on_validity(self._warn_within)
        self._ssl_context = _context_from_material(material, verify)
        self._httpx_init(verify=self._ssl_context, **kwargs)

    def _init_state(self, kwargs: dict[str, Any]) -> None:
        """Subclass hook: claim constructor keywords and set up extra state.

        Runs exactly once on every path that builds a session -- ``__init__``,
        every ``from_*`` alternate constructor, and unpickling -- before the
        remaining *kwargs* are forwarded to the httpx base class. ``pop()``
        your subclass's keywords out of *kwargs* (it is mutated in place) and
        assign your attributes; anything left over must be a keyword httpx
        accepts. Popping with a default keeps the attributes present on every
        path, including the constructors a caller passes no extras to::

            class TracedClient(PKIClient):
                def _init_state(self, kwargs):
                    self.trace_header = kwargs.pop("trace_header", "X-Trace-Id")

            TracedClient("client.p12", trace_header="X-Request-Id")
            TracedClient.from_env()   # trace_header defaults to "X-Trace-Id"

        The full keyword set is snapshotted for pickling before this hook
        runs, and an unpickled client re-runs the hook with the original
        keywords -- state set here survives a pickle round trip with no extra
        code, as long as the values are themselves picklable.
        :meth:`reload` and ``auto_reload`` swap certificate material in place
        and do **not** re-run this hook.

        Do not rely on other session state here: the hook runs mid-
        construction, before the httpx base class is initialized. When
        subclassing a subclass, chain with ``super()._init_state(kwargs)``.
        The base implementation does nothing.
        """

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

    # -- alternate constructors (shared verbatim by the sync and async
    # clients; each returns the class it was called on) ----------------------

    @classmethod
    def from_env(  # pylint: disable=too-many-arguments
        cls: type[_S],
        prefix: str = "HTTPX_PKI_",
        *,
        verify: VerifyTypes | None = None,
        warn_if_expires_within: datetime.timedelta | None = None,
        auto_reload: bool | datetime.timedelta = False,
        strict_validity: bool = False,
        **kwargs: Any,
    ) -> _S:
        """Build a session from ``{prefix}*`` environment variables.

        Reads ``{prefix}CERT`` (required), ``{prefix}PASSWORD``, ``{prefix}KEY``
        (switches to a separate cert+key), ``{prefix}CHAIN`` (extra
        intermediates to present), and ``{prefix}CA`` (server-trust bundle
        path, or the literal ``system`` for the OS trust store).
        An explicit *verify* overrides ``{prefix}CA``. Reloading re-reads the
        environment; ``auto_reload`` watches the files the variables pointed
        at when the session was built. *warn_if_expires_within* warns about a
        certificate that expires inside that window (see :meth:`check_validity`).
        """
        material, env_verify = resolve_env_material(prefix)
        return cls._from_material(
            material,
            verify=env_verify if verify is None else verify,
            warn_if_expires_within=warn_if_expires_within,
            source=SourceRef("env", {"prefix": prefix}),
            auto_reload=auto_reload,
            strict_validity=strict_validity,
            **kwargs,
        )

    @classmethod
    def from_pkcs12(  # pylint: disable=too-many-arguments
        cls: type[_S],
        source: CertSource,
        password: Password = None,
        *,
        verify: VerifyTypes = True,
        identity: IdentitySelector | None = None,
        key_usage: UsageSelector | None = None,
        extended_key_usage: UsageSelector | None = None,
        chain: CertSource | list[CertSource] | None = None,
        warn_if_expires_within: datetime.timedelta | None = None,
        auto_reload: bool | datetime.timedelta = False,
        strict_validity: bool = False,
        **kwargs: Any,
    ) -> _S:
        """Build a session from a PKCS#12 bundle (path or bytes).

        A bundle holding more than one identity -- a dual key pair, where the
        CA issued separate signing and encryption certificates -- requires a
        selector saying which to present, or
        :class:`~httpx_pki.AmbiguousCertificateError` is raised rather than an
        arbitrary one being picked. ``identity`` takes the file position, a
        case-insensitive substring of the friendly name / common name / subject,
        an exact SHA-1 or SHA-256 fingerprint, or a predicate over
        :class:`~httpx_pki.P12Identity`; ``key_usage`` and
        ``extended_key_usage`` require the named usages, which is usually what
        separates the two::

            PKIClient.from_pkcs12(
                "corp.p12", password=pw, key_usage="digital_signature"
            )

        For a bundle holding a renewed certificate alongside the one it
        replaces, ``identity=httpx_pki.currently_valid`` presents whichever is
        valid right now (preferring the renewed one while both are).
        See :func:`~httpx_pki.list_pkcs12_identities` for what a file holds.
        *warn_if_expires_within* warns about a certificate that expires inside
        that window (see :meth:`check_validity`).
        """
        encoded = encode_password(password)
        selectors: dict[str, Any] = {
            "identity": identity,
            "key_usage": key_usage,
            "extended_key_usage": extended_key_usage,
        }
        material = with_extra_chain(
            parse_pkcs12(read_source(source), encoded, **selectors), chain
        )
        return cls._from_material(
            material,
            verify=verify,
            warn_if_expires_within=warn_if_expires_within,
            source=SourceRef(
                "pkcs12", {"source": source, **selectors, "chain": chain}, encoded
            ),
            auto_reload=auto_reload,
            strict_validity=strict_validity,
            **kwargs,
        )

    @classmethod
    def from_pem(  # pylint: disable=too-many-arguments
        cls: type[_S],
        source: CertSource,
        password: Password = None,
        *,
        verify: VerifyTypes = True,
        identity: IdentitySelector | None = None,
        key_usage: UsageSelector | None = None,
        extended_key_usage: UsageSelector | None = None,
        chain: CertSource | list[CertSource] | None = None,
        warn_if_expires_within: datetime.timedelta | None = None,
        auto_reload: bool | datetime.timedelta = False,
        strict_validity: bool = False,
        **kwargs: Any,
    ) -> _S:
        """Build a session from a single PEM blob holding the key(s) and cert(s).

        A blob usually holds one key+certificate identity plus chain certs. It
        may hold several -- two key+cert pairs concatenated, or a renewed
        certificate alongside the one it replaces over a single key -- and then
        ``identity`` / ``key_usage`` / ``extended_key_usage`` choose which to
        present, exactly as on :meth:`from_pkcs12` (without a selector,
        :class:`~httpx_pki.AmbiguousCertificateError` is raised). See
        :func:`~httpx_pki.list_identities` for what a blob holds.
        *warn_if_expires_within* warns about a certificate that expires inside
        that window (see :meth:`check_validity`).
        """
        encoded = encode_password(password)
        selectors: dict[str, Any] = {
            "identity": identity,
            "key_usage": key_usage,
            "extended_key_usage": extended_key_usage,
        }
        material = with_extra_chain(
            parse_pem_bundle(read_source(source), encoded, **selectors), chain
        )
        return cls._from_material(
            material,
            verify=verify,
            warn_if_expires_within=warn_if_expires_within,
            source=SourceRef(
                "pem", {"source": source, **selectors, "chain": chain}, encoded
            ),
            auto_reload=auto_reload,
            strict_validity=strict_validity,
            **kwargs,
        )

    @classmethod
    def from_key_pair(  # pylint: disable=too-many-arguments
        cls: type[_S],
        certificate: CertSource,
        private_key: CertSource,
        *,
        password: Password = None,
        chain: CertSource | list[CertSource] | None = None,
        verify: VerifyTypes = True,
        warn_if_expires_within: datetime.timedelta | None = None,
        auto_reload: bool | datetime.timedelta = False,
        strict_validity: bool = False,
        **kwargs: Any,
    ) -> _S:
        """Build a session from a separate certificate and private key.

        *certificate* is the client (leaf) certificate. Pass *chain* to present
        intermediate certificates to the server: a single source (which may
        concatenate several PEM certs) or a list of sources.
        *password* decrypts *private_key* if it is encrypted; certificates are
        never encrypted, so it is the same *password* every other constructor
        takes.
        *warn_if_expires_within* warns about a certificate that expires inside
        that window (see :meth:`check_validity`).
        """
        encoded = encode_password(password)
        material = normalize_pem(certificate, private_key, password, chain)
        return cls._from_material(
            material,
            verify=verify,
            warn_if_expires_within=warn_if_expires_within,
            source=SourceRef(
                "key_pair",
                {
                    "certificate": certificate,
                    "private_key": private_key,
                    "chain": chain,
                },
                encoded,
            ),
            auto_reload=auto_reload,
            strict_validity=strict_validity,
            **kwargs,
        )

    @classmethod
    def from_macos_keychain(  # pylint: disable=too-many-arguments
        cls: type[_S],
        name: str | None = None,
        *,
        thumbprint: str | None = None,
        identity: str | MacPredicate | None = None,
        key_usage: UsageSelector | None = None,
        extended_key_usage: UsageSelector | None = None,
        verify: VerifyTypes = True,
        warn_if_expires_within: datetime.timedelta | None = None,
        strict_validity: bool = False,
        **kwargs: Any,
    ) -> _S:
        """Build a session from an exportable identity in the macOS keychain.

        macOS only. Selects the identity from the default keychain search list
        by ``name`` (case-insensitive substring of the subject common name or
        keychain label), ``thumbprint``, ``identity`` (a name substring, an
        exact fingerprint, or a predicate callable), or the
        ``key_usage`` / ``extended_key_usage`` the certificate must assert;
        every selector given must match. A keychain holding both halves of a
        dual key pair needs the usage to choose between them, and one holding a
        renewed certificate alongside the one it replaces can take
        ``identity=httpx_pki.currently_valid``::

            AsyncPKIClient.from_macos_keychain(
                "corp-user", key_usage="digital_signature"
            )

        The private key must be exportable, and the keychain must not require
        an interactive consent prompt (provision with ``security import ... -A``
        or "Always Allow" for unattended use). :meth:`reload` re-exports from
        the keychain with the same selector (there is no file to watch, so
        ``auto_reload`` is not available). *warn_if_expires_within* warns about
        a certificate that expires inside that window (see
        :meth:`check_validity`).

        Raises :class:`~httpx_pki.UnsupportedPlatformError` off macOS,
        :class:`~httpx_pki.CertificateNotFoundError` if nothing matches, and
        :class:`~httpx_pki.AmbiguousCertificateError` if several do.
        """
        from ._keychain import load_macos_pkcs12

        selector: dict[str, Any] = {
            "name": name,
            "thumbprint": thumbprint,
            "identity": identity,
            "key_usage": key_usage,
            "extended_key_usage": extended_key_usage,
        }
        pfx, password, chosen = load_macos_pkcs12(**selector)
        return cls._from_material(
            material_from_store_export(pfx, password, chosen),
            verify=verify,
            warn_if_expires_within=warn_if_expires_within,
            source=SourceRef("macos_keychain", selector),
            strict_validity=strict_validity,
            **kwargs,
        )

    @classmethod
    def from_windows_cert_store(  # pylint: disable=too-many-arguments,too-many-locals
        cls: type[_S],
        name: str | None = None,
        *,
        thumbprint: str | None = None,
        identity: str | Predicate | None = None,
        key_usage: UsageSelector | None = None,
        extended_key_usage: UsageSelector | None = None,
        store: str = "MY",
        location: str = "CurrentUser",
        verify: VerifyTypes = True,
        warn_if_expires_within: datetime.timedelta | None = None,
        strict_validity: bool = False,
        **kwargs: Any,
    ) -> _S:
        """Build a session from an exportable certificate in the Windows store.

        Windows only. Selects the certificate by ``name`` (case-insensitive
        substring of the subject common name or friendly name), ``thumbprint``,
        ``identity`` (a name substring, an exact fingerprint, or a predicate
        callable), or the ``key_usage`` / ``extended_key_usage``
        the certificate must assert; every selector given must match. A store
        holding both halves of a dual key pair -- what Active Directory key
        archival provisions -- needs the usage to choose between them, and one
        holding a renewed certificate alongside the one it replaces can take
        ``identity=httpx_pki.currently_valid``::

            PKIClient.from_windows_cert_store(
                "corp-user", key_usage="digital_signature"
            )

        The matching certificate's private key must be marked exportable.
        :meth:`reload` re-exports from the store with the same selector (there
        is no file to watch, so ``auto_reload`` is not available).
        *warn_if_expires_within* warns about a certificate that expires inside
        that window (see :meth:`check_validity`).

        Raises :class:`~httpx_pki.UnsupportedPlatformError` off Windows,
        :class:`~httpx_pki.CertificateNotFoundError` if nothing matches, and
        :class:`~httpx_pki.AmbiguousCertificateError` if several do.
        """
        from ._winstore import load_windows_pkcs12

        selector: dict[str, Any] = {
            "name": name,
            "thumbprint": thumbprint,
            "identity": identity,
            "key_usage": key_usage,
            "extended_key_usage": extended_key_usage,
            "store": store,
            "location": location,
        }
        pfx, password, chosen = load_windows_pkcs12(**selector)
        return cls._from_material(
            material_from_store_export(pfx, password, chosen),
            verify=verify,
            warn_if_expires_within=warn_if_expires_within,
            source=SourceRef("winstore", selector),
            strict_validity=strict_validity,
            **kwargs,
        )

    # -- validity -----------------------------------------------------------

    @property
    def not_valid_before(self) -> datetime.datetime:
        """Start of the client certificate's validity window (UTC)."""
        return self._certinfo.not_valid_before

    @property
    def not_valid_after(self) -> datetime.datetime:
        """End of the client certificate's validity window (UTC)."""
        return self._certinfo.not_valid_after

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
        not_before = f"{info.not_valid_before:%Y-%m-%d %H:%M UTC}"
        not_after = f"{info.not_valid_after:%Y-%m-%d %H:%M UTC}"
        if now < info.not_valid_before:
            raise CertificateNotYetValidError(
                f"client certificate is not valid until {not_before}"
            )
        if now > info.not_valid_after:
            raise CertificateExpiredError(
                f"client certificate expired on {not_after}"
            )
        if within is not None and info.not_valid_after - now <= within:
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
        the previous certificate. Pass *password* if the source is a file or
        bundle that is encrypted and the client was not built with
        ``auto_reload`` (which is the only mode that retains the password).

        The freshly loaded certificate is put through the same validity checks
        the constructor ran, against the ``warn_if_expires_within`` window the
        client was built with -- so a rotation that lands another short-lived
        certificate warns again, and one that lands a healthy certificate goes
        quiet.

        Raises :class:`TypeError` for a client built from in-memory bytes
        (there is no source to re-read), and for a *password* passed to a
        source that has none to use: ``from_env`` reads ``{prefix}PASSWORD``
        itself, and the Windows store and macOS keychain export under an
        internal single-use password.
        """
        if self._source is None or not is_reloadable(self._source):
            raise TypeError(
                "this client was built from in-memory bytes; there is no "
                "certificate source to reload from"
            )
        if password is not None and self._source.kind in _PASSWORDLESS_SOURCES:
            raise TypeError(_no_password_message(self._source))
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
            self._warn_on_validity(self._warn_within)

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
                TLSConfigWarning,
                stacklevel=3,
            )

    def _warn_on_validity(
        self, warn_if_expires_within: datetime.timedelta | None
    ) -> None:
        info = self._certinfo
        now = _utcnow()
        if now > info.not_valid_after:
            warnings.warn(
                f"client certificate expired on {info.not_valid_after:%Y-%m-%d}; "
                "mTLS handshakes will fail.",
                CertificateValidityWarning,
                stacklevel=3,
            )
        elif now < info.not_valid_before:
            starts = f"{info.not_valid_before:%Y-%m-%d}"
            warnings.warn(
                f"client certificate is not valid until {starts}; "
                "mTLS handshakes will fail until then.",
                CertificateValidityWarning,
                stacklevel=3,
            )
        elif (
            warn_if_expires_within is not None
            and info.not_valid_after - now <= warn_if_expires_within
        ):
            days = (info.not_valid_after - now).days
            warnings.warn(
                f"client certificate expires on {info.not_valid_after:%Y-%m-%d} "
                f"(in {days} day(s)).",
                CertificateValidityWarning,
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
                PicklingWarning,
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
                    PicklingWarning,
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
            "warn_if_expires_within": self._warn_within,
        }

    def __setstate__(self, state: dict[str, Any]) -> None:
        # .get() defaults keep pickles from before the rotation feature loading.
        self._apply_material(
            state["material"],
            verify=state["verify"],
            source=state.get("source"),
            auto_reload=state.get("auto_reload", False),
            strict_validity=state.get("strict_validity", False),
            warn_if_expires_within=state.get("warn_if_expires_within"),
            **state["httpx_kwargs"],
        )

    def __repr__(self) -> str:
        info = self._certinfo
        return (
            f"<{type(self).__name__} "
            f"cn={info.common_name!r} "
            f"expires={info.not_valid_after:%Y-%m-%d}>"
        )
