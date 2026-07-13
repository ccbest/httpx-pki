# pylint: disable=invalid-name, too-many-locals
"""Retrieve an exportable client certificate from the Windows certificate store.

Everything Windows-specific (``ctypes`` against ``crypt32.dll``) lives inside
functions guarded by a ``sys.platform`` check, so importing this module is safe
on every platform and adds no dependency. The only platform-independent piece is
:func:`select_windows_certificate`, which is pure and unit-tested everywhere.

The flow is: enumerate the personal ("MY") store, pick the matching certificate,
and export it -- private key included -- to PKCS#12 bytes under a random,
single-use password. Those bytes feed the same
:func:`~httpx_pki._material.parse_pkcs12` pipeline used by every other
constructor, so the throwaway password never escapes this module.
"""

from __future__ import annotations

import secrets
import sys
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from ._exceptions import (
    AmbiguousCertificateError,
    CertificateLoadError,
    CertificateNotFoundError,
    UnsupportedPlatformError,
)

Predicate = Callable[["WinCert"], bool]


@dataclass(frozen=True)
class WinCert:
    """A certificate discovered in the Windows store.

    ``handle`` is the opaque ``PCCERT_CONTEXT`` used to export the key; it is
    ``None`` for the synthetic candidates used in tests.
    """

    subject_cn: str | None
    friendly_name: str | None
    thumbprint: str
    handle: Any = None


def _normalize_thumbprint(value: str) -> str:
    return value.replace(":", "").replace(" ", "").upper()


def select_windows_certificate(
    candidates: list[WinCert],
    *,
    name: str | None = None,
    thumbprint: str | None = None,
    predicate: Predicate | None = None,
) -> WinCert:
    """Choose a single certificate from *candidates*.

    Selectors are applied in order of specificity: an exact ``thumbprint``, then
    a ``predicate`` callable, then a case-insensitive ``name`` substring matched
    against the subject common name and the Windows friendly name. With no
    selector, all candidates qualify (handy when the store holds exactly one).

    Raises :class:`CertificateNotFoundError` if nothing matches and
    :class:`AmbiguousCertificateError` if more than one does.
    """
    if thumbprint is not None:
        target = _normalize_thumbprint(thumbprint)
        matches = [c for c in candidates if c.thumbprint == target]
    elif predicate is not None:
        matches = [c for c in candidates if predicate(c)]
    elif name is not None:
        needle = name.lower()
        matches = [
            c
            for c in candidates
            if (c.subject_cn is not None and needle in c.subject_cn.lower())
            or (c.friendly_name is not None and needle in c.friendly_name.lower())
        ]
    else:
        matches = list(candidates)

    if not matches:
        raise CertificateNotFoundError(
            _selector_repr(name, thumbprint, predicate)
            + " matched no certificate in the store"
        )
    if len(matches) > 1:
        listing = ", ".join(
            f"{c.subject_cn or '<no CN>'} ({c.thumbprint})" for c in matches
        )
        raise AmbiguousCertificateError(
            f"{_selector_repr(name, thumbprint, predicate)} matched "
            f"{len(matches)} certificates: {listing}. "
            "Narrow it with a more specific name or an exact thumbprint."
        )
    return matches[0]


def _selector_repr(
    name: str | None, thumbprint: str | None, predicate: Predicate | None
) -> str:
    if thumbprint is not None:
        return f"thumbprint={thumbprint!r}"
    if predicate is not None:
        return "predicate"
    if name is not None:
        return f"name={name!r}"
    return "no selector"


def list_windows_certificates(
    *, store: str = "MY", location: str = "CurrentUser"
) -> list[WinCert]:
    """List the certificates in a Windows certificate store.

    Returns a :class:`WinCert` for each certificate in *store* under *location*
    (``"CurrentUser"`` or ``"LocalMachine"``), carrying its subject common name,
    Windows friendly name, and SHA-1 thumbprint -- enough to pick the right one
    by whatever convention your organization follows, without exporting any
    private key. Feed the result to :func:`select_windows_certificate`, or filter it
    yourself and pass a ``thumbprint`` to a session constructor.

    The returned objects hold no live handle (every enumerated context is freed
    before returning), so there is nothing for the caller to release.

    Windows only; raises :class:`~httpx_pki.UnsupportedPlatformError` elsewhere.
    """
    candidates = _enumerate_store(store, location)
    try:
        return [replace(c, handle=None) for c in candidates]
    finally:
        _free_contexts(candidates)


def load_windows_pkcs12(
    *,
    name: str | None = None,
    thumbprint: str | None = None,
    predicate: Predicate | None = None,
    store: str = "MY",
    location: str = "CurrentUser",
) -> tuple[bytes, bytes]:
    """Export the matching store certificate to ``(pkcs12_bytes, password)``."""
    if sys.platform != "win32":
        raise UnsupportedPlatformError(
            "the Windows certificate store is only available on Windows"
        )
    candidates = _enumerate_store(store, location)
    keep: WinCert | None = None
    try:
        keep = select_windows_certificate(
            candidates, name=name, thumbprint=thumbprint, predicate=predicate
        )
        return _export_pfx(keep)
    finally:
        # _enumerate_store duplicates every context so the handles outlive the
        # enumeration cursor; free the ones we are not exporting (_export_pfx
        # frees the chosen one). On a selection error keep is None, so every
        # duplicated context is released here instead of leaking.
        _free_contexts([c for c in candidates if c is not keep])


def _free_contexts(certs: list[WinCert]) -> None:
    """Release duplicated certificate contexts.

    Handle-less candidates (the synthetic stand-ins used in tests) are skipped,
    and ``crypt32`` is only loaded when there is a real handle to free -- so this
    is a no-op, and safe, off Windows.
    """
    live = [c.handle for c in certs if c.handle is not None]
    if not live:
        return
    crypt32 = _load_crypt32()
    for handle in live:
        crypt32.CertFreeCertificateContext(handle)


# ---------------------------------------------------------------------------
# Windows-only ctypes plumbing. The bodies are unreachable (and unchecked by
# mypy) off Windows because the platform guard always raises there.
#
# Every crypt32 function below has its restype/argtypes declared. This is not
# optional on 64-bit Windows: without it ctypes assumes 32-bit ``int`` for
# returns and arguments and silently truncates HCERTSTORE/PCCERT_CONTEXT
# pointers, which corrupts the handles and faults (access violation).
# ---------------------------------------------------------------------------


def _load_crypt32() -> Any:  # pragma: no cover
    if sys.platform != "win32":
        raise UnsupportedPlatformError(
            "the Windows certificate store is only available on Windows"
        )

    import ctypes
    from ctypes import wintypes

    c = ctypes.WinDLL("crypt32", use_last_error=True)
    VOID = ctypes.c_void_p
    DWORD = wintypes.DWORD
    BOOL = wintypes.BOOL
    LPCWSTR = wintypes.LPCWSTR
    PDWORD = ctypes.POINTER(DWORD)

    c.CertOpenStore.restype = VOID
    c.CertOpenStore.argtypes = [VOID, DWORD, VOID, DWORD, VOID]
    c.CertEnumCertificatesInStore.restype = VOID
    c.CertEnumCertificatesInStore.argtypes = [VOID, VOID]
    c.CertDuplicateCertificateContext.restype = VOID
    c.CertDuplicateCertificateContext.argtypes = [VOID]
    c.CertFreeCertificateContext.restype = BOOL
    c.CertFreeCertificateContext.argtypes = [VOID]
    c.CertCloseStore.restype = BOOL
    c.CertCloseStore.argtypes = [VOID, DWORD]
    c.CertGetNameStringW.restype = DWORD
    c.CertGetNameStringW.argtypes = [VOID, DWORD, DWORD, VOID, VOID, DWORD]
    c.CertGetCertificateContextProperty.restype = BOOL
    c.CertGetCertificateContextProperty.argtypes = [VOID, DWORD, VOID, PDWORD]
    c.CertAddCertificateContextToStore.restype = BOOL
    c.CertAddCertificateContextToStore.argtypes = [VOID, VOID, DWORD, VOID]
    c.PFXExportCertStoreEx.restype = BOOL
    c.PFXExportCertStoreEx.argtypes = [VOID, VOID, LPCWSTR, VOID, DWORD]
    return c


def _enumerate_store(store: str, location: str) -> list[WinCert]:  # pragma: no cover
    if sys.platform != "win32":
        raise UnsupportedPlatformError(
            "the Windows certificate store is only available on Windows"
        )

    import ctypes

    crypt32 = _load_crypt32()

    CERT_STORE_PROV_SYSTEM_W = 10
    CERT_STORE_READONLY_FLAG = 0x00008000
    CERT_SYSTEM_STORE_CURRENT_USER = 1 << 16
    CERT_SYSTEM_STORE_LOCAL_MACHINE = 2 << 16
    CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
    CERT_FRIENDLY_NAME_PROP_ID = 11
    CERT_SHA1_HASH_PROP_ID = 3

    flags = {
        "CurrentUser": CERT_SYSTEM_STORE_CURRENT_USER,
        "LocalMachine": CERT_SYSTEM_STORE_LOCAL_MACHINE,
    }.get(location)
    if flags is None:
        raise ValueError(
            f"location must be 'CurrentUser' or 'LocalMachine', got {location!r}"
        )

    store_name = ctypes.c_wchar_p(store)
    h_store = crypt32.CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        None,
        flags | CERT_STORE_READONLY_FLAG,
        ctypes.cast(store_name, ctypes.c_void_p),
    )
    if not h_store:
        raise CertificateLoadError(
            f"could not open certificate store {store!r}: "
            f"error {ctypes.get_last_error()}"
        )

    results: list[WinCert] = []
    try:
        cert_ctx = crypt32.CertEnumCertificatesInStore(h_store, None)
        while cert_ctx:
            # Duplicate so the context survives past the enumeration cursor
            # (the next enum call frees the one it just returned).
            dup = crypt32.CertDuplicateCertificateContext(cert_ctx)
            results.append(
                WinCert(
                    subject_cn=_name_string(
                        crypt32, cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE
                    ),
                    friendly_name=_friendly_name(
                        crypt32, cert_ctx, CERT_FRIENDLY_NAME_PROP_ID
                    ),
                    thumbprint=_thumbprint(
                        crypt32, cert_ctx, CERT_SHA1_HASH_PROP_ID
                    ),
                    handle=dup,
                )
            )
            cert_ctx = crypt32.CertEnumCertificatesInStore(h_store, cert_ctx)
    finally:
        crypt32.CertCloseStore(h_store, 0)
    return results


def _name_string(
    crypt32: Any, cert_ctx: Any, name_type: int
) -> str | None:  # pragma: no cover
    import ctypes

    size = crypt32.CertGetNameStringW(cert_ctx, name_type, 0, None, None, 0)
    if size <= 1:
        return None
    buf = ctypes.create_unicode_buffer(size)
    crypt32.CertGetNameStringW(
        cert_ctx, name_type, 0, None, ctypes.cast(buf, ctypes.c_void_p), size
    )
    return buf.value or None


def _friendly_name(
    crypt32: Any, cert_ctx: Any, prop_id: int
) -> str | None:  # pragma: no cover
    import ctypes
    from ctypes import wintypes

    size = wintypes.DWORD(0)
    if not crypt32.CertGetCertificateContextProperty(
        cert_ctx, prop_id, None, ctypes.byref(size)
    ):
        return None
    buf = ctypes.create_string_buffer(size.value)
    if not crypt32.CertGetCertificateContextProperty(
        cert_ctx, prop_id, ctypes.cast(buf, ctypes.c_void_p), ctypes.byref(size)
    ):
        return None
    # Friendly name is stored as a wide (UTF-16-LE) string.
    return buf.raw.decode("utf-16-le").rstrip("\x00") or None


def _thumbprint(
    crypt32: Any, cert_ctx: Any, prop_id: int
) -> str:  # pragma: no cover
    import ctypes
    from ctypes import wintypes

    size = wintypes.DWORD(0)
    if not crypt32.CertGetCertificateContextProperty(
        cert_ctx, prop_id, None, ctypes.byref(size)
    ):
        return ""
    buf = ctypes.create_string_buffer(size.value)
    crypt32.CertGetCertificateContextProperty(
        cert_ctx, prop_id, ctypes.cast(buf, ctypes.c_void_p), ctypes.byref(size)
    )
    return buf.raw.hex().upper()


def _export_pfx(cert: WinCert) -> tuple[bytes, bytes]:  # pragma: no cover
    # pylint: disable=attribute-defined-outside-init,missing-class-docstring,too-few-public-methods
    if sys.platform != "win32":
        raise UnsupportedPlatformError(
            "the Windows certificate store is only available on Windows"
        )

    import ctypes
    from ctypes import wintypes

    crypt32 = _load_crypt32()

    CERT_STORE_PROV_MEMORY = 2
    CERT_STORE_ADD_ALWAYS = 4
    EXPORT_PRIVATE_KEYS = 0x0004
    REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY = 0x0002
    NON_EXPORTABLE_ERRORS = {0x80090003, 0x8009000B, 0x80090009}

    class CRYPT_DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    mem_store = crypt32.CertOpenStore(CERT_STORE_PROV_MEMORY, 0, None, 0, None)
    if not mem_store:
        raise CertificateLoadError("could not open temporary in-memory store")

    password = secrets.token_urlsafe(24)
    try:
        if not crypt32.CertAddCertificateContextToStore(
            mem_store, cert.handle, CERT_STORE_ADD_ALWAYS, None
        ):
            raise CertificateLoadError("could not stage certificate for export")

        flags = EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY
        blob = CRYPT_DATA_BLOB()
        blob.cbData = 0
        blob.pbData = None

        def _export() -> int:
            return crypt32.PFXExportCertStoreEx(
                mem_store, ctypes.addressof(blob), password, None, flags
            )

        if not _export():
            _raise_export_error(ctypes.get_last_error(), NON_EXPORTABLE_ERRORS)

        buf = (ctypes.c_byte * blob.cbData)()
        blob.pbData = ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte))
        if not _export():
            _raise_export_error(ctypes.get_last_error(), NON_EXPORTABLE_ERRORS)

        pfx_bytes = ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        crypt32.CertCloseStore(mem_store, 0)
        if cert.handle is not None:
            crypt32.CertFreeCertificateContext(cert.handle)

    return pfx_bytes, password.encode("utf-8")


def _raise_export_error(
    code: int, non_exportable: set[int]
) -> None:  # pragma: no cover
    if code in non_exportable:
        raise CertificateLoadError(
            "the certificate's private key is not exportable "
            f"(Windows error {code:#010x})"
        )
    raise CertificateLoadError(f"PFX export failed (Windows error {code:#010x})")
