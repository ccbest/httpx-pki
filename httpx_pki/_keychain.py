# pylint: disable=invalid-name, too-many-locals
"""Retrieve an exportable client certificate from the macOS keychain.

Everything macOS-specific (``ctypes`` against the Security and CoreFoundation
frameworks) lives inside functions guarded by a ``sys.platform`` check, so
importing this module is safe on every platform and adds no dependency. The
platform-independent piece is :func:`select_macos_certificate`, which is pure
and unit-tested everywhere.

The flow mirrors the Windows store (:mod:`httpx_pki._winstore`): enumerate the
identities (certificate + private key pairs) in the default keychain search
list, pick the matching one, and export it -- private key included -- to
PKCS#12 bytes under a random, single-use password. Those bytes feed the same
:func:`~httpx_pki._material.parse_pkcs12` pipeline used by every other
constructor, so the throwaway password never escapes this module.

Two macOS caveats, both surfacing as :class:`~httpx_pki.CertificateLoadError`:
the private key must be exportable, and the keychain may demand user consent
for the export. A headless session cannot grant consent, so provision
certificates with access pre-granted (``security import ... -A``, or "Always
Allow" in the consent dialog).
"""

from __future__ import annotations

import secrets
import sys
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from cryptography.hazmat.primitives import hashes

from ._exceptions import CertificateLoadError, UnsupportedPlatformError
from ._material import _load_certificate, cert_info
from ._select import select_certificate

MacPredicate = Callable[["MacCert"], bool]

# OSStatus codes (Security/SecBase.h).
_ERR_SEC_ITEM_NOT_FOUND = -25300
_ERR_SEC_INTERACTION_NOT_ALLOWED = -25308

# SecExternalFormat (Security/SecImportExport.h): Unknown=0, OpenSSL, SSH,
# BSAFE, RawKey, WrappedPKCS8, WrappedOpenSSL, WrappedSSH, WrappedLSH,
# X509Cert=9, PEMSequence=10, PKCS7=11, PKCS12=12, ...
_K_SEC_FORMAT_PKCS12 = 12
_K_CF_STRING_ENCODING_UTF8 = 0x08000100


@dataclass(frozen=True)
class MacCert:
    """A certificate identity discovered in the macOS keychain.

    ``label`` is the keychain item label (``kSecAttrLabel``), the analog of
    the Windows friendly name. ``handle`` is the retained ``SecIdentityRef``
    used to export the key; it is ``None`` for the synthetic candidates used
    in tests.
    """

    subject_cn: str | None
    label: str | None
    thumbprint: str
    handle: Any = None


def select_macos_certificate(
    candidates: list[MacCert],
    *,
    name: str | None = None,
    thumbprint: str | None = None,
    predicate: MacPredicate | None = None,
) -> MacCert:
    """Choose a single certificate from *candidates*.

    Selectors are applied in order of specificity: an exact ``thumbprint``
    (SHA-1; colons, spaces, and case are ignored), then a ``predicate``
    callable, then a case-insensitive ``name`` substring matched against the
    subject common name and the keychain label. With no selector, all
    candidates qualify (handy when the keychain holds exactly one identity).

    Raises :class:`CertificateNotFoundError` if nothing matches and
    :class:`AmbiguousCertificateError` if more than one does.
    """
    return select_certificate(
        candidates,
        name=name,
        thumbprint=thumbprint,
        predicate=predicate,
        aliases=lambda c: (c.subject_cn, c.label),
    )


def list_macos_certificates() -> list[MacCert]:
    """List the client-certificate identities in the macOS keychain.

    Returns a :class:`MacCert` for each identity (a certificate with its
    private key) in the default keychain search list, carrying its subject
    common name, keychain label, and SHA-1 thumbprint -- metadata only, no key
    is exported. Feed the result to :func:`select_macos_certificate`, or filter
    it yourself and pass a ``thumbprint`` to a session constructor.

    The returned objects hold no live handle (every retained identity is
    released before returning), so there is nothing for the caller to free.

    macOS only; raises :class:`~httpx_pki.UnsupportedPlatformError` elsewhere.
    """
    candidates = _enumerate_identities()
    try:
        return [replace(c, handle=None) for c in candidates]
    finally:
        _free_identities(candidates)


def load_macos_pkcs12(
    *,
    name: str | None = None,
    thumbprint: str | None = None,
    predicate: MacPredicate | None = None,
) -> tuple[bytes, bytes]:
    """Export the matching keychain identity to ``(pkcs12_bytes, password)``."""
    if sys.platform != "darwin":
        raise UnsupportedPlatformError(
            "the macOS keychain is only available on macOS"
        )
    candidates = _enumerate_identities()
    keep: MacCert | None = None
    try:
        keep = select_macos_certificate(
            candidates, name=name, thumbprint=thumbprint, predicate=predicate
        )
        return _export_identity(keep)
    finally:
        # Every enumerated identity was retained so it outlives the query
        # result; release the ones we are not exporting (_export_identity
        # releases the chosen one). On a selection error keep is None, so
        # every retained identity is released here instead of leaking.
        _free_identities([c for c in candidates if c is not keep])


def _free_identities(certs: list[MacCert]) -> None:
    """Release retained keychain identity references.

    Handle-less candidates (the synthetic stand-ins used in tests) are
    skipped, and the frameworks are only loaded when there is a real handle to
    free -- so this is a no-op, and safe, off macOS.
    """
    live = [c.handle for c in certs if c.handle is not None]
    if not live:
        return
    _sec, cf = _load_frameworks()
    for handle in live:
        cf.CFRelease(handle)


# ---------------------------------------------------------------------------
# macOS-only ctypes plumbing. The bodies are unreachable (and unchecked by
# mypy) off macOS because the platform guard always raises there.
#
# Every framework function below has its restype/argtypes declared. This is
# not optional on 64-bit: without it ctypes assumes 32-bit ``int`` returns and
# silently truncates CFTypeRef/SecIdentityRef pointers, which corrupts the
# handles and faults.
#
# CoreFoundation ownership discipline: results of Copy/Create-rule functions
# and explicit CFRetains are CFReleased; Get-rule pointers are borrowed and
# left alone.
# ---------------------------------------------------------------------------


def _load_frameworks() -> tuple[Any, Any]:  # pragma: no cover
    if sys.platform != "darwin":
        raise UnsupportedPlatformError(
            "the macOS keychain is only available on macOS"
        )

    import ctypes

    sec = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
    cf = ctypes.CDLL(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
    )

    VOID = ctypes.c_void_p
    OSSTATUS = ctypes.c_int32
    CFINDEX = ctypes.c_long
    BOOLEAN = ctypes.c_ubyte
    UINT32 = ctypes.c_uint32

    cf.CFRelease.restype = None
    cf.CFRelease.argtypes = [VOID]
    cf.CFRetain.restype = VOID
    cf.CFRetain.argtypes = [VOID]
    cf.CFDictionaryCreateMutable.restype = VOID
    cf.CFDictionaryCreateMutable.argtypes = [VOID, CFINDEX, VOID, VOID]
    cf.CFDictionarySetValue.restype = None
    cf.CFDictionarySetValue.argtypes = [VOID, VOID, VOID]
    cf.CFDictionaryGetValue.restype = VOID
    cf.CFDictionaryGetValue.argtypes = [VOID, VOID]
    cf.CFArrayGetCount.restype = CFINDEX
    cf.CFArrayGetCount.argtypes = [VOID]
    cf.CFArrayGetValueAtIndex.restype = VOID
    cf.CFArrayGetValueAtIndex.argtypes = [VOID, CFINDEX]
    cf.CFStringCreateWithCString.restype = VOID
    cf.CFStringCreateWithCString.argtypes = [VOID, ctypes.c_char_p, UINT32]
    cf.CFStringGetLength.restype = CFINDEX
    cf.CFStringGetLength.argtypes = [VOID]
    cf.CFStringGetMaximumSizeForEncoding.restype = CFINDEX
    cf.CFStringGetMaximumSizeForEncoding.argtypes = [CFINDEX, UINT32]
    cf.CFStringGetCString.restype = BOOLEAN
    cf.CFStringGetCString.argtypes = [VOID, ctypes.c_char_p, CFINDEX, UINT32]
    cf.CFDataGetLength.restype = CFINDEX
    cf.CFDataGetLength.argtypes = [VOID]
    cf.CFDataGetBytePtr.restype = VOID
    cf.CFDataGetBytePtr.argtypes = [VOID]

    sec.SecItemCopyMatching.restype = OSSTATUS
    sec.SecItemCopyMatching.argtypes = [VOID, ctypes.POINTER(VOID)]
    sec.SecIdentityCopyCertificate.restype = OSSTATUS
    sec.SecIdentityCopyCertificate.argtypes = [VOID, ctypes.POINTER(VOID)]
    sec.SecCertificateCopyData.restype = VOID
    sec.SecCertificateCopyData.argtypes = [VOID]
    sec.SecItemExport.restype = OSSTATUS
    sec.SecItemExport.argtypes = [VOID, UINT32, UINT32, VOID, ctypes.POINTER(VOID)]
    sec.SecCopyErrorMessageString.restype = VOID
    sec.SecCopyErrorMessageString.argtypes = [OSSTATUS, VOID]

    return sec, cf


def _symbol(lib: Any, name: str) -> Any:  # pragma: no cover
    """The CFTypeRef stored in an exported constant symbol (e.g. kSecClass)."""
    import ctypes

    return ctypes.c_void_p.in_dll(lib, name)


def _symbol_addr(lib: Any, name: str) -> int:  # pragma: no cover
    """The address of an exported constant struct (e.g. dictionary callbacks)."""
    import ctypes

    return ctypes.addressof(ctypes.c_void_p.in_dll(lib, name))


def _cfstr(cf: Any, ref: Any) -> str | None:  # pragma: no cover
    """Decode a borrowed CFStringRef to ``str`` (``None`` if absent/undecodable)."""
    import ctypes

    if not ref:
        return None
    length = cf.CFStringGetLength(ref)
    max_size = (
        cf.CFStringGetMaximumSizeForEncoding(length, _K_CF_STRING_ENCODING_UTF8) + 1
    )
    buf = ctypes.create_string_buffer(max_size)
    if not cf.CFStringGetCString(ref, buf, max_size, _K_CF_STRING_ENCODING_UTF8):
        return None
    return buf.value.decode("utf-8") or None


def _consume_cfdata(cf: Any, ref: Any) -> bytes:  # pragma: no cover
    """Copy an owned CFDataRef's bytes out and release it."""
    import ctypes

    try:
        return ctypes.string_at(cf.CFDataGetBytePtr(ref), cf.CFDataGetLength(ref))
    finally:
        cf.CFRelease(ref)


def _error_message(sec: Any, cf: Any, status: int) -> str:  # pragma: no cover
    ref = sec.SecCopyErrorMessageString(status, None)
    if ref:
        try:
            message = _cfstr(cf, ref)
        finally:
            cf.CFRelease(ref)
        if message:
            return f"{message} (OSStatus {status})"
    return f"OSStatus {status}"


def _enumerate_identities() -> list[MacCert]:  # pragma: no cover
    if sys.platform != "darwin":
        raise UnsupportedPlatformError(
            "the macOS keychain is only available on macOS"
        )

    import ctypes

    sec, cf = _load_frameworks()

    kSecValueRef = _symbol(sec, "kSecValueRef")
    kSecAttrLabel = _symbol(sec, "kSecAttrLabel")

    query = cf.CFDictionaryCreateMutable(
        None,
        0,
        _symbol_addr(cf, "kCFTypeDictionaryKeyCallBacks"),
        _symbol_addr(cf, "kCFTypeDictionaryValueCallBacks"),
    )
    if not query:
        raise CertificateLoadError("could not create keychain query")
    result = ctypes.c_void_p()
    try:
        cf.CFDictionarySetValue(
            query, _symbol(sec, "kSecClass"), _symbol(sec, "kSecClassIdentity")
        )
        cf.CFDictionarySetValue(
            query, _symbol(sec, "kSecMatchLimit"), _symbol(sec, "kSecMatchLimitAll")
        )
        true_ref = _symbol(cf, "kCFBooleanTrue")
        cf.CFDictionarySetValue(query, _symbol(sec, "kSecReturnRef"), true_ref)
        cf.CFDictionarySetValue(
            query, _symbol(sec, "kSecReturnAttributes"), true_ref
        )
        status = sec.SecItemCopyMatching(query, ctypes.byref(result))
    finally:
        cf.CFRelease(query)

    if status == _ERR_SEC_ITEM_NOT_FOUND:
        return []
    if status != 0 or not result:
        raise CertificateLoadError(
            f"could not search the keychain: {_error_message(sec, cf, status)}"
        )

    results: list[MacCert] = []
    try:
        for i in range(cf.CFArrayGetCount(result)):
            attrs = cf.CFArrayGetValueAtIndex(result, i)  # borrowed
            identity = cf.CFDictionaryGetValue(attrs, kSecValueRef)  # borrowed
            if not identity:
                continue
            # Retain so the identity outlives the released query result.
            handle = cf.CFRetain(identity)
            label = _cfstr(cf, cf.CFDictionaryGetValue(attrs, kSecAttrLabel))
            subject_cn, thumbprint = _certificate_details(sec, cf, identity)
            results.append(
                MacCert(
                    subject_cn=subject_cn,
                    label=label,
                    thumbprint=thumbprint,
                    handle=handle,
                )
            )
    finally:
        cf.CFRelease(result)
    return results


def _certificate_details(
    sec: Any, cf: Any, identity: Any
) -> tuple[str | None, str]:  # pragma: no cover
    """The subject CN and SHA-1 thumbprint of an identity's certificate.

    The certificate DER is parsed with ``cryptography`` rather than more
    Security-framework calls -- it is already a dependency and spares the
    CFString plumbing the Windows module needs for names.
    """
    import ctypes

    cert_ref = ctypes.c_void_p()
    status = sec.SecIdentityCopyCertificate(identity, ctypes.byref(cert_ref))
    if status != 0 or not cert_ref:
        raise CertificateLoadError(
            "could not read the certificate of a keychain identity: "
            f"{_error_message(sec, cf, status)}"
        )
    try:
        der = _consume_cfdata(cf, sec.SecCertificateCopyData(cert_ref))
    finally:
        cf.CFRelease(cert_ref)
    thumbprint = _load_certificate(der).fingerprint(hashes.SHA1()).hex().upper()
    return cert_info(der).common_name, thumbprint


def _export_identity(cert: MacCert) -> tuple[bytes, bytes]:  # pragma: no cover
    # pylint: disable=attribute-defined-outside-init,missing-class-docstring,too-few-public-methods
    if sys.platform != "darwin":
        raise UnsupportedPlatformError(
            "the macOS keychain is only available on macOS"
        )

    import ctypes

    sec, cf = _load_frameworks()

    # SecImportExport.h, SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION = 0.
    class SecItemImportExportKeyParameters(ctypes.Structure):
        _fields_ = [
            ("version", ctypes.c_uint32),
            ("flags", ctypes.c_uint32),
            ("passphrase", ctypes.c_void_p),
            ("alertTitle", ctypes.c_void_p),
            ("alertPrompt", ctypes.c_void_p),
            ("accessRef", ctypes.c_void_p),
            ("keyUsage", ctypes.c_void_p),
            ("keyAttributes", ctypes.c_void_p),
        ]

    password = secrets.token_urlsafe(24)
    pw_ref = cf.CFStringCreateWithCString(
        None, password.encode("ascii"), _K_CF_STRING_ENCODING_UTF8
    )
    if not pw_ref:
        raise CertificateLoadError("could not create the export passphrase")

    params = SecItemImportExportKeyParameters()
    params.version = 0
    params.flags = 0
    params.passphrase = pw_ref

    data = ctypes.c_void_p()
    try:
        status = sec.SecItemExport(
            cert.handle,
            _K_SEC_FORMAT_PKCS12,
            0,
            ctypes.cast(ctypes.pointer(params), ctypes.c_void_p),
            ctypes.byref(data),
        )
        if status != 0 or not data:
            _raise_export_error(sec, cf, status)
        pfx_bytes = _consume_cfdata(cf, data)
    finally:
        cf.CFRelease(pw_ref)
        if cert.handle is not None:
            cf.CFRelease(cert.handle)

    return pfx_bytes, password.encode("utf-8")


def _raise_export_error(sec: Any, cf: Any, status: int) -> None:  # pragma: no cover
    message = _error_message(sec, cf, status)
    if status == _ERR_SEC_INTERACTION_NOT_ALLOWED:
        raise CertificateLoadError(
            "the keychain needs user consent to export this key, and none can "
            "be given in this session; re-import the certificate with access "
            f"pre-granted (security import ... -A): {message}"
        )
    raise CertificateLoadError(f"keychain PKCS#12 export failed: {message}")
