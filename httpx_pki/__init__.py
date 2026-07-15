"""httpx-pki: PKCS#12 client-certificate (mTLS) sessions for httpx."""

from __future__ import annotations

from ._client import AsyncPKIClient, PKIClient
from ._exceptions import (
    AmbiguousCertificateError,
    CertificateExpiredError,
    CertificateLoadError,
    CertificateNotFoundError,
    CertificateNotYetValidError,
    CertificateValidityWarning,
    PicklingWarning,
    PKIError,
    PKIWarning,
    TLSConfigWarning,
    UnsupportedPlatformError,
)
from ._keychain import (
    MacCert,
    list_macos_certificates,
    select_macos_certificate,
)
from ._material import CertInfo, Material, cert_info
from ._ssl import build_macos_ssl_context, build_ssl_context, build_windows_ssl_context
from ._winstore import (
    WinCert,
    list_windows_certificates,
    select_windows_certificate,
)

__all__ = [
    "PKIClient",
    "AsyncPKIClient",
    "build_ssl_context",
    "build_macos_ssl_context",
    "build_windows_ssl_context",
    "list_macos_certificates",
    "select_macos_certificate",
    "list_windows_certificates",
    "select_windows_certificate",
    "PKIError",
    "CertificateLoadError",
    "CertificateExpiredError",
    "CertificateNotYetValidError",
    "CertificateNotFoundError",
    "AmbiguousCertificateError",
    "UnsupportedPlatformError",
    "PKIWarning",
    "CertificateValidityWarning",
    "TLSConfigWarning",
    "PicklingWarning",
    "CertInfo",
    "Material",
    "cert_info",
    "WinCert",
    "MacCert",
]

__version__ = "0.6.0"
