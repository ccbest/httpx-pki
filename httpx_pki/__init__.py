"""httpx-pki: PKCS#12 client-certificate (mTLS) sessions for httpx."""

from __future__ import annotations

from ._client import AsyncPKIClient, PKIClient
from ._exceptions import (
    AmbiguousCertificateError,
    CertificateExpiredError,
    CertificateLoadError,
    CertificateNotFoundError,
    CertificateNotYetValidError,
    PKIError,
    UnsupportedPlatformError,
)
from ._material import CertInfo, Material, cert_info
from ._ssl import build_ssl_context, build_windows_ssl_context
from ._winstore import (
    WinCert,
    list_windows_certificates,
    select_windows_certificate,
)

__all__ = [
    "PKIClient",
    "AsyncPKIClient",
    "build_ssl_context",
    "build_windows_ssl_context",
    "list_windows_certificates",
    "select_windows_certificate",
    "PKIError",
    "CertificateLoadError",
    "CertificateExpiredError",
    "CertificateNotYetValidError",
    "CertificateNotFoundError",
    "AmbiguousCertificateError",
    "UnsupportedPlatformError",
    "CertInfo",
    "Material",
    "cert_info",
    "WinCert",
]

__version__ = "0.1.0"
