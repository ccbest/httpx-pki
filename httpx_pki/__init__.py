"""httpx-pki: PKCS#12 client-certificate (mTLS) sessions for httpx."""

from __future__ import annotations

from ._client import AsyncPKCSession, PKCSession
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
from ._ssl import build_ssl_context
from ._winstore import WinCert

__all__ = [
    "PKCSession",
    "AsyncPKCSession",
    "build_ssl_context",
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
