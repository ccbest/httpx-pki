"""httpx-pki: PKCS#12 client-certificate (mTLS) sessions for httpx."""

from __future__ import annotations

from ._client import AsyncPKCSession, PKCSession
from ._exceptions import (
    AmbiguousCertificateError,
    CertificateLoadError,
    CertificateNotFoundError,
    PKIError,
    UnsupportedPlatformError,
)
from ._material import CertInfo, Material, cert_info
from ._winstore import WinCert

__all__ = [
    "PKCSession",
    "AsyncPKCSession",
    "PKIError",
    "CertificateLoadError",
    "CertificateNotFoundError",
    "AmbiguousCertificateError",
    "UnsupportedPlatformError",
    "CertInfo",
    "Material",
    "cert_info",
    "WinCert",
]

__version__ = "0.1.0"
