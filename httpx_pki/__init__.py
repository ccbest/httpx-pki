"""httpx-pki: PKCS#12 client-certificate (mTLS) sessions for httpx2 and httpx."""

from __future__ import annotations

from ._audit import AnchorStatus, ChainLink, Problem
from ._client import AsyncPKIClient, PKIClient
from ._compat import HTTP_BACKEND
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
from ._explain import TrustAnchor, X509Explanation, explain
from ._keychain import (
    MacCert,
    list_macos_certificates,
    select_macos_certificate,
)
from ._material import CertInfo, Material, cert_info
from ._pkcs12 import P12Identity, list_identities, list_pkcs12_identities
from ._select import currently_valid, for_mtls
from ._ssl import build_macos_ssl_context, build_ssl_context, build_windows_ssl_context
from ._winstore import (
    WinCert,
    list_windows_certificates,
    select_windows_certificate,
)

__all__ = [
    "PKIClient",
    "AsyncPKIClient",
    "HTTP_BACKEND",
    "build_ssl_context",
    "explain",
    "X509Explanation",
    "Problem",
    "ChainLink",
    "AnchorStatus",
    "TrustAnchor",
    "build_macos_ssl_context",
    "build_windows_ssl_context",
    "list_identities",
    "list_pkcs12_identities",
    "currently_valid",
    "for_mtls",
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
    "P12Identity",
    "cert_info",
    "WinCert",
    "MacCert",
]

__version__ = "0.8.0"
