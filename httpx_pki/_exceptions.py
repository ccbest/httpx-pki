"""Exceptions raised by httpx-pki."""

from __future__ import annotations


class PKIError(Exception):
    """Base class for all errors raised by httpx-pki."""


class CertificateLoadError(PKIError):
    """Raised when certificate material cannot be parsed or decrypted.

    Typical causes are corrupt PKCS#12 data, a wrong (or missing) password, a
    PEM key/certificate that cannot be deserialized, or a private key that does
    not match its certificate.
    """


class CertificateExpiredError(PKIError):
    """Raised when a certificate's validity window has already ended.

    Raised by :meth:`PKCSession.check_validity`. Construction only *warns* about
    an expired certificate; call ``check_validity()`` to turn it into an error.
    """


class CertificateNotYetValidError(PKIError):
    """Raised when a certificate's validity window has not yet begun.

    Raised by :meth:`PKCSession.check_validity` for a ``notBefore`` in the
    future (typically a clock-skew or freshly minted-cert problem).
    """


class CertificateNotFoundError(PKIError):
    """Raised when no certificate in a store matches the given selector."""


class AmbiguousCertificateError(PKIError):
    """Raised when more than one certificate matches the given selector.

    The message lists the candidates so the caller can narrow the match (for
    example with a more specific ``name`` or an exact ``thumbprint``).
    """


class UnsupportedPlatformError(PKIError):
    """Raised when a platform-specific feature is used on the wrong platform.

    For example, :meth:`PKCSession.from_windows_cert_store` is only available on
    Windows.
    """
