"""Exceptions and warnings raised by httpx-pki."""

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

    Raised by :meth:`PKIClient.check_validity`. Construction only *warns* about
    an expired certificate; call ``check_validity()`` to turn it into an error.
    """


class CertificateNotYetValidError(PKIError):
    """Raised when a certificate's validity window has not yet begun.

    Raised by :meth:`PKIClient.check_validity` for a ``notBefore`` in the
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

    For example, :meth:`PKIClient.from_windows_cert_store` is only available on
    Windows.
    """


class PKIWarning(UserWarning):
    """Base class for all warnings emitted by httpx-pki.

    Subclasses ``UserWarning`` so existing filters keep matching; filter on a
    specific subclass to silence one concern without hiding the others::

        warnings.filterwarnings("ignore", category=CertificateValidityWarning)
    """


class CertificateValidityWarning(PKIWarning):
    """The client certificate is expired, not yet valid, or expiring soon.

    Emitted when a session is built from (or reloaded to) a certificate whose
    validity window is closed, has not opened, or ends within
    ``warn_if_expires_within``.
    """


class TLSConfigWarning(PKIWarning):
    """A TLS configuration choice that likely doesn't do what was intended.

    Emitted for a custom ``transport=``/``mounts=`` that makes httpx ignore the
    mounted client certificate, a pre-built ``ssl.SSLContext`` passed as
    ``verify=`` (which is mutated in place), and ``verify=False``.
    """


class PicklingWarning(PKIWarning):
    """Part of the client's configuration was dropped during pickling.

    Emitted when a custom ``verify=`` SSL context or an unpicklable certificate
    source cannot be serialized; the unpickled client works but falls back to
    default server verification or loses :meth:`PKIClient.reload` support.
    """
