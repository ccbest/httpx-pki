"""Shared certificate-selection logic.

Three surfaces let a caller point at one certificate among several: a
multi-identity PKCS#12 file (:mod:`httpx_pki._pkcs12`), the Windows certificate
store (:mod:`httpx_pki._winstore`), and the macOS keychain
(:mod:`httpx_pki._keychain`). They differ in how the candidates are discovered
and in what names they carry -- a Windows friendly name, a keychain label, a
PKCS#12 bag name -- but the question is the same, so the vocabulary is shared:

* the *usage* selectors (``key_usage``, ``extended_key_usage``) and their
  spelling rules live here and behave identically everywhere;
* :func:`select_certificate` is the generic store selector, wrapped by each
  platform module with its concrete type
  (:func:`~httpx_pki._winstore.select_windows_certificate`,
  :func:`~httpx_pki._keychain.select_macos_certificate`).

Every selector **intersects**: each one given narrows the candidates further,
so a name and a key usage together mean "both", never "whichever is more
specific". Selecting the signing half of a dual key pair is exactly that
combination.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Protocol, TypeVar

from cryptography import x509

from ._exceptions import AmbiguousCertificateError, CertificateNotFoundError
from ._material import _EKU_NAMES, KEY_USAGE_NAMES, CertInfo

# One usage name or several; every named usage must be present to match.
UsageSelector = str | Iterable[str]


class _StoreCert(Protocol):
    """What the generic selector needs from a platform certificate record."""

    @property
    def subject_cn(self) -> str | None:
        """The certificate's subject common name."""

    @property
    def thumbprint(self) -> str:
        """The certificate's thumbprint as normalized uppercase hex."""

    @property
    def info(self) -> CertInfo | None:
        """The parsed certificate summary, if the record could be read."""

    @property
    def key_usage(self) -> frozenset[str]:
        """The asserted KeyUsage bits (empty when unknown)."""

    @property
    def extended_key_usage(self) -> list[str]:
        """The ExtendedKeyUsage entries (empty when unknown)."""


_C = TypeVar("_C", bound=_StoreCert)


class _CertDetails:
    """Usage accessors derived from a candidate's :class:`CertInfo`.

    Mixed into every selectable certificate type so one predicate reads the
    same whether it is filtering a PKCS#12 file, the Windows store, or the
    macOS keychain::

        predicate=lambda c: "digital_signature" in c.key_usage

    Both accessors are empty rather than ``None`` when the certificate could
    not be read, so a predicate never has to guard against it -- such a
    candidate simply never matches a usage selector.
    """

    info: CertInfo | None

    @property
    def key_usage(self) -> frozenset[str]:
        """The asserted KeyUsage bits, by their attribute names."""
        return frozenset() if self.info is None else self.info.key_usage

    @property
    def extended_key_usage(self) -> list[str]:
        """The ExtendedKeyUsage entries, named where cryptography names them."""
        return [] if self.info is None else self.info.extended_key_usage


def normalize_thumbprint(value: str) -> str:
    """Normalize a thumbprint for comparison: strip colons/spaces, uppercase."""
    return value.replace(":", "").replace(" ", "").upper()


# -- usage vocabulary -------------------------------------------------------


def _squash(name: str) -> str:
    """Normalize a usage name: ``keyEncipherment`` == ``key_encipherment``."""
    return name.lower().replace("_", "").replace("-", "")


_KEY_USAGE_BY_SQUASHED = {_squash(name): name for name in KEY_USAGE_NAMES}
# X.509 renamed the nonRepudiation bit to contentCommitment, and cryptography
# follows the new name -- but CA documentation, openssl's own output, and the
# schemes that lean on the bit all still say nonRepudiation, so accept both.
_KEY_USAGE_BY_SQUASHED[_squash("non_repudiation")] = "content_commitment"
_EKU_BY_SQUASHED = {_squash(name): name for name in _EKU_NAMES.values()}


def _as_names(value: UsageSelector, what: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    try:
        names = list(value)
    except TypeError as exc:
        raise TypeError(
            f"{what} must be a string or an iterable of strings, got "
            f"{type(value).__name__}"
        ) from exc
    if not names:
        raise ValueError(f"{what} must name at least one usage")
    return names


def normalize_key_usages(value: UsageSelector) -> list[str]:
    """Canonical KeyUsage attribute names, rejecting anything unknown."""
    resolved = []
    for name in _as_names(value, "key_usage"):
        canonical = _KEY_USAGE_BY_SQUASHED.get(_squash(name))
        if canonical is None:
            raise ValueError(
                f"unknown key usage {name!r}; valid usages are "
                + ", ".join(KEY_USAGE_NAMES)
            )
        resolved.append(canonical)
    return resolved


def normalize_extended_key_usages(value: UsageSelector) -> list[str]:
    """Canonical extended key usage names; dotted OIDs are accepted as-is."""
    resolved = []
    for name in _as_names(value, "extended_key_usage"):
        canonical = _EKU_BY_SQUASHED.get(_squash(name))
        if canonical is None and _looks_like_oid(name):
            # Name it if cryptography knows it, so it compares equal to what
            # CertInfo reports; otherwise keep the dotted form.
            canonical = _EKU_NAMES.get(x509.ObjectIdentifier(name), name)
        if canonical is None:
            raise ValueError(
                f"unknown extended key usage {name!r}; pass a dotted OID or "
                "one of " + ", ".join(sorted(_EKU_BY_SQUASHED.values()))
            )
        resolved.append(canonical)
    return resolved


def eku_object_identifier(name: str) -> x509.ObjectIdentifier:
    """The OID behind a canonical extended key usage name or dotted OID."""
    for oid, known in _EKU_NAMES.items():
        if known == name:
            return oid
    return x509.ObjectIdentifier(name)


def _looks_like_oid(value: str) -> bool:
    parts = value.split(".")
    return len(parts) > 2 and all(part.isdigit() for part in parts)


def matches_usages(
    candidate: _StoreCert,
    key_usage: UsageSelector | None,
    extended_key_usage: UsageSelector | None,
) -> bool:
    """Whether *candidate* asserts every usage the selectors name.

    Shared by the store selector and the PKCS#12 one so the two never drift.
    Normalization happens here, so an unknown usage name raises rather than
    quietly matching nothing.
    """
    if key_usage is not None:
        wanted = normalize_key_usages(key_usage)
        if not all(usage in candidate.key_usage for usage in wanted):
            return False
    if extended_key_usage is not None:
        wanted = normalize_extended_key_usages(extended_key_usage)
        if not all(usage in candidate.extended_key_usage for usage in wanted):
            return False
    return True


# -- store selection --------------------------------------------------------


def select_certificate(  # pylint: disable=too-many-arguments
    candidates: Sequence[_C],
    *,
    name: str | None,
    thumbprint: str | None,
    predicate: Callable[[_C], bool] | None,
    aliases: Callable[[_C], tuple[str | None, ...]],
    key_usage: UsageSelector | None = None,
    extended_key_usage: UsageSelector | None = None,
) -> _C:
    """Choose a single certificate from *candidates*.

    Every selector given must match: an exact ``thumbprint`` (compared
    normalized -- colons, spaces, and case are ignored), a ``predicate``
    callable, a case-insensitive ``name`` substring matched against the strings
    *aliases* extracts from each candidate, and the ``key_usage`` /
    ``extended_key_usage`` the certificate must assert. With no selector, all
    candidates qualify (handy when the store holds exactly one).

    Raises :class:`~httpx_pki.CertificateNotFoundError` if nothing matches and
    :class:`~httpx_pki.AmbiguousCertificateError` if more than one does.
    """
    matches = list(candidates)
    if thumbprint is not None:
        target = normalize_thumbprint(thumbprint)
        matches = [c for c in matches if c.thumbprint == target]
    if predicate is not None:
        matches = [c for c in matches if predicate(c)]
    if name is not None:
        needle = name.lower()
        matches = [
            c
            for c in matches
            if any(
                alias is not None and needle in alias.lower()
                for alias in aliases(c)
            )
        ]
    if key_usage is not None or extended_key_usage is not None:
        matches = [
            c for c in matches if matches_usages(c, key_usage, extended_key_usage)
        ]

    selector = _selector_repr(
        name, thumbprint, predicate, key_usage, extended_key_usage
    )
    if not matches:
        raise CertificateNotFoundError(
            f"{selector} matched no certificate in the store, which holds:"
            f"\n{_listing(candidates)}"
        )
    if len(matches) > 1:
        raise AmbiguousCertificateError(
            f"{selector} matched {len(matches)} certificates:"
            f"\n{_listing(matches)}\n"
            "Narrow it with a more specific name, a key usage, or an exact "
            "thumbprint."
        )
    return matches[0]


def _listing(candidates: Sequence[_StoreCert]) -> str:
    """The candidates as one indented line each, for an error message.

    Everything that plausibly distinguishes two entries is on the line: the
    usage separates the halves of a dual key pair, and the expiry separates a
    renewed certificate from the one it replaces -- both of which a real store
    holds side by side.
    """
    lines = []
    for candidate in candidates:
        parts = [f"  {candidate.subject_cn or '<no CN>'}"]
        if candidate.key_usage:
            parts.append(f"key_usage={','.join(sorted(candidate.key_usage))}")
        if candidate.info is not None:
            parts.append(f"expires={candidate.info.not_after:%Y-%m-%d}")
        parts.append(candidate.thumbprint)
        lines.append(" ".join(parts))
    return "\n".join(lines) if lines else "  (nothing)"


def _selector_repr(  # pylint: disable=too-many-arguments
    name: str | None,
    thumbprint: str | None,
    predicate: object,
    key_usage: UsageSelector | None = None,
    extended_key_usage: UsageSelector | None = None,
) -> str:
    described = []
    if thumbprint is not None:
        described.append(f"thumbprint={thumbprint!r}")
    if predicate is not None:
        described.append("predicate")
    if name is not None:
        described.append(f"name={name!r}")
    if key_usage is not None:
        described.append(f"key_usage={key_usage!r}")
    if extended_key_usage is not None:
        described.append(f"extended_key_usage={extended_key_usage!r}")
    return " + ".join(described) if described else "no selector"
