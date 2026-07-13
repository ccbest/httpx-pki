"""Shared certificate-selection logic for the platform certificate stores.

The Windows certificate store and the macOS keychain expose the same selection
surface -- an exact thumbprint, a predicate callable, or a case-insensitive
name substring -- over different candidate dataclasses. The generic core lives
here; each platform module wraps it with its concrete type
(:func:`~httpx_pki._winstore.select_windows_certificate`,
:func:`~httpx_pki._keychain.select_macos_certificate`).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol, TypeVar

from ._exceptions import AmbiguousCertificateError, CertificateNotFoundError


class _StoreCert(Protocol):
    """What the generic selector needs from a platform certificate record."""

    @property
    def subject_cn(self) -> str | None:
        """The certificate's subject common name."""

    @property
    def thumbprint(self) -> str:
        """The certificate's thumbprint as normalized uppercase hex."""


_C = TypeVar("_C", bound=_StoreCert)


def normalize_thumbprint(value: str) -> str:
    """Normalize a thumbprint for comparison: strip colons/spaces, uppercase."""
    return value.replace(":", "").replace(" ", "").upper()


def select_certificate(
    candidates: Sequence[_C],
    *,
    name: str | None,
    thumbprint: str | None,
    predicate: Callable[[_C], bool] | None,
    aliases: Callable[[_C], tuple[str | None, ...]],
) -> _C:
    """Choose a single certificate from *candidates*.

    Selectors are applied in order of specificity: an exact ``thumbprint``
    (compared normalized -- colons, spaces, and case are ignored), then a
    ``predicate`` callable, then a case-insensitive ``name`` substring matched
    against the strings *aliases* extracts from each candidate. With no
    selector, all candidates qualify (handy when the store holds exactly one).

    Raises :class:`~httpx_pki.CertificateNotFoundError` if nothing matches and
    :class:`~httpx_pki.AmbiguousCertificateError` if more than one does.
    """
    if thumbprint is not None:
        target = normalize_thumbprint(thumbprint)
        matches = [c for c in candidates if c.thumbprint == target]
    elif predicate is not None:
        matches = [c for c in candidates if predicate(c)]
    elif name is not None:
        needle = name.lower()
        matches = [
            c
            for c in candidates
            if any(
                alias is not None and needle in alias.lower()
                for alias in aliases(c)
            )
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
    name: str | None, thumbprint: str | None, predicate: object
) -> str:
    if thumbprint is not None:
        return f"thumbprint={thumbprint!r}"
    if predicate is not None:
        return "predicate"
    if name is not None:
        return f"name={name!r}"
    return "no selector"
